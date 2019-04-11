// The original idea for this padding check tool was a very simple tool for checking for POODLE issues in TLS servers.
// See https://www.imperialviolet.org/2014/12/08/poodleagain.html

package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	hostsFile      *string = flag.String("hosts", "", "Filename containing hosts to query")
	workerCount    *int    = flag.Int("workerCount", 32, "Desired number of workers for testing lists")
	keyLogFile     *string = flag.String("keylog", "/dev/null", "Path to a file NSS key log export (needed to decrypt pcap files)")
	verboseLevel   *int    = flag.Int("v", 1, "Specify verboseness level (default: 1, max: 5)")
	iterationCount *int    = flag.Int("iterations", 3, "Number of iterations required to confirm oracle")
	showHelp       *bool   = flag.Bool("h", false, "Show help")
)

const testCount = 5

type cbcSuite struct {
	id       uint16
	macLen   int
	blockLen int
}

var cbcSuites = []*cbcSuite{
	{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, 20, 8},
	{tls.TLS_RSA_WITH_AES_128_CBC_SHA, 20, 16},
	{tls.TLS_RSA_WITH_AES_256_CBC_SHA, 20, 16},
	{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, 32, 16},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 20, 16},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 20, 16},
	{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 20, 8},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 20, 16},
	{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 20, 16},
	{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 32, 16},
	{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 32, 16},
}

func cbcSuiteByID(id uint16) *cbcSuite {
	for _, cipherSuite := range cbcSuites {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

func SupportedCipherTest(hostname, serverName string, supportedCiphers []uint16, maxVersion uint16) (availableCipher *cbcSuite, protocolVersion uint16, err error) {
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}

	keyLogWriter, err := os.OpenFile(*keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return
	}

	conn, err := tls.DialWithDialer(&dialer, "tcp", hostname, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       supportedCiphers,
		ServerName:         serverName,
		KeyLogWriter:       keyLogWriter,
		MaxVersion:         maxVersion,
	})

	if err != nil {
		if *verboseLevel > 2 {
			fmt.Printf("Error connecting to %s: %v\n", serverName, err)
		}
		return
	}

	conn.Close()

	availableCipher = cbcSuiteByID(conn.ConnectionState().CipherSuite)
	protocolVersion = conn.ConnectionState().Version

	return

}

func testCipher(hostname, serverName string, cipherId, protocolVersion uint16) (responseLengths [testCount]int, responseSizeProfile, errorStrings [testCount]string, err error) {
	var (
		selectedCipher                         = cbcSuiteByID(cipherId)
		macLen                                 = selectedCipher.macLen
		blockLen                               = selectedCipher.blockLen
		errorList, secondErrorList             [testCount]error
		secondResponseLengths                  [testCount]int
		secondResponseSizeProfile              [testCount]string
		uniqueLengthCount                      int = 0
		uniqueSecondLengthCount                int = 0
		responseBuffers, secondResponseBuffers [testCount][16384]byte
	)

	testNames := [testCount]string{"Invalid MAC/Valid Pad", "Missing MAC/Incomplete Pad", "Valid MAC/Invalid Pad", "Missing MAC/Valid Pad", "Invalid Mac/Valid Pad (0-length record)"}

	keyLogWriter, err := os.OpenFile(*keyLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return
	}

	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}

	// An HTTP request is prepared to have a full block of padding required
	requestData := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", serverName)
	overrun := (len(requestData) + macLen) % blockLen
	if overrun > 0 {
		requestData = fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", strings.Repeat("a", blockLen-overrun), serverName)
	}

	if *verboseLevel >= 1 {
		fmt.Printf("%s (%s) is being tested for oracles with cipher 0x%04x using TLS 0x%04x\n", serverName, hostname, cipherId, protocolVersion)
	}
	for i := 0; i < testCount; i++ {
		// Establish connection with padding mode option
		conn, connErr := tls.DialWithDialer(&dialer, "tcp", hostname, &tls.Config{
			InsecureSkipVerify: true,
			PaddingMode:        i + 1,
			KeyLogWriter:       keyLogWriter,
			ServerName:         serverName,
			CipherSuites:       []uint16{cipherId},
			MinVersion:         protocolVersion,
			MaxVersion:         protocolVersion,
		})

		if connErr != nil {
			err = connErr
			return
		}

		// Send the request and set a timeout for reading the response
		conn.Write([]byte(requestData))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		// Read from the socket
		responseLengths[i], errorList[i] = conn.Read(responseBuffers[i][:])
		secondResponseLengths[i], secondErrorList[i] = conn.Read(secondResponseBuffers[i][:])
		errClose := conn.Close()

		// Response lengths must be normalized into letters for comparison
		// 1) Initialize value with empty string
		// 2) Iterate over responseLengths for matching length
		// 3) Use ID from matching responseSizeProfile if lengths match
		// 4) If responseSizeProfile is not set, assign next letter for length

		responseSizeProfile[i] = ""
		for w := 0; w < i; w++ {
			if responseLengths[i] == responseLengths[w] {
				responseSizeProfile[i] = responseSizeProfile[w]
				break
			}
		}
		if responseSizeProfile[i] == "" {
			responseSizeProfile[i] = string(65 + uniqueLengthCount)
			uniqueLengthCount++
		}

		// Deal with secondResponseProfile
		secondResponseSizeProfile[i] = ""
		for w := 0; w < i; w++ {
			if secondResponseLengths[i] == secondResponseLengths[w] {
				secondResponseSizeProfile[i] = secondResponseSizeProfile[w]
				break
			}
		}
		if secondResponseSizeProfile[i] == "" {
			secondResponseSizeProfile[i] = string(65 + uniqueLengthCount)
			uniqueSecondLengthCount++
		}

		//responseSizeProfile[i] += secondResponseSizeProfile[i]
		secondErrString := ""
		// Error message is converted to a string
		if secondErrorList[i] != nil {
			if secondErrorList[i] != errorList[i] {
				r, _ := regexp.Compile(".*read: ")
				errString := string(r.ReplaceAll([]byte(fmt.Sprintf("%v", secondErrorList[i])), []byte("")))
				secondErrString = fmt.Sprintf("+%v", errString)
			} else {
				secondErrString = "+"
			}
		}

		if errClose == nil {
			errorStrings[i] = fmt.Sprintf("%v%s", errorList[i], secondErrString)
		} else {
			r, _ := regexp.Compile(".*write: ")
			errString := string(r.ReplaceAll([]byte(fmt.Sprintf("%v", errClose)), []byte("")))
			if strings.HasPrefix(errorStrings[i], errString) {
				errorStrings[i] = fmt.Sprintf("%v%s+", errorList[i], secondErrString)
			} else {
				errorStrings[i] = fmt.Sprintf("%v%s+%v", errorList[i], secondErrString, errString)
			}
			if *verboseLevel > 2 {
				fmt.Printf("%s (%s) error on close: %s\n", serverName, hostname, errString)
			}
		}

		// Error messages must be normalized for comparison
		// IP address / port number info must be stripped
		if strings.HasPrefix(errorStrings[i], "read tcp") {
			if strings.Contains(errorStrings[i], "timeout") {
				errorStrings[i] = "Timeout"
			} else if strings.Contains(errorStrings[i], "reset") {
				errorStrings[i] = "Reset"
			} else {
				if *verboseLevel >= 5 {
					fmt.Printf("WARN: %s|%s - Received unexpected error '%v' on padding mode %d\n", hostname, serverName, i+1)
				}
				errorStrings[i] = "Unknown TCP Error"
			}
		}

		// Print test status if using high verbosity
		if *verboseLevel >= 5 {
			fmt.Printf("\t%s Test\n\t\tResponse Length: %v(%s)\n\t\tError: %v\n\t\tSecond Error: %v\n\t\tClose Error:%v\n", testNames[i], responseLengths[i], responseSizeProfile[i], errorList[i], secondErrorList[i], errClose)
			if responseLengths[i] > 0 {
				fmt.Printf("\tDecrypted Data (up to 256 bytes):\n%s\n", responseBuffers[i][0:256])
			}
			fmt.Println()
		}

		conn.Close()
	}
	return
}

func analyzeResponseProfile(hostname, serverName string, responseLengths [testCount]int, responseSizeProfile, errorStrings [testCount]string) (isVulnerable, isPoodle, isGoldenDoodle, isZombiePoodle, isZeroLength, isObservable bool, errorPrint, lengthPrint string, err error) {
	// Decrypted response length should be zero for all tests
	for i := 0; i < testCount; i++ {
		if responseLengths[i] > 0 {
			isVulnerable = true
			isObservable = true
			if i == 0 {
				// Non-zero response length for valid padding with invalid MAC: GOLDENDOODLE
				isGoldenDoodle = true
			}
			if i == 2 {
				// Non-zero response length for invalid padding with valid MAC: POODLE
				isPoodle = true
			}
		}
	}

	var uniqueErrorCount int
	var messageHeader string
	if *verboseLevel > 1 {
		messageHeader = "\t"
	} else {
		messageHeader = fmt.Sprintf("%s (%s)\t\t", serverName, hostname)
	}

	for i := 1; i < testCount; i++ {
		if errorStrings[i] != errorStrings[0] {
			uniqueErrorCount++
			isFirstRemote := strings.HasPrefix(errorStrings[0], "remote error: tls:")
			isCurrentRemote := strings.HasPrefix(errorStrings[i], "remote error: tls:")
			if *verboseLevel > 1 {
				fmt.Printf("%sDistinct error observed. Error[0]==%v, Error[%d]==%v\n", messageHeader, errorStrings[0], i, errorStrings[i])
				if isCurrentRemote && isFirstRemote {
					fmt.Printf("%sThis may oracle may not be observable to the attacker.\n", messageHeader)
				}
			}
			isVulnerable = true

			if !(isCurrentRemote && isFirstRemote) {
				isObservable = true
			}

			if i == 2 {
				// Unique error on invalid padding with valid MAC: likely Zombie POODLE
				isZombiePoodle = true
			}
			if i == 3 {
				isZeroLength = true
			}
		}
	}

	if isVulnerable && *verboseLevel > 0 {
		fmt.Println()
	}
	if uniqueErrorCount == testCount-1 {
		// Distinct error for valid padding with invalid MAC: GOLDENDOODLE
		isGoldenDoodle = true
	}

	// Generating a checksum makes for easier comparison across iterations
	errorMap := []byte(fmt.Sprintf("%v/%v/%v/%v/%v", errorStrings[0], errorStrings[1], errorStrings[2], errorStrings[3], errorStrings[4]))
	shasum := sha1.New()
	shasum.Write(errorMap)
	errorPrint = fmt.Sprintf("%x", shasum.Sum(nil))

	lengthMap := []byte(fmt.Sprintf("%v/%v/%v/%v/%v", responseSizeProfile[0], responseSizeProfile[1], responseSizeProfile[2], responseSizeProfile[3], responseSizeProfile[4]))
	shasum = sha1.New()
	shasum.Write(lengthMap)
	lengthPrint = fmt.Sprintf("%x", shasum.Sum(nil))

	return

}

func scanHost(hostname, serverName string, cipherIndex int) error {
	allCiphers := []uint16{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}
	cipherList := []uint16 {allCiphers[cipherIndex]};

	availableCipher, availableProtocol, err := SupportedCipherTest(hostname, serverName, cipherList, 0x0303)
	if err != nil {
		if *verboseLevel > 0 {
			fmt.Printf("%s (%s) had an unexpected connection failure: %v (cipher 0x%04x)\n", serverName, hostname, err, cipherList[0])
		}
		return err
	}
	if *verboseLevel > 1 {
		fmt.Printf("%s (%s) using TLS 0x%04x supports cipher 0x%04x which uses CBC.\n", serverName, hostname, availableProtocol, availableCipher.id)
	}

	var (
		lastErrorPrint, lastLengthPrint                                                    string
		isVulnerable, isPoodle, isGoldenDoodle, isZombiePoodle, isObservable, isZeroLength bool
		errorPrint, lengthPrint                                                            string
		responseLengths                                                                    [testCount]int
		responseSizeProfile, errorStrings                                                  [testCount]string
	)

	for iteration := 0; iteration < *iterationCount; iteration++ {
		// Connect to target with identified cipher and test each malformed record case
		responseLengths, responseSizeProfile, errorStrings, err = testCipher(hostname, serverName, availableCipher.id, availableProtocol)

		if err != nil {
			if *verboseLevel > 0 {
				fmt.Printf("%s (%s) encountered the following error while testing cipher 0x%04x: %v\n", serverName, hostname, availableCipher.id, err)
			}
			return err
		}

		// Analyze the response profile for oracles
		isVulnerable, isPoodle, isGoldenDoodle, isZombiePoodle, isZeroLength, isObservable, errorPrint, lengthPrint, err = analyzeResponseProfile(hostname, serverName, responseLengths, responseSizeProfile, errorStrings)

		if isVulnerable != true {
			if iteration > 0 {
				if *verboseLevel > 0 {
					fmt.Printf("%s (%s) exhibited an oracle which did not appear on iteration %d. (Not exploitable)\n", serverName, hostname, iteration)
				}
				return errors.New("Oracle disappeared")
			}
			return nil
		}

		if lastErrorPrint != "" {
			if lastErrorPrint != errorPrint {
				if *verboseLevel > 0 {
					fmt.Printf("%s (%s) has an inconsistent error oracle response. (Maybe exploitable)\n", serverName, hostname)
				}
				return errors.New("Inconsistent error responses")
			}
		} else {
			lastErrorPrint = errorPrint
		}

		if lastLengthPrint != "" {
			if lastLengthPrint != lengthPrint {
				if *verboseLevel > 0 {
					fmt.Printf("%s (%s) has an inconsistent response length profile\n (Maybe exploitable)", serverName, hostname)
				}
				return errors.New("Inconsistent length responses")
			}
		} else {
			lastLengthPrint = lengthPrint
		}
	}

	if isVulnerable {
		var vulnTag string
		if isObservable {
			vulnTag = "Observable "
		}
		if isGoldenDoodle {
			vulnTag += "Padding Validity (GOLDENDOODLE)"
		} else if isZombiePoodle {
			vulnTag += "MAC Validity (Zombie POODLE)"
		} else if isPoodle {
			vulnTag += "MAC validity (POODLE or 'sleeping' POODLE)"
		} else if isZeroLength {
			vulnTag += "Incomplete or Missing MAC"
		} else {
			vulnTag += "unkown"
		}

		respLenTag := strings.Join(responseSizeProfile[:], "/")
		respLenRaw := fmt.Sprintf("%v/%v/%v/%v", responseLengths[0], responseLengths[1], responseLengths[2], responseLengths[3])
		errMsgTag := strings.Join(errorStrings[:], "/")
		shortPrint := errorPrint[0:3] + lengthPrint[0:3]

		fmt.Printf("%s (%s) is VULNERABLE with a %s oracle when using cipher 0x%04x with TLS 0x%04x. The fingerprint is %s\n", serverName, hostname, vulnTag, availableCipher.id, availableProtocol, shortPrint)
		if *verboseLevel <= 1 {
			fmt.Printf("%s (%s) error profile: ^%v^ and response size profile ^%v^\n", serverName, hostname, errMsgTag, respLenTag)
		} else {
			fmt.Printf("The following responses were observed:\n")
			fmt.Printf("\tLengths:%s(%s)\n\tErrors:%s\n", respLenRaw, respLenTag, errMsgTag)
			fmt.Printf("\tLength Hash:%v\n\tError Hash:%v\n", lengthPrint, errorPrint)
		}
	} else {
		if *verboseLevel > 0 {
			fmt.Printf("%s (%s) behaves securely\n", serverName, hostname)
		}
	}

	return nil
}

func worker(hosts <-chan string, done *sync.WaitGroup) {
	defer done.Done()

	for hostname := range hosts {
		var targetHost string
		hostnameParts := strings.Split(hostname, ":")
		addressList, err := net.LookupIP(hostnameParts[0])
		if err != nil {
			if *verboseLevel > 2 {
				fmt.Printf("Error resolving %s [error: %s]\n", hostname, err)
				continue
			}
		}
		if len(addressList) == 0 {
			if *verboseLevel > 0 {
				fmt.Printf("ERROR: No address associated with %s\n", hostnameParts[0])
			}
			continue
		}
		address := ""
		for i := 0; i < len(addressList); i++ {
			if addressList[i].To4() != nil {
				address = addressList[i].String()
				break
			}
		}
		if address == "" {
			continue
		}
		if len(hostnameParts) > 1 {
			targetHost = fmt.Sprintf("%s:%s", address, hostnameParts[1])
		} else {
			targetHost = fmt.Sprintf("%s:443", address)
		}

		for cipherIndex := 0; cipherIndex < len(cbcSuites); cipherIndex++ {
			err = scanHost(targetHost, hostnameParts[0], cipherIndex)
			if err != nil {
				if *verboseLevel >= 5 {
					fmt.Fprintf(os.Stderr, "%s: %s\n", hostname, err)
				}
			}
		}
		continue
	}
}

func main() {
	flag.Parse()

	var wg sync.WaitGroup
	var numWorkers = *workerCount
	hostnames := make(chan string, numWorkers)

	if *verboseLevel == 0 {
		fmt.Fprintf(os.Stderr, "Quiet Mode Enabled: Only vulnerable hosts will be reported.\n")
	}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(hostnames, &wg)
	}

	if len(*hostsFile) == 0 {
		for _, hostname := range os.Args[len(os.Args)-1:] {
			hostnames <- hostname
		}
	}

	if *showHelp {
		fmt.Fprintf(os.Stderr, "This tool tests how a server responds to various CBC padding errors.\n\nFive HTTPS GET requests will be made to the target with different padding modes.\nFirst a good padding and then the errors:\n\t1 - Invalid MAC with Valid Padding (0-length pad)\n\t2 - Missing MAC with Incomplete/Invalid Padding (255-length pad)\n\t3 - Typical POODLE condition (incorrect bytes followed by correct length)\n\t4 - All padding bytes set to 0x80 (integer overflow attempt)\n\nA file containing a list of hosts to scanned with worker threads can be specified via -hosts\n")
	}

	if len(*hostsFile) > 0 {
		hosts, err := os.Open(*hostsFile)
		if *verboseLevel == 1 {
			*verboseLevel = 0
		}
		if err != nil {
			panic(err)
		}
		defer hosts.Close()
		inHosts := bufio.NewScanner(hosts)
		for inHosts.Scan() {
			hostnames <- inHosts.Text()
		}
		if err := inHosts.Err(); err != nil {
			panic(err)
		}
	}

	close(hostnames)

	wg.Wait()
}
