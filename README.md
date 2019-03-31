# Padcheck: A TLS CBC Padding Oracle Scanner

This tool tests how a server responds to various CBC padding errors.

The tool makes a series of connections where the TLS record containing an HTTP request is malformed. Servers should respond uniformly to all malformed records. If the server responds differently to certain types of errors, an attacker may be able to construct a padding oracle for use in an adaptive chosen ciphertext attack.

There are currently five malformed record test cases: 
1. Invalid MAC with Valid Padding (0-length pad)
2. Missing MAC with Incomplete Padding (255-length pad)
3. Valid MAC with Inconsistent Padding (SSLv3 style padding)
4. Missing MAC with Valid Padding (Entire record is padding)
5. Invalid MAC with Valid Padding (0-length record)

## Background

This tool was created to help identify lingering TLS CBC padding oracles. The research was [originally presented at Black Hat Asia](https://www.blackhat.com/asia-19/briefings/schedule/index.html#zombie-poodle-goldendoodle-and-how-tlsv-can-save-us-all-13741) in March 2019. The [slides](http://i.blackhat.com/asia-19/Fri-March-29/bh-asia-Young-Zombie-Poodle-Goldendoodle-and-How-TLSv13-Can-Save-Us-All.pdf) are available for review.

For further reading on the topic, refer to the following links:
* [TLS CBC Padding Oracles in 2019](https://www.tripwire.com/state-of-security/vert/tls-cbc-padding-oracles/)
* [What is Zombie POODLE?](https://www.tripwire.com/state-of-security/vert/zombie-poodle/)
* [What is GOLDENDOODLE?](https://www.tripwire.com/state-of-security/vert/goldendoodle-attack/)
* [Scanning for Padding Oracles](https://web-in-security.blogspot.com/2019/03/scanning-for-padding-oracles.html)

Disclosures related to modern TLS CBC padding oracles are being [tracked on GitHub](https://github.com/RUB-NDS/TLS-Padding-Oracles). This also includes oracles identified by [TLS-Scanner](https://github.com/RUB-NDS/TLS-Scanner)

## Usage

|              |        |                                                                                        |
| ------------ | ------ | -------------------------------------------------------------------------------------- |
| -h           |        | Show help                                                                              |
| -hosts       | string | Filename containing hosts to query                                                     |
| -iterations  | int    | Number of iterations required to confirm oracle (default 3)                            |
| -keylog      | string | Path to a file NSS key log export (needed to decrypt pcap files) (default "/dev/null") |
| -v           | int    | Specify verboseness level (default: 1, max: 5) (default 1)                             |
| -workerCount | int    | Desired number of workers for testing lists (default 32)                               |

The basic usage is to run ```padcheck hostname```
A list of hosts can also be read from a file ```padcheck -hosts hostnames.txt```

Vulnerable hosts are indicated in the tool output with a line similar to:

*Hostname (ip:443)* is VULNERABLE with a *Observable MAC Validity (Zombie POODLE)* oracle when using cipher *0xc027* with TLS *0x0303*. The fingerprint is *6867b5*

The fingerprint produced by this tool is a hash of the server responses. These values are subject to change with changes to the tool or with environmental variation which may influence the error message text. The fingerprint value should therefore be primarily used for correlating similar vulnerabilities within a specific environment.

## Obtaining padcheck
The easiest way to get started with padcheck is by downloading the latest [Linux binary release](https://github.com/Tripwire/padcheck/releases)

Users can alternatively build it locally for cross-platform or development testing. 

## Building on Linux

1) [Install Go](https://golang.org/doc/install) - Distro packages (e.g. sudo apt install golang-go) are fine.
2) Run `./build.sh`

Upon success, `./padcheck` will be available as a portable/standalone executable.

## Building on Docker

Building with Docker is easier and cross-platform.

Run `docker build . -t padcheck` to build the patched Go toolchain and the `padcheck` tool in a container.

Run with: `docker run --rm -it padcheck [args]`

If you want to use a hosts file or keylog file, you will need to mount them in the container:

```sh
docker run --rm -it \
    -v /path/to/hosts:/tmp/hosts \
    -v /path/to/keylog:/tmp/keylog \
    padcheck -hosts /tmp/hosts -keylog /tmp/keylog
```

## Credits

The original idea for this padding check tool was a very simple tool for checking for POODLE issues in TLS servers, by Adam Langley (`agl` AT `imperialviolet` DOT `org`). See:

- https://www.imperialviolet.org/2014/12/08/poodleagain.html
- https://www.imperialviolet.org/binary/poodle-tls-go.patch
- https://www.imperialviolet.org/binary/scanpadding.go

## Additional Resources

More information about scanning for TLS CBC padding oracles on the Internet can be found in this repo: https://github.com/RUB-NDS/TLS-Padding-Oracles


## License

Original tool copyright 2014 Adam Langley, released under a BSD license.

Copyright 2019 Tripwire, Inc. All rights reserved.
Released under a [BSD 2-Clause License](./LICENSE).
