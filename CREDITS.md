Credits and Thanks
====

This tool goes along with Craig Young's research outlined at [Black Hat Asia 2019](https://www.blackhat.com/asia-19/briefings/schedule/index.html#zombie-poodle-goldendoodle-and-how-tlsv-can-save-us-all-13741)

I would like to thank the following people for their collaboration and feedback throughout this research:
* Hanno Böck
* Juraj Somorovsky (Ruhr-University Bochum)
* Robert Merget (Ruhr-University Bochum)
* Nimrod Aviram (Department of Electrical Engineering, Tel Aviv University)
* Tyler Reguly (Tripwire)
* Bob Thomas (Tripwire)

This tool was based on Adam Langley's original POODLE TLS scan tool.
His [original source](https://www.imperialviolet.org/binary/scanpadding.go) and [Go patch](https://www.imperialviolet.org/binary/poodle-tls-go.patch) were published on https://www.imperialviolet.org

Docker support was added by Bob Thomas.

The underlying padding oracle attack technique was [published by Serge Vaudenay in 2002.](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)
