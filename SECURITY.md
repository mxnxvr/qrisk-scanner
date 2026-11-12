# Security policy

## Responsible use

QRisk actively connects to the servers you give it: a TLS scan makes about 30-100 short
handshakes, and an SSH scan reads the server's algorithm list and starts one key exchange.
It never logs in, sends credentials or exploits anything, but it is still a security scan.

**Only scan systems you own or have explicit written permission to test.** Scanning other
people's systems without permission may be illegal where you live.

The Docker lab in [`lab/`](lab) contains deliberately insecure servers. Its ports are bound to
`127.0.0.1`; never expose them to a network.

## Reporting a vulnerability in QRisk

QRisk processes data controlled by the systems it scans (certificate names, SSH banners,
config files, source code). If you find a way for that data to attack the person running
QRisk or reading its reports, for example script injection in the HTML/PDF report, a crash
that hides results, or reading files outside the scanned folder, please report it privately:

1. Open a [private security advisory](https://github.com/mxnxvr/qrisk-scanner/security/advisories/new) on GitHub.
2. Include the QRisk version (`qrisk --version`), the command you ran, and a minimal example.

Please don't open a public issue for security problems.
