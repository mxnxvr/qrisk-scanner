# QRisk Scanner

[![CI](https://github.com/mxnxvr/qrisk-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mxnxvr/qrisk-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Find the cryptography an organisation uses, flag what quantum computers will break, and export a standard Cryptographic Bill of Materials (CBOM).**

QRisk is a command-line tool for the first step of any post-quantum migration: *crypto discovery and inventory*. It scans TLS endpoints, SSH servers, certificate/key files, source code and server configuration, rates every finding on a four-level quantum-risk scale, maps it to the NIST IR 8547 deadlines, and gives a concrete fix.

```text
╭──────────────────── QRisk Scanner ────────────────────╮
│ Quantum Readiness: 34/100  (Quantum-vulnerable)        │
│ ● Critical 2   ● Quantum-vulnerable 14   ● Hybrid 1   ● Quantum-safe 6 │
╰────────────────────── 3 target(s) ─────────────────────╯
```

## Why

A cryptographically relevant quantum computer will break RSA, ECDSA, ECDH and Diffie-Hellman. Data recorded today can be decrypted later ("harvest now, decrypt later"). NIST IR 8547 deprecates 112-bit quantum-vulnerable algorithms after **2030** and disallows all of them after **2035**. You can't migrate what you haven't inventoried.

## Features

| Layer | What it finds | Status |
|---|---|---|
| 1. TLS endpoints | SSL 3.0 to TLS 1.3, TLS 1.3 key-exchange groups including **X25519MLKEM768** and other PQ hybrids, the real TLS 1.2 curves and DHE prime size (Logjam check), accepted cipher suites, certificate key, signature and expiry | ✅ |
| 2. Certificates and keys | `.pem .crt .cer .der .key .p12 .pfx .pub .csr` (PEM, DER, PKCS#12, OpenSSH), including ML-DSA / SLH-DSA certificates by OID. **JKS / JCEKS keystores are read without the password** (their certificates aren't encrypted) | ✅ |
| 3. SSH servers | Key exchange (shows `mlkem768x25519-sha256` / `sntrup761x25519-sha512`), host-key algorithms, ciphers, and the **actual RSA host key size** (via one key-exchange round trip, no login) | ✅ |
| 4. Source code | Crypto API calls in Python, Java/Kotlin, JavaScript/TypeScript and Go, reported by file and line, with key sizes and curves read from the arguments. See [Code rules](#code-rules) | ✅ |
| 5. Config files | nginx, Apache, `openssl.cnf`, `sshd_config` / `ssh_config`: protocols, cipher strings, key-exchange groups, SSH algorithms, plus the certificates, DH parameters and host keys they point to. See [Config checks](#config-checks) | ✅ |

**How it detects post-quantum TLS without a post-quantum OpenSSL:** QRisk speaks raw TLS. It sends ClientHellos that list key-exchange groups but leave `key_share` empty, so the server answers with a HelloRetryRequest that names the group it chose. By offering groups, recording the server's choice and removing it, QRisk lists every group the server supports, including ML-KEM hybrids, using only Python's standard library.

### Code rules

Layer 4 uses about 45 regex rules ([`scanners/code.py`](src/qrisk/scanners/code.py)) that run on whole files, so a call split over several lines still matches and its key size is read correctly.

| Finds | Python | Java / Kotlin | JS / TS | Go |
|---|---|---|---|---|
| RSA / ECDSA / Ed25519 / DSA / DH keys (with size or curve) | `rsa.generate_private_key(key_size=…)`, `ec.generate_private_key(ec.SECP384R1())`, `RSA.generate(…)` | `KeyPairGenerator.getInstance("RSA")` + `.initialize(2048)`, `ECGenParameterSpec`, `Signature.getInstance("SHA1withRSA")` | `generateKeyPairSync('rsa', {modulusLength})`, WebCrypto, `createECDH` | `rsa.GenerateKey(r, 2048)`, `ecdsa.GenerateKey(elliptic.P256(), …)`, `ecdh.X25519()` |
| MD5 / SHA-1 | `hashlib.md5()` (skips `usedforsecurity=False`) | `MessageDigest.getInstance("MD5")` | `createHash('sha1')` | `md5.Sum` |
| Weak ciphers and ECB | `DES3.new`, `modes.ECB()`, `AES.MODE_ECB` | `Cipher.getInstance("AES")` (silently ECB), `"DESede/…"` | `createCipheriv('des-ede3-cbc')`, `crypto.createCipher` | `des.NewTripleDESCipher`, `rc4.NewCipher` |
| Old TLS and disabled verification | `minimum_version = TLSVersion.TLSv1`, `verify=False`, `= ssl.CERT_NONE` | `SSLContext.getInstance("TLSv1")`, `NoopHostnameVerifier` | `rejectUnauthorized: false`, `minVersion: 'TLSv1'` | `InsecureSkipVerify: true`, `tls.VersionTLS10` |
| Post-quantum (✅ safe) | `oqs.KeyEncapsulation("ML-KEM-768")` | `getInstance("ML-KEM-768")`, `MLKEMParameterSpec` | `@noble/post-quantum` `ml_kem768` | `mlkem.GenerateKey768()` |
| Private keys committed to code | all languages | | | |

The scanner skips comments, `node_modules`, `vendor`, virtualenvs and build folders. To silence a deliberate use, add `qrisk: ignore` in a comment on that line.

### Config checks

Layer 5 ([`scanners/config.py`](src/qrisk/scanners/config.py)) recognises config files by their contents, so Debian-style `sites-enabled/example` files without an extension work too. Every finding points to `file:line`, and its fix is written in that server's own syntax.

| Server | What it checks |
|---|---|
| nginx | `ssl_protocols`, `ssl_ciphers`, `ssl_ecdh_curve`, `ssl_conf_command Groups/MinProtocol`, and the files named in `ssl_certificate` / `ssl_dhparam` |
| Apache httpd | `SSLProtocol` (resolves `all -SSLv3`, which still enables TLS 1.0/1.1), `SSLCipherSuite`, `SSLOpenSSLConfCmd Groups/MinProtocol/DHParameters`, and the file named in `SSLCertificateFile` |
| OpenSSL | `MinProtocol`, `CipherString` (including `@SECLEVEL=0/1`), `Ciphersuites`, `Groups`, and `[req] default_bits` / `default_md` |
| OpenSSH | `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `Ciphers`, `MACs`, `Protocol 1`, the `HostKey` files (via their `.pub`), and the `+` / `-` / `^` list modifiers |

Cipher strings are read the way OpenSSL reads them: `!`/`-` exclusions are ignored, while `RC4`, `3DES`, `kRSA`, `ALL` (without `!kRSA`) and static-RSA suite names such as `AES256-SHA` are flagged. When a setting is missing, a note says which default applies, for example *"Key-exchange groups are not set: OpenSSL 3.5+ offers X25519MLKEM768 by default; older versions offer none."*

### The quantum-risk engine

| Rating | Meaning | Examples |
|---|---|---|
| 🔴 Critical | Weak even today | RSA-1024, SHA-1 signatures, TLS 1.0/1.1, RC4, 3DES, static-RSA key exchange, `ssh-rsa` |
| 🟠 Quantum-vulnerable | Fine today, broken by quantum | RSA-2048/3072, ECDSA, Ed25519, ECDHE, X25519, DH |
| 🟡 Hybrid / transitional | Post-quantum + classical combined (today's recommended deployment) | X25519MLKEM768, SecP256r1MLKEM768, mlkem768x25519-sha256 |
| 🟢 Quantum-safe | Post-quantum standards or strong symmetric crypto | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), AES-256 |

Each finding includes:

- **A NIST deadline**: "deprecated after 2030, disallowed after 2035" for 112-bit keys such as RSA-2048, or "disallowed after 2035" for stronger keys.
- **A specific recommendation**, for example *"Enable hybrid post-quantum key exchange with OpenSSL 3.5+: `Groups = X25519MLKEM768:X25519:secp256r1`"*.

**Quantum Readiness score (0-100).** Only *public-key* findings (key exchange, certificate keys and signatures, host keys and other key pairs) measure quantum readiness. They earn 100 points if quantum-safe **or hybrid** (hybrid is the recommended deployment, so it never scores below pure ML-KEM), 25 if quantum-vulnerable and 0 if critical. Protocol versions, symmetric ciphers, MACs and other hygiene findings count only when they are critical: AES-GCM shouldn't make a classical server look "in transition". Findings are averaged per category inside a target, so 15 cipher suites don't outweigh one certificate. Categories are then averaged per target, and targets are averaged together. **Any critical finding caps the score at 49.** See [`scoring.py`](src/qrisk/scoring.py).

### Outputs

- **Terminal**: a colour-coded table with the top recommendations.
- **CycloneDX 1.6 CBOM** (`--cbom`): algorithms, certificates, keys and protocols (with cipher suites) as `cryptographic-asset` components, linked through `dependencies`. Code findings are recorded as evidence occurrences with file and line. The test suite validates it against the official schema.
- **HTML report** (`--html`): an executive summary with a score gauge, NIST deadline counts and priority actions, followed by technical detail. It's self-contained, prints cleanly and supports dark mode.
- **PDF report** (`--pdf`): the same report, printed to A4 by an installed Chrome, Edge or Chromium (no extra Python dependencies; set `QRISK_BROWSER` to choose one).
- **Arabic report** (`--lang ar`): a right-to-left HTML/PDF report. The executive summary, ratings, deadlines and priority actions are in Arabic; technical reasons stay in English so algorithm names stay exact.
- **JSON** (`--json`): for other tools and pipelines.

## Install

```bash
git clone https://github.com/mxnxvr/qrisk-scanner && cd qrisk-scanner
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
qrisk scan --tls pq.cloudflareresearch.com            # a server that offers X25519MLKEM768
qrisk scan --tls example.com:8443 --ssh github.com --path ./certs
qrisk scan --tls example.com --html report.html --cbom cbom.json --json results.json
qrisk scan --tls example.com --pdf report-ar.pdf --lang ar   # Arabic PDF for the executive summary
qrisk scan --code ./my-app --html code-report.html     # file:line findings for a codebase
qrisk scan --config /etc/nginx --config /etc/apache2 --config /etc/ssh --config /etc/ssl/openssl.cnf
qrisk scan --path /etc/ssl --fail-under 50            # CI gate: exit code 2 if the score < 50
qrisk scan --code ./src --fail-under 80 --allow-empty  # pass a code base with no crypto at all
```

> **Responsible use:** only scan systems you own or have written permission to test. A TLS scan makes about 30-100 short handshakes per endpoint. See [SECURITY.md](SECURITY.md).

## Learn more

- **[Study guide (PDF)](docs/QRisk-Study-Guide.pdf)**: how the whole project works, from the big picture to each module, with diagrams.
- **[NOTES.md](NOTES.md)**: bugs found while building it (including a report XSS found in code review), how each was fixed, and the regression test that guards it.

## Lab

[`lab/`](lab) is a Docker Compose lab with weak, classical and post-quantum TLS and SSH servers (OpenSSL 3.5, OpenSSH 10), plus sample certificates, insecure sample code and configs, so every layer can be demoed and tested end to end:

```bash
docker compose -f lab/docker-compose.yml up -d --build
pytest -m lab
```

See [lab/README.md](lab/README.md) for the expected result of each server.

## Development

```bash
pytest                    # all tests run offline using local TLS and SSH test servers
```

```text
src/qrisk/
  models.py          Finding, Rating, Algo, CertInfo, ScanResult
  rules.py           the quantum-risk engine: ratings, NIST deadlines, recommendations
  scoring.py         Quantum Readiness score
  scanners/tlswire.py  raw ClientHello / ServerHello / HelloRetryRequest
  scanners/tls.py      Layer 1
  scanners/certs.py    Layer 2
  scanners/ssh.py      Layer 3 (reads the clear-text SSH KEXINIT)
  scanners/code.py     Layer 4 (regex rules for Python, Java, JS/TS, Go)
  scanners/config.py   Layer 5 (nginx, Apache, openssl.cnf, OpenSSH parsers)
  reports/           terminal, JSON, CBOM, HTML (Jinja2), PDF (headless Chromium)
  i18n.py            English / Arabic report text
```

## Roadmap

- [x] Layer 4: regex source-code rules for Python, Java/Kotlin, JS/TS and Go
- [x] Layer 4 v2: key sizes and curves held in constants, defaults and class attributes (Python AST; regex for Java/JS/Go)
- [ ] Semgrep rules for full data-flow tracking across files
- [x] Layer 5: nginx / Apache / OpenSSL / OpenSSH config analysis
- [x] Layer 5 v2: follow `include` / `Include` / `.include` directives; report the nginx `server`, Apache `VirtualHost` or SSH `Host`/`Match` block of each finding
- [ ] HAProxy and Postfix configs
- [x] Docker lab with deliberately weak, modern and post-quantum servers (OpenSSL 3.5, OpenSSH 10)
- [x] TLS 1.2 ECDHE curve and DHE prime-size detection (from ServerKeyExchange)
- [ ] Full certificate chain analysis
- [x] SSH RSA host key sizes
- [x] PDF export and an Arabic report (RTL)
- [x] JKS / JCEKS keystores

## Limitations

QRisk is an automated, point-in-time assessment, not a full audit. NIST deadlines are based on NIST IR 8547, so check them against the latest NIST publication.

- **What a server offers, not what each client negotiates.** QRisk lists everything a server accepts. It probes 68 TLS 1.2-era cipher suites (including NULL, EXPORT, DES, RC4, anonymous, Camellia, ARIA, SEED and CCM) at every older protocol version the server allows, plus all TLS 1.3 suites. Suites outside that list are not tested.
- **Server certificates are fetched with Python's `ssl` module**, so the certificate check fails (with a note) on servers that Python's OpenSSL can't negotiate with, such as servers presenting only an ML-DSA certificate or offering only pure ML-KEM key exchange. The key-exchange findings still work, because those come from QRisk's own TLS messages.
- **Only the leaf certificate is analysed**, not the intermediate and root certificates in the chain.
- **Code scanning uses regular expressions.** Lines that *start* with a comment are skipped, but matches inside block comments, Python docstrings or string literals are still reported. Key sizes are resolved from constants and defaults in the same file, not across files. Add `qrisk: ignore` to silence a line.
- **Config includes stay inside the scanned folder.** `include` directives, certificate paths and host keys that point outside the folder you scan are *not* read, so scanning a copied config never pulls the scanning machine's own `/etc` files into the report. Each skipped file is listed in the notes. Use `--config-follow-external` when you are scanning a live system and want them followed.
- **`--fail-under` fails on incomplete scans.** If any target can't be scanned, or nothing cryptographic is found, the gate fails rather than showing a green build. Add `--allow-empty` when finding nothing is expected.

## License

MIT. See [LICENSE](LICENSE).
