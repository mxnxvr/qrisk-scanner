# QRisk lab

A set of local servers built to be scanned: one **weak**, one **modern but classical**, and one **post-quantum** setup for each protocol. Use it to demo QRisk, to try new rules, and to check that every rating works end to end.

> ⚠️ The weak servers are insecure on purpose. Every port is bound to `127.0.0.1`. Never expose them to a network.

## Servers

| Service | Address | What it runs | Expected QRisk result |
|---|---|---|---|
| `weak-tls` | `localhost:8443` | TLS 1.0/1.1/1.2, static RSA, RSA-1024 cert signed with SHA-1, `@SECLEVEL=0` | 🔴 Critical |
| `modern-tls` | `localhost:8444` | TLS 1.2/1.3, ECDHE (X25519, P-256), AES-GCM, ECDSA P-256 cert | 🟠 Quantum-vulnerable |
| `pq-tls` | `localhost:8445` | TLS 1.3 only, X25519MLKEM768, SecP384r1MLKEM1024, MLKEM1024 (OpenSSL 3.5) | 🟡 Hybrid / 🟢 Quantum-safe |
| `weak-ssh` | `localhost:2222` | diffie-hellman-group1-sha1, ssh-rsa, 3des-cbc, hmac-md5 | 🔴 Critical |
| `pq-ssh` | `localhost:2223` | mlkem768x25519-sha256, sntrup761x25519 only (OpenSSH 10) | 🟡 Hybrid |

Each layer also has something to scan:

- **Layer 2 (files):** `certgen` writes the lab certificates to `lab/nginx/certs/`, including an **ML-DSA-65** certificate.
- **Layer 4 (code):** [`sample-app/`](sample-app) contains insecure and post-quantum crypto calls in Python, Java, JavaScript and Go.
- **Layer 5 (config):** the nginx sites and `sshd_config` files the servers use are in this folder.

All images are based on Alpine 3.22, which ships **OpenSSL 3.5** and **OpenSSH 10**, so post-quantum support is built in. No extra plugins are needed.

## Run it

Needs Docker Desktop (Windows/macOS) or Docker Engine with the Compose plugin (Linux).

```bash
docker compose -f lab/docker-compose.yml up -d --build
```

Scan everything (all five layers) and write the reports:

```bash
qrisk scan --tls localhost:8443 --tls localhost:8444 --tls localhost:8445 --ssh localhost:2222 --ssh localhost:2223 --path lab/nginx/certs --code lab/sample-app --config lab --html lab-report.html --cbom lab-cbom.json
```

Check each server gets the rating it was built for:

```bash
pytest -m lab -v
```

Stop it:

```bash
docker compose -f lab/docker-compose.yml down
```

To regenerate the certificates, delete `lab/nginx/certs/` and start the lab again.

## Notes

- `weak-tls` *asks* for 3DES (`DES-CBC3-SHA`), but Alpine's OpenSSL 3.5 no longer offers it. The config scan (`--config lab`) flags the setting, while the live scan correctly shows the server never accepts it: a good example of the difference between what a config says and what a server actually does.
- The `pq-tls` server uses an ECDSA P-384 certificate, because browsers and most TLS libraries can't verify ML-DSA certificates yet. Its *key exchange* is post-quantum. The ML-DSA certificate is there for the file scanner.
- The SSH servers have no user accounts. QRisk only reads the algorithm list each server sends before login.
- CI starts the same lab on GitHub Actions (`lab` job) with `QRISK_LAB_REQUIRED=1`, so a server that fails to start fails the build instead of skipping.
