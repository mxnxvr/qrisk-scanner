#!/bin/sh
# Creates the lab's certificates once. Delete lab/nginx/certs to regenerate.
# Needs OpenSSL 3.5+ (for ML-DSA), which the Alpine 3.22 lab image provides.
set -eu
cd /out
if [ -f .done ]; then
  echo "certgen: certificates already exist"
  exit 0
fi

san="subjectAltName=DNS:localhost,IP:127.0.0.1"

# Weak: RSA-1024 signed with SHA-1 (critical today)
openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 825 \
  -subj "/CN=weak.qrisk.lab" -addext "$san" -keyout weak.key -out weak.crt

# Modern: ECDSA P-256 (quantum-vulnerable)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 825 \
  -subj "/CN=modern.qrisk.lab" -addext "$san" -keyout modern.key -out modern.crt

# Post-quantum server: ECDSA P-384 for the handshake (clients can't verify ML-DSA yet)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes -days 825 \
  -subj "/CN=pq.qrisk.lab" -addext "$san" -keyout pq.key -out pq.crt

# Sample ML-DSA-65 certificate (FIPS 204) for the file scanner (Layer 2)
openssl req -x509 -newkey ML-DSA-65 -nodes -days 825 \
  -subj "/CN=mldsa.qrisk.lab" -keyout mldsa.key -out mldsa.crt

# Lab only: let nginx workers and the host user read the keys.
chmod 644 ./*.key ./*.crt
touch .done
echo "certgen: done"
ls -l
