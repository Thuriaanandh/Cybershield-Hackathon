#!/usr/bin/env bash
# gen_certs.sh - Generate self-signed TLS certificates for development/testing.
# For production, use certificates from a trusted CA (Let's Encrypt, etc.)
#
# Usage: bash gen_certs.sh [output_dir]

set -euo pipefail

OUTPUT_DIR="${1:-./certs}"
mkdir -p "$OUTPUT_DIR"

echo "[*] Generating self-signed TLS certificate for LiveBoot Sentinel..."

# Generate private key (RSA 4096)
openssl genrsa -out "$OUTPUT_DIR/server.key" 4096

# Generate self-signed certificate (valid 365 days)
openssl req -new -x509 \
    -key "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.crt" \
    -days 365 \
    -subj "/CN=liveboot-sentinel/O=LiveBoot Sentinel/C=US" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Set secure permissions
chmod 600 "$OUTPUT_DIR/server.key"
chmod 644 "$OUTPUT_DIR/server.crt"

echo "[+] Certificates generated:"
echo "    Key:  $OUTPUT_DIR/server.key"
echo "    Cert: $OUTPUT_DIR/server.crt"
echo ""
echo "[!] For production, replace with certificates from a trusted CA."
