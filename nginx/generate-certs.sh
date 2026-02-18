#!/bin/bash
# Generate self-signed certificates for development/testing
# For production, use Let's Encrypt or a proper CA

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="${SCRIPT_DIR}/ssl"

# Create SSL directory if it doesn't exist
mkdir -p "${SSL_DIR}"

# Certificate details
DAYS=365
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORG="NetworkOps Development"
CN="localhost"

echo "Generating self-signed certificate for development..."

# Generate private key and certificate
openssl req -x509 -nodes -days ${DAYS} -newkey rsa:2048 \
    -keyout "${SSL_DIR}/server.key" \
    -out "${SSL_DIR}/server.crt" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/CN=${CN}" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,DNS:networkops.local,IP:127.0.0.1"

# Set permissions
chmod 600 "${SSL_DIR}/server.key"
chmod 644 "${SSL_DIR}/server.crt"

echo ""
echo "Certificate generated successfully!"
echo "  Key:  ${SSL_DIR}/server.key"
echo "  Cert: ${SSL_DIR}/server.crt"
echo ""
echo "Certificate details:"
openssl x509 -in "${SSL_DIR}/server.crt" -noout -subject -dates
echo ""
echo "NOTE: This is a self-signed certificate for development only."
echo "      For production, use Let's Encrypt or a trusted CA."
