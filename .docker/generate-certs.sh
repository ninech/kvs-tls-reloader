#!/bin/sh

set -e

CERT_DIR="/certs"
DAYS_VALID=365

echo "Generating test TLS certificates in ${CERT_DIR}"

apk add -U openssl

# Create certificate directory if it doesn't exist
mkdir -p "${CERT_DIR}"

# Generate CA private key
echo "Generating CA private key..."
openssl genrsa -out "${CERT_DIR}/ca.key" 4096

# Generate CA certificate
echo "Generating CA certificate..."
openssl req -new -x509 -days ${DAYS_VALID} -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/C=US/ST=Test/L=Test/O=Test Org/OU=Test/CN=Test CA"

# Generate server private key
echo "Generating server private key..."
openssl genrsa -out "${CERT_DIR}/tls.key" 4096

# Generate server certificate signing request
echo "Generating server CSR..."
openssl req -new -key "${CERT_DIR}/tls.key" \
    -out "${CERT_DIR}/tls.csr" \
    -subj "/C=US/ST=Test/L=Test/O=Test Org/OU=Test/CN=redis"

# Create extensions file for SAN
cat >"${CERT_DIR}/tls.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = redis
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Generate server certificate signed by CA
echo "Generating server certificate..."
openssl x509 -req -in "${CERT_DIR}/tls.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/tls.crt" \
    -days ${DAYS_VALID} \
    -extfile "${CERT_DIR}/tls.ext"

# Clean up intermediate files
rm -f "${CERT_DIR}/tls.csr" "${CERT_DIR}/tls.ext" "${CERT_DIR}/ca.key" "${CERT_DIR}/ca.srl"

# Set appropriate permissions
chmod 644 "${CERT_DIR}/ca.crt"
chmod 644 "${CERT_DIR}/tls.crt"
chmod 600 "${CERT_DIR}/tls.key"

echo "✓ Certificate generation complete!"
echo ""
echo "Generated files:"
ls -lh "${CERT_DIR}/"
echo ""
echo "Certificate details:"
openssl x509 -in "${CERT_DIR}/tls.crt" -noout -subject -issuer -dates
