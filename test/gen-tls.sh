#!/usr/bin/env bash
# Generate a lab CA and a server certificate for the BIG-IP virtual server.
# Output in test/tls/ (git-ignored). The test client validates against ca.pem.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/tls"
VIP_IP="${VIP_IP:?set VIP_IP to the virtual server address, e.g. VIP_IP=192.0.2.100 test/gen-tls.sh}"
VIP_NAME="${VIP_NAME:-csv-lab.local}"
mkdir -p "$OUT" && chmod 700 "$OUT" && cd "$OUT"

if [[ ! -f ca.key ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
    -keyout ca.key -out ca.pem -subj "/CN=csv-lab test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
fi
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr \
  -subj "/CN=$VIP_NAME" >/dev/null 2>&1
cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:$VIP_IP,DNS:$VIP_NAME
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
  -extfile server.ext -out server.crt >/dev/null 2>&1
# A second, unrelated CA used by the "wrong CA" TLS test.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
  -keyout wrong-ca.key -out wrong-ca.pem -subj "/CN=unrelated CA" >/dev/null 2>&1
chmod 600 ./*.key
echo "wrote $OUT: ca.pem server.crt server.key (SAN IP:$VIP_IP, DNS:$VIP_NAME)"
