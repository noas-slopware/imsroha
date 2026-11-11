# SPDX-License-Identifier: GPL-3.0-only
# make_certs DIR: a test CA and a server certificate for localhost in DIR.
make_certs() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
		-subj "/CN=imsroha test CA" -keyout "$1/ca.key" -out "$1/ca.pem" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-subj "/CN=localhost" -keyout "$1/server.key" -out "$1/server.csr" 2>/dev/null
	printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$1/ext"
	openssl x509 -req -in "$1/server.csr" -CA "$1/ca.pem" -CAkey "$1/ca.key" -CAcreateserial \
		-days 2 -extfile "$1/ext" -out "$1/server.pem" 2>/dev/null
}
