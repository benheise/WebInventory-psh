#!/usr/bin/env bash
# Creates the lab certificates start-lab.sh expects in <certdir>:
#   lab.pem/lab.key   RSA 2048, CN=localhost, SANs localhost/app1.lab.test/app2.lab.test/127.0.0.1, 400 days
#   weak.pem/weak.key RSA 1024, SHA-1, CN=weak.lab.test O=Fortinet OU=FortiGate, 10 days (legacy-appliance fixture)
# Benchmark references embed certificate fields, so re-create the references after making new certificates.
set -eu
D=${1:?certdir}; mkdir -p "$D"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/lab.key" -out "$D/lab.pem" -days 400 -sha256 \
    -subj "/CN=localhost/O=WebInv Lab" -addext "subjectAltName=DNS:localhost,DNS:app1.lab.test,DNS:app2.lab.test,IP:127.0.0.1" 2>/dev/null
openssl req -x509 -newkey rsa:1024 -nodes -keyout "$D/weak.key" -out "$D/weak.pem" -days 10 -sha1 \
    -subj "/CN=weak.lab.test/O=Fortinet/OU=FortiGate" 2>/dev/null
ls -l "$D"
