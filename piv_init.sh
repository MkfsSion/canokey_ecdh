#!/usr/bin/bash

openssl ecparam -name secp384r1 -noout -genkey -outform PEM -out privkey2.pem
openssl req -keyform PEM -key privkey2.pem -new -x509 -nodes -subj '/CN=P384-TEST/' -days 365 -sha256 -outform PEM -out pubkey2.pem -addext keyUsage=critical,keyAgreement,digitalSignature
ykman -r Cano piv keys import 9a privkey2.pem
ykman -r Cano piv certificates import 9a pubkey2.pem
pkcs15-tool --list-keys --list-public-keys
