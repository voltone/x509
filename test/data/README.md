# Generating sample data with OpenSSL

When regenerating the test dataset, ensure to update all files! Test cases
assume that the different variants of a private/public key encode the same
keypair.

## RSA keys

Generating PEM output:

```bash
openssl genrsa -out rsa.pem
openssl rsa -in rsa.pem -pubout -out rsa_pub.pem
openssl rsa -in rsa.pem -des3 -passout pass:secret -out rsa_des3.pem
openssl rsa -in rsa.pem -aes256 -passout pass:secret -out rsa_aes.pem
openssl pkcs8 -in rsa.pem -topk8 -nocrypt -out rsa_pkcs8.pem
openssl pkcs8 -in rsa.pem -topk8 -passout pass:secret -out rsa_pkcs8_enc.pem
```

Generating DER output:

```bash
openssl rsa -in rsa.pem -out rsa.der -outform der
openssl rsa -in rsa.pem -pubout -out rsa_pub.der -outform der
openssl rsa -in rsa.pem -des3 -out rsa_des3.der -passout pass:secret -outform der
openssl rsa -in rsa.pem -aes256 -out rsa_aes.der -passout pass:secret -outform der
openssl pkcs8 -in rsa.pem -topk8 -nocrypt -out rsa_pkcs8.der -outform der
openssl pkcs8 -in rsa.pem -topk8 -passout pass:secret -out rsa_pkcs8_enc.der -outform der
```

## EC keys

Generating PEM output:

```bash
openssl ecparam -name secp256k1 -genkey -out secp256k1.pem
openssl ec -in secp256k1.pem -pubout -out secp256k1_pub.pem
openssl ec -in secp256k1.pem -des3 -passout pass:secret -out secp256k1_des3.pem
openssl ec -in secp256k1.pem -aes256 -passout pass:secret -out secp256k1_aes.pem
openssl pkcs8 -in secp256k1.pem  -topk8 -nocrypt -out secp256k1_pkcs8.pem
openssl pkcs8 -in secp256k1.pem  -topk8 -passout pass:secret -out secp256k1_pkcs8_enc.pem
```

Generating DER output:

```bash
openssl ec -in secp256k1.pem -out secp256k1.der -outform der
openssl ec -in secp256k1.pem -pubout -out secp256k1_pub.der -outform der
openssl ec -in secp256k1.pem -des3 -out secp256k1_des3.der -passout pass:secret -outform der
openssl ec -in secp256k1.pem -aes256 -out secp256k1_aes.der -passout pass:secret -outform der
openssl pkcs8 -in secp256k1.pem -topk8 -nocrypt -out secp256k1_pkcs8.der -outform der
openssl pkcs8 -in secp256k1.pem -topk8 -passout pass:secret -out secp256k1_pkcs8_enc.der -outform der
```

## CSRs

Generating PEM output:

```bash
openssl req -new -sha256 -subj "/C=US/ST=NT/L=Springfield/O=ACME Inc." -key rsa.pem -out csr_rsa.pem
openssl req -new -sha256 -subj "/C=US/ST=NT/L=Springfield/O=ACME Inc." -key secp256k1.pem -out csr_secp256k1.pem
```

Generating DER output:

```bash
openssl req -in csr_rsa.pem -out csr_rsa.der -outform der
openssl req -in csr_secp256k1.pem -out csr_secp256k1.der -outform der
```
