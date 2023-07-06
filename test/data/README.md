# Generating sample data with OpenSSL

When regenerating the test dataset, ensure to update all files! Test cases
assume that the different variants of a private/public key encode the same
key pair.

## RSA keys

Generating PEM output:

```bash
openssl genrsa -out rsa.pem
openssl rsa -in rsa.pem -pubout -out rsa_pub.pem
openssl rsa -in rsa.pem -des3 -passout pass:secret -out rsa_des3.pem
openssl rsa -in rsa.pem -aes128 -passout pass:secret -out rsa_aes.pem
openssl pkcs8 -in rsa.pem -topk8 -nocrypt -out rsa_pkcs8.pem
openssl pkcs8 -in rsa.pem -topk8 -passout pass:secret -out rsa_pkcs8_enc.pem
```

Generating DER output:

```bash
openssl rsa -in rsa.pem -out rsa.der -outform der
openssl rsa -in rsa.pem -pubout -out rsa_pub.der -outform der
openssl rsa -in rsa.pem -des3 -out rsa_des3.der -passout pass:secret -outform der
openssl rsa -in rsa.pem -aes128 -out rsa_aes.der -passout pass:secret -outform der
openssl pkcs8 -in rsa.pem -topk8 -nocrypt -out rsa_pkcs8.der -outform der
openssl pkcs8 -in rsa.pem -topk8 -passout pass:secret -out rsa_pkcs8_enc.der -outform der
```

## EC keys

Generating PEM output:

```bash
openssl ecparam -name prime256v1 -genkey -out prime256v1.pem
openssl ec -in prime256v1.pem -pubout -out prime256v1_pub.pem
openssl ec -in prime256v1.pem -des3 -passout pass:secret -out prime256v1_des3.pem
openssl ec -in prime256v1.pem -aes128 -passout pass:secret -out prime256v1_aes.pem
openssl pkcs8 -in prime256v1.pem  -topk8 -nocrypt -out prime256v1_pkcs8.pem
openssl pkcs8 -in prime256v1.pem  -topk8 -passout pass:secret -out prime256v1_pkcs8_enc.pem
```

Generating DER output:

```bash
openssl ec -in prime256v1.pem -out prime256v1.der -outform der
openssl ec -in prime256v1.pem -pubout -out prime256v1_pub.der -outform der
openssl ec -in prime256v1.pem -des3 -out prime256v1_des3.der -passout pass:secret -outform der
openssl ec -in prime256v1.pem -aes128 -out prime256v1_aes.der -passout pass:secret -outform der
openssl pkcs8 -in prime256v1.pem -topk8 -nocrypt -out prime256v1_pkcs8.der -outform der
openssl pkcs8 -in prime256v1.pem -topk8 -passout pass:secret -out prime256v1_pkcs8_enc.der -outform der
```

## CSRs

Generating PEM output:

```bash
openssl req -new -sha256 -subj "/C=US/ST=NT/L=Springfield/O=ACME Inc." -key rsa.pem -out csr_rsa.pem
openssl req -new -sha256 -subj "/C=US/ST=NT/L=Springfield/O=ACME Inc." -key prime256v1.pem -out csr_prime256v1.pem
```

Generating DER output:

```bash
openssl req -in csr_rsa.pem -out csr_rsa.der -outform der
openssl req -in csr_prime256v1.pem -out csr_prime256v1.der -outform der
```

## Certificates

Generating PEM output:

```bash
openssl req -new -key rsa.pem -days 365 -x509 -subj "/C=US/ST=NT/L=Springfield/O=ACME Inc." -out selfsigned_rsa.pem
openssl req -new -key prime256v1.pem -days 365 -x509 -subj "/C=US/ST=NT/L=Springfield/O=ACME Inc." -out selfsigned_prime256v1.pem
```
