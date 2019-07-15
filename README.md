# X509

[![Build Status](https://travis-ci.com/voltone/x509.svg?branch=master)](https://travis-ci.com/voltone/x509)
[![Hex.pm](https://img.shields.io/hexpm/v/x509.svg)](https://hex.pm/packages/x509)
[![Hex.pm](https://img.shields.io/hexpm/dt/x509.svg)](https://hex.pm/packages/x509)

Elixir package for working with X.509 certificates, Certificate Signing Requests (CSRs), Certificate Revocation Lists (CRLs) and RSA/ECC key pairs.

Requires Erlang/OTP 20.1 or later.

## Usage

### As a Certificate Authority (CA)

Generate a self-signed CA certificate and private key, using the `root_ca`
template:

```elixir
iex> ca_key = X509.PrivateKey.new_ec(:secp256r1)
{:ECPrivateKey, ...}
iex> ca = X509.Certificate.self_signed(ca_key,
...>   "/C=US/ST=CA/L=San Francisco/O=Acme/CN=ECDSA Root CA",
...>   template: :root_ca
...>)
{:OTPCertificate, ...}
```

Use the CA certificate to issue a server certificate, using the default
`server` template and the given SAN hostnames:

```elixir
iex> my_key = X509.PrivateKey.new_ec(:secp256r1)
{:ECPrivateKey, ...}
iex> my_cert = my_key |>
...> X509.PublicKey.derive() |>
...> X509.Certificate.new(
...>   "/C=US/ST=CA/L=San Francisco/O=Acme/CN=Sample",
...>   ca, ca_key,
...>   extensions: [
...>     subject_alt_name: X509.Certificate.Extension.subject_alt_name(["example.org", "www.example.org"])
...>   ]
...> )
{:OTPCertificate, ...}
```

Or sign a certificate based on an incoming CSR:

```elixir
iex> csr = X509.CSR.from_pem!(pem_string)
{:CertificationRequest, ...}
iex> subject = X509.CSR.subject(csr)
{:rdnSequence, ...}
iex> my_cert = csr |>
...> X509.CSR.public_key() |>
...> X509.Certificate.new(
...>   subject,
...>   ca, ca_key,
...>   extensions: [
...>     subject_alt_name: X509.Certificate.Extension.subject_alt_name(["example.org", "www.example.org"])
...>   ]
...> )
```

### With `:public_key` for encryption/signing

Please refer to the documentation for the `X509.PrivateKey` module for
examples showing asymmetrical encryption and decryption, as well as message
signing and verification, with Erlang/OTP's `:public_key` APIs.

### For TLS client/server testing

The `x509.gen.selfsigned` Mix task generates a self-signed certificate for use
with a TLS server in development or testing.

The `X509.Test.Suite` and `X509.Test.Server` modules may be used to create
test cases for TLS clients. The [server_test.exs](test/x509/test/server_test.exs)
file can serve as a template: update the `request/2` function to invoke of the
TLS client under test,  make sure it returns the expected response format, and
update the test server's canned response in the test module's setup if
necessary.

You may want to include the X509 package only in the 'dev' and/or 'test'
environments for this use-case, by adding an `only: ...` clause to the
dependency definition in your Mix file.

## Installation

Add `x509` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:x509, "~> 0.7.0"}
  ]
end
```

Documentation can be found at [https://hexdocs.pm/x509](https://hexdocs.pm/x509).
