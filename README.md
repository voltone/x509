# X509

[![Github.com](https://github.com/voltone/x509/workflows/CI/badge.svg)](https://github.com/voltone/x509/actions)
[![Hex.pm](https://img.shields.io/hexpm/v/x509.svg)](https://hex.pm/packages/x509)
[![Hexdocs.pm](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/x509/)
[![Hex.pm](https://img.shields.io/hexpm/dt/x509.svg)](https://hex.pm/packages/x509)
[![Hex.pm](https://img.shields.io/hexpm/l/x509.svg)](https://hex.pm/packages/x509)
[![Github.com](https://img.shields.io/github/last-commit/voltone/x509.svg)](https://github.com/voltone/x509/commits/master)


Elixir package for working with X.509 certificates, Certificate Signing Requests (CSRs), Certificate Revocation Lists (CRLs) and RSA/ECC key pairs.

Requires Erlang/OTP 20.1 or later.

Development and public release of this package were made possible by
[Bluecode](https://bluecode.com/).

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
    {:x509, "~> 0.8"}
  ]
end
```

Documentation can be found at [https://hexdocs.pm/x509](https://hexdocs.pm/x509).

## License

Copyright (c) 2019, Bram Verburg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its contributors
  may be used to endorse or promote products derived from this software
  without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
