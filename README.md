# X509

[![Build Status](https://travis-ci.com/voltone/x509.svg?branch=master)](https://travis-ci.com/voltone/x509)

Elixir package for working with certificates, CSRs and key pairs.

Requires Erlang/OTP 20.1 or later.

## Usage

Generate a self-signed CA certificate and private key:

```elixir
iex> ca_key = X509.PrivateKey.new_ec(:secp256r1)
{:ECPrivateKey, ...}
iex> ca = X509.Certificate.self_signed(ca_key,
...>   "/C=US/ST=CA/L=San Francisco/O=Acme/CN=ECDSA Root CA",
...>   template: :root_ca
...>)
{:OTPCertificate, ...}
```

Use a CA certificate to issue a server certificate :

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

Please refer to the documentation for the `X509.PrivateKey` module for
examples showing asymmetrical encryption and decryption, as well as message
signing and verification, with Erlang/OTP's `:public_key` APIs.

## Mix tasks

The `x509.gen.selfsigned` Mix task generates a self-signed certificate for use
with a TLS server in development or testing.

## Installation

Add `x509` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:x509, "~> 0.4.0"}
  ]
end
```

Documentation can be found at [https://hexdocs.pm/x509](https://hexdocs.pm/x509).
