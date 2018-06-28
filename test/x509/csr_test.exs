defmodule X509.CSRTest do
  use ExUnit.Case
  import X509.ASN1

  doctest X509.CSR

  setup_all do
    [
      rsa_key: X509.PrivateKey.new_rsa(512),
      ec_key: X509.PrivateKey.new_ec(:secp256k1)
    ]
  end

  describe "RSA" do
    test "new and valid?", context do
      csr =
        context.rsa_key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)
    end

    test :public_key, context do
      csr =
        context.rsa_key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert X509.CSR.public_key(csr) == X509.PublicKey.derive(context.rsa_key)
    end

    test :subject, context do
      csr =
        context.rsa_key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert X509.CSR.subject(csr) ==
               X509.RDNSequence.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")
    end

    test "PEM decode and encode" do
      pem = File.read!("test/data/csr_rsa.pem")
      csr = X509.from_pem(pem) |> hd
      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)

      assert csr == csr |> X509.to_pem() |> X509.from_pem() |> hd()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/csr_rsa.der")
      assert match?(certification_request(), X509.from_der(der, :CertificationRequest))
      assert der == der |> X509.from_der(:CertificationRequest) |> X509.to_der()
    end
  end

  describe "ECDSA" do
    test "new and valid?", context do
      csr =
        context.ec_key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)
    end

    test :public_key, context do
      csr =
        context.ec_key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert X509.CSR.public_key(csr) == X509.PublicKey.derive(context.ec_key)
    end

    test "PEM decode and encode" do
      pem = File.read!("test/data/csr_secp256k1.pem")
      csr = X509.from_pem(pem) |> hd
      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)

      assert csr == csr |> X509.to_pem() |> X509.from_pem() |> hd()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/csr_secp256k1.der")
      assert match?(certification_request(), X509.from_der(der, :CertificationRequest))
      assert der == der |> X509.from_der(:CertificationRequest) |> X509.to_der()
    end
  end
end
