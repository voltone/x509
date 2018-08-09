defmodule X509.CSRTest do
  use ExUnit.Case
  import X509.ASN1

  doctest X509.CSR

  setup_all do
    [
      rsa_key: X509.PrivateKey.new_rsa(512),
      ec_key: X509.PrivateKey.new_ec(:secp256r1)
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
      csr = X509.CSR.from_pem!(pem)
      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)

      assert csr == csr |> X509.CSR.to_pem() |> X509.CSR.from_pem!()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/csr_rsa.der")
      assert match?(certification_request(), X509.CSR.from_der!(der))
      assert der == der |> X509.CSR.from_der!() |> X509.CSR.to_der()
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
      pem = File.read!("test/data/csr_prime256v1.pem")
      csr = X509.CSR.from_pem!(pem)
      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)

      assert csr == csr |> X509.CSR.to_pem() |> X509.CSR.from_pem!()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/csr_prime256v1.der")
      assert match?(certification_request(), X509.CSR.from_der!(der))
      assert der == der |> X509.CSR.from_der!() |> X509.CSR.to_der()
    end
  end
end
