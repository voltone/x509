defmodule X509.CSRTest do
  use ExUnit.Case
  import X509.ASN1

  doctest X509.CSR

  describe "RSA" do
    setup _context, do: [key: X509.PrivateKey.new_rsa(512)]

    test "new and valid?", context do
      csr =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)
    end

    test :public_key, context do
      csr =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert X509.CSR.public_key(csr) == X509.PublicKey.derive(context.key)
    end

    test :subject, context do
      csr =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert X509.CSR.subject(csr) ==
               X509.RDNSequence.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")
    end

    test :extension_request, context do
      csr_without_ext =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      san = X509.Certificate.Extension.subject_alt_name(["www.example.net"])

      csr_with_ext =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.",
          extension_request: [san]
        )

      assert X509.CSR.extension_request(csr_without_ext) == []
      assert X509.CSR.extension_request(csr_with_ext) == [san]
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
    setup _context, do: [key: X509.PrivateKey.new_ec(:secp256r1)]

    test "new and valid?", context do
      csr =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert match?(certification_request(), csr)
      assert X509.CSR.valid?(csr)
    end

    test :public_key, context do
      csr =
        context.key
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert X509.CSR.public_key(csr) == X509.PublicKey.derive(context.key)
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
