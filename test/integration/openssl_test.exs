defmodule X509.OpenSSLTest do
  # Integration testing with OpenSSL's CLI. Make sure the `openssl`
  # binary exists in your $PATH, or that you specify its full path
  # using the OPENSSL_PATH environment variable.

  use ExUnit.Case

  @moduletag :openssl

  setup_all do
    [openssl_version: openssl("version")]
  rescue
    ErlangError ->
      raise "Could not find OpenSSL executable; please set/fix OPENSSL_PATH environment variable"
  end

  describe "PEM encode" do
    test "OpenSSL can read RSA private keys" do
      pem_file =
        X509.PrivateKey.new_rsa(2048)
        |> write_tmp_pem()

      assert openssl(["rsa", "-in", pem_file, "-text", "-noout"]) =~ "Private-Key: (2048 bit)"
    end

    test "OpenSSL can read RSA public keys" do
      pem_file =
        X509.PrivateKey.new_rsa(2048)
        |> X509.PublicKey.derive()
        |> X509.PublicKey.wrap()
        |> write_tmp_pem()

      assert openssl(["rsa", "-pubin", "-in", pem_file, "-text", "-noout"]) =~
               "Public-Key: (2048 bit)"
    end

    test "OpenSSL can read EC private keys" do
      pem_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> write_tmp_pem()

      assert openssl(["ec", "-in", pem_file, "-text", "-noout"]) =~ "ASN1 OID: prime256v1"
    end

    test "OpenSSL can read EC public keys" do
      pem_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> X509.PublicKey.derive()
        |> X509.PublicKey.wrap()
        |> write_tmp_pem()

      assert openssl(["ec", "-pubin", "-in", pem_file, "-text", "-noout"]) =~
               "ASN1 OID: prime256v1"
    end

    test "OpenSSL can read CSRs (RSA)" do
      pem_file =
        X509.PrivateKey.new_rsa(2048)
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")
        |> write_tmp_pem()

      openssl_out = openssl(["req", "-verify", "-in", pem_file, "-text", "-noout"])
      assert openssl_out =~ "verify OK"
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: rsaEncryption"
      assert openssl_out =~ "Signature Algorithm: sha256WithRSAEncryption"
    end

    test "OpenSSL can read CSRs (ECDSA)" do
      pem_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")
        |> write_tmp_pem()

      openssl_out = openssl(["req", "-verify", "-in", pem_file, "-text", "-noout"])
      assert openssl_out =~ "verify OK"
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: id-ecPublicKey"
      assert openssl_out =~ "Signature Algorithm: ecdsa-with-SHA256"
    end

    test "OpenSSL can read certificates (RSA)" do
      pem_file =
        X509.PrivateKey.new_rsa(2048)
        |> X509.Certificate.self_signed(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc.",
          extensions: [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name(["acme.com", "www.acme.com"])
          ]
        )
        |> write_tmp_pem()

      openssl_out = openssl(["x509", "-in", pem_file, "-text", "-noout"])
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: rsaEncryption"
      assert openssl_out =~ "Signature Algorithm: sha256WithRSAEncryption"
      assert openssl_out =~ "DNS:acme.com, DNS:www.acme.com"
    end

    test "OpenSSL can read certificates (ECDSA)" do
      pem_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> X509.Certificate.self_signed(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc.",
          extensions: [
            subject_alte_name:
              X509.Certificate.Extension.subject_alt_name(["acme.com", "www.acme.com"])
          ]
        )
        |> write_tmp_pem()

      openssl_out = openssl(["x509", "-in", pem_file, "-text", "-noout"])
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: id-ecPublicKey"
      assert openssl_out =~ "Signature Algorithm: ecdsa-with-SHA256"
      assert openssl_out =~ "DNS:acme.com, DNS:www.acme.com"
    end
  end

  describe "DER encode" do
    test "OpenSSL can read RSA private keys" do
      der_file =
        X509.PrivateKey.new_rsa(2048)
        |> write_tmp_der()

      assert openssl(["rsa", "-in", der_file, "-inform", "der", "-text", "-noout"]) =~
               "Private-Key: (2048 bit)"
    end

    test "OpenSSL can read RSA public keys" do
      der_file =
        X509.PrivateKey.new_rsa(2048)
        |> X509.PublicKey.derive()
        |> X509.PublicKey.wrap()
        |> write_tmp_der()

      assert openssl(["rsa", "-pubin", "-in", der_file, "-inform", "der", "-text", "-noout"]) =~
               "Public-Key: (2048 bit)"
    end

    test "OpenSSL can read EC private keys" do
      der_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> write_tmp_der()

      assert openssl(["ec", "-in", der_file, "-inform", "der", "-text", "-noout"]) =~
               "ASN1 OID: prime256v1"
    end

    test "OpenSSL can read EC public keys" do
      der_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> X509.PublicKey.derive()
        |> X509.PublicKey.wrap()
        |> write_tmp_der()

      assert openssl(["ec", "-pubin", "-in", der_file, "-inform", "der", "-text", "-noout"]) =~
               "ASN1 OID: prime256v1"
    end

    test "OpenSSL can read CSRs (RSA)" do
      pem_file =
        X509.PrivateKey.new_rsa(2048)
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")
        |> write_tmp_der()

      openssl_out =
        openssl(["req", "-verify", "-in", pem_file, "-inform", "der", "-text", "-noout"])

      assert openssl_out =~ "verify OK"
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: rsaEncryption"
      assert openssl_out =~ "Signature Algorithm: sha256WithRSAEncryption"
    end

    test "OpenSSL can read CSRs (ECDSA)" do
      pem_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> X509.CSR.new("/C=US/ST=NT/L=Springfield/O=ACME Inc.")
        |> write_tmp_der()

      openssl_out =
        openssl(["req", "-verify", "-in", pem_file, "-inform", "der", "-text", "-noout"])

      assert openssl_out =~ "verify OK"
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: id-ecPublicKey"
      assert openssl_out =~ "Signature Algorithm: ecdsa-with-SHA256"
    end

    test "OpenSSL can read certificates (RSA)" do
      pem_file =
        X509.PrivateKey.new_rsa(2048)
        |> X509.Certificate.self_signed(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc.",
          extensions: [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name(["acme.com", "www.acme.com"])
          ]
        )
        |> write_tmp_der()

      openssl_out = openssl(["x509", "-in", pem_file, "-inform", "der", "-text", "-noout"])
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: rsaEncryption"
      assert openssl_out =~ "Signature Algorithm: sha256WithRSAEncryption"
      assert openssl_out =~ "DNS:acme.com, DNS:www.acme.com"
    end

    test "OpenSSL can read certificates (ECDSA)" do
      pem_file =
        X509.PrivateKey.new_ec(:secp256r1)
        |> X509.Certificate.self_signed(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc.",
          extensions: [
            subject_alt_name:
              X509.Certificate.Extension.subject_alt_name(["acme.com", "www.acme.com"])
          ]
        )
        |> write_tmp_der()

      openssl_out = openssl(["x509", "-in", pem_file, "-inform", "der", "-text", "-noout"])
      assert openssl_out =~ "Subject: C=US, ST=NT, L=Springfield, O=ACME Inc."
      assert openssl_out =~ "Public Key Algorithm: id-ecPublicKey"
      assert openssl_out =~ "Signature Algorithm: ecdsa-with-SHA256"
      assert openssl_out =~ "DNS:acme.com, DNS:www.acme.com"
    end
  end

  defp openssl(args) do
    openssl = System.get_env("OPENSSL_PATH") || "openssl"

    {output, 0} = System.cmd(openssl, List.wrap(args), stderr_to_stdout: true)
    output
  end

  defp write_tmp_pem(record) do
    tmp_file =
      System.tmp_dir!()
      |> Path.join("openssl_test.pem")

    File.write!(tmp_file, X509.to_pem(record))

    tmp_file
  end

  defp write_tmp_der(record) do
    tmp_file =
      System.tmp_dir!()
      |> Path.join("openssl_test.der")

    File.write!(tmp_file, X509.to_der(record))

    tmp_file
  end
end
