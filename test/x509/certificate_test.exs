defmodule X509.CertificateTest do
  use ExUnit.Case
  import X509.ASN1

  doctest X509.Certificate

  setup_all do
    [
      rsa_key: X509.PrivateKey.new_rsa(512),
      ec_key: X509.PrivateKey.new_ec(:secp256r1),
      selfsigned_rsa:
        "test/data/selfsigned_rsa.pem"
        |> File.read!()
        |> X509.Certificate.from_pem!(),
      selfsigned_rsa_key:
        "test/data/rsa.pem"
        |> File.read!()
        |> X509.PrivateKey.from_pem!(),
      selfsigned_ecdsa:
        "test/data/selfsigned_prime256v1.pem"
        |> File.read!()
        |> X509.Certificate.from_pem!(),
      selfsigned_ecdsa_key:
        "test/data/prime256v1.pem"
        |> File.read!()
        |> X509.PrivateKey.from_pem!()
    ]
  end

  describe "RSA" do
    test :new, context do
      cert =
        context.rsa_key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
          context.selfsigned_rsa,
          context.selfsigned_rsa_key
        )

      assert match?(otp_certificate(), cert)
      refute :public_key.pkix_is_self_signed(cert)
      assert :public_key.pkix_is_issuer(cert, context.selfsigned_rsa)
      assert {:ok, _} = :public_key.pkix_path_validation(context.selfsigned_rsa, [cert], [])

      assert cert
             |> X509.Certificate.to_der()
             |> :public_key.pkix_verify(X509.PublicKey.derive(context.selfsigned_rsa_key))
    end

    test "intermediate", context do
      root_key = X509.PrivateKey.new_rsa(512)

      root =
        root_key
        |> X509.Certificate.self_signed(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Intermediate CA",
          template: :root_ca
        )

      intermediata_key = X509.PrivateKey.new_rsa(512)

      intermediate =
        intermediata_key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Intermediate CA",
          root,
          root_key,
          template: :ca
        )

      cert =
        context.rsa_key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
          intermediate,
          intermediata_key
        )

      assert {:ok, _} = :public_key.pkix_path_validation(root, [intermediate, cert], [])
    end

    test :self_signed, context do
      cert =
        context.rsa_key
        |> X509.Certificate.self_signed("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert match?(otp_certificate(), cert)
      assert :public_key.pkix_is_self_signed(cert)

      assert cert
             |> X509.Certificate.to_der()
             |> :public_key.pkix_verify(X509.PublicKey.derive(context.rsa_key))
    end

    test "RFC example" do
      assert {:ok, cert1} =
               "test/data/rfc5280_cert1.cer"
               |> File.read!()
               |> X509.Certificate.from_der()

      assert {:BasicConstraints, true, :asn1_NOVALUE} =
               cert1
               |> X509.Certificate.extension(:basic_constraints)
               |> extension(:extnValue)

      assert {:ok, cert2} =
               "test/data/rfc5280_cert2.cer"
               |> File.read!()
               |> X509.Certificate.from_der()

      assert [:digitalSignature, :nonRepudiation] =
               cert2
               |> X509.Certificate.extension(:key_usage)
               |> extension(:extnValue)

      assert [rfc822Name: ~c"end.entity@example.com"] =
               cert2
               |> X509.Certificate.extension(:subject_alt_name)
               |> extension(:extnValue)
    end
  end

  describe "ECDSA" do
    test :new, context do
      cert =
        context.ec_key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
          context.selfsigned_ecdsa,
          context.selfsigned_ecdsa_key
        )

      assert match?(otp_certificate(), cert)
      refute :public_key.pkix_is_self_signed(cert)
      assert :public_key.pkix_is_issuer(cert, context.selfsigned_ecdsa)
      assert {:ok, _} = :public_key.pkix_path_validation(context.selfsigned_ecdsa, [cert], [])

      assert cert
             |> X509.Certificate.to_der()
             |> :public_key.pkix_verify(X509.PublicKey.derive(context.selfsigned_ecdsa_key))
    end

    test "intermediate", context do
      root_key = X509.PrivateKey.new_ec(:secp256r1)

      root =
        root_key
        |> X509.Certificate.self_signed(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Intermediate CA",
          template: :root_ca
        )

      intermediata_key = X509.PrivateKey.new_ec(:secp256r1)

      intermediate =
        intermediata_key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Intermediate CA",
          root,
          root_key,
          template: :ca
        )

      cert =
        context.ec_key
        |> X509.PublicKey.derive()
        |> X509.Certificate.new(
          "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
          intermediate,
          intermediata_key
        )

      assert {:ok, _} = :public_key.pkix_path_validation(root, [intermediate, cert], [])
    end

    test :self_signed, context do
      cert =
        context.ec_key
        |> X509.Certificate.self_signed("/C=US/ST=NT/L=Springfield/O=ACME Inc.")

      assert match?(otp_certificate(), cert)
      assert :public_key.pkix_is_self_signed(cert)

      assert cert
             |> X509.Certificate.to_der()
             |> :public_key.pkix_verify(X509.PublicKey.derive(context.ec_key))
    end
  end

  test :version, context do
    assert :v3 == X509.Certificate.version(context.selfsigned_rsa)
  end

  test :subject, context do
    subject = X509.Certificate.subject(context.selfsigned_rsa)
    assert match?({:rdnSequence, _}, subject)
    assert X509.RDNSequence.to_string(subject) == "/C=US/ST=NT/L=Springfield/O=ACME Inc."
    assert ["ACME Inc."] == X509.Certificate.subject(context.selfsigned_rsa, "O")

    assert ["NT"] ==
             X509.Certificate.subject(context.selfsigned_rsa, oid(:"id-at-stateOrProvinceName"))
  end

  test :issuer, context do
    issuer = X509.Certificate.issuer(context.selfsigned_rsa)
    assert match?({:rdnSequence, _}, issuer)
    assert X509.RDNSequence.to_string(issuer) == "/C=US/ST=NT/L=Springfield/O=ACME Inc."
    assert ["US"] == X509.Certificate.subject(context.selfsigned_rsa, "countryName")
  end

  test :validity, context do
    assert match?(validity(), X509.Certificate.validity(context.selfsigned_rsa))
  end

  test :extension, context do
    assert {:Extension, oid(:"id-ce-subjectKeyIdentifier"), false, _} =
             X509.Certificate.extension(context.selfsigned_rsa, :subject_key_identifier)

    assert {:Extension, oid(:"id-ce-authorityKeyIdentifier"), false, _} =
             X509.Certificate.extension(context.selfsigned_rsa, :authority_key_identifier)

    assert {:Extension, oid(:"id-ce-basicConstraints"), true, {:BasicConstraints, true, 1}} =
             X509.Certificate.extension(context.selfsigned_rsa, :basic_constraints)
  end

  test :serial_number, context do
    serial = X509.Certificate.random_serial(8)

    cert =
      context.ec_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
        context.selfsigned_ecdsa,
        context.selfsigned_ecdsa_key,
        serial: serial
      )

    assert X509.Certificate.serial(cert) == serial

    cert =
      context.ec_key
      |> X509.Certificate.self_signed(
        "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
        serial: {:random, 2}
      )

    assert X509.Certificate.serial(cert) < 0x10000
  end
end
