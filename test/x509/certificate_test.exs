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

      assert cert
             |> X509.Certificate.to_der()
             |> :public_key.pkix_verify(X509.PublicKey.derive(context.selfsigned_rsa_key))
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

      assert cert
             |> X509.Certificate.to_der()
             |> :public_key.pkix_verify(X509.PublicKey.derive(context.selfsigned_ecdsa_key))
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

  test :serial_number, context do
    serial = X509.Certificate.random_serial(8)

    cert =
      context.ec_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
        "/C=US/ST=NT/L=Springfield/O=ACME Inc./CN=Example",
        context.selfsigned_ecdsa,
        context.selfsigned_ecdsa_key,
        template: X509.Certificate.Template.new(:server, serial: serial)
      )

    assert X509.Certificate.serial(cert) == serial
  end
end
