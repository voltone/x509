defmodule X509.PublicKeyTest do
  use ExUnit.Case
  import X509.{ASN1, PublicKey}

  doctest X509.PublicKey

  setup_all do
    rsa = X509.PrivateKey.new_rsa(512)
    ec = X509.PrivateKey.new_ec(:secp256r1)

    [
      rsa_key: rsa,
      rsa_pub: derive(rsa),
      ec_key: ec,
      ec_pub: derive(ec)
    ]
  end

  describe "RSA" do
    test "derive", context do
      assert match?(rsa_public_key(), derive(context.rsa_key))
      signature = :public_key.sign("message", :sha256, context.rsa_key)
      assert :public_key.verify("message", :sha256, signature, derive(context.rsa_key))
    end

    test "wrap and unwrap", context do
      assert match?(subject_public_key_info(), wrap(context.rsa_pub))
      assert context.rsa_pub == context.rsa_pub |> wrap() |> unwrap()

      assert match?(subject_public_key_info(), wrap(context.rsa_pub, :SubjectPublicKeyInfo))
      assert context.rsa_pub == context.rsa_pub |> wrap(:SubjectPublicKeyInfo) |> unwrap()

      assert match?(
               otp_subject_public_key_info(),
               wrap(context.rsa_pub, :OTPSubjectPublicKeyInfo)
             )

      assert context.rsa_pub == context.rsa_pub |> wrap(:OTPSubjectPublicKeyInfo) |> unwrap()

      assert match?(
               certification_request_subject_pk_info(),
               wrap(context.rsa_pub, :CertificationRequestInfo_subjectPKInfo)
             )

      assert context.rsa_pub ==
               context.rsa_pub |> wrap(:CertificationRequestInfo_subjectPKInfo) |> unwrap()
    end

    test "PEM decode and encode", context do
      pem = File.read!("test/data/rsa_pub.pem")
      assert match?({:ok, rsa_public_key()}, from_pem(pem))

      assert context.rsa_pub == context.rsa_pub |> to_pem() |> from_pem!()
      assert context.rsa_pub == context.rsa_pub |> to_pem(wrap: false) |> from_pem!()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/rsa_pub.der")
      assert match?({:ok, rsa_public_key()}, from_der(der))
      assert der == der |> from_der!() |> to_der()
    end
  end

  describe "EC" do
    test "derive", context do
      assert match?({ec_point(), _}, derive(context.ec_key))
      signature = :public_key.sign("message", :sha256, context.ec_key)
      assert :public_key.verify("message", :sha256, signature, derive(context.ec_key))

      ed25519 = X509.PrivateKey.new_ec(:ed25519)
      signature = :public_key.sign("message", :sha256, ed25519)
      assert :public_key.verify("message", :sha256, signature, derive(ed25519))

      ed448 = X509.PrivateKey.new_ec(:ed448)
      signature = :public_key.sign("message", :sha256, ed448)
      assert :public_key.verify("message", :sha256, signature, derive(ed448))
    end

    test "wrap and unwrap", context do
      assert match?(subject_public_key_info(), wrap(context.ec_pub))
      assert context.ec_pub == context.ec_pub |> wrap() |> unwrap()

      assert match?(subject_public_key_info(), wrap(context.ec_pub, :SubjectPublicKeyInfo))
      assert context.ec_pub == context.ec_pub |> wrap(:SubjectPublicKeyInfo) |> unwrap()

      assert match?(
               otp_subject_public_key_info(),
               wrap(context.ec_pub, :OTPSubjectPublicKeyInfo)
             )

      assert context.ec_pub == context.ec_pub |> wrap(:OTPSubjectPublicKeyInfo) |> unwrap()

      assert match?(
               certification_request_subject_pk_info(),
               wrap(context.ec_pub, :CertificationRequestInfo_subjectPKInfo)
             )

      assert context.ec_pub ==
               context.ec_pub |> wrap(:CertificationRequestInfo_subjectPKInfo) |> unwrap()
    end

    for curve <- ["prime256v1", "ed25519", "ed448"] do
      @curve curve

      test "PEM decode and encode: #{@curve}", context do
        pem = File.read!("test/data/#{@curve}_pub.pem")
        assert match?({:ok, {ec_point(), _}}, from_pem(pem))

        assert context.ec_pub == context.ec_pub |> to_pem() |> from_pem!()
        # EC public key encoding always wraps, ignoring the `wrap: false` option,
        # so this test is effectively the same as the previous one
        assert context.ec_pub == context.ec_pub |> to_pem(wrap: false) |> from_pem!()
      end

      test "DER decode and encode: #{@curve}" do
        der = File.read!("test/data/#{@curve}_pub.der")
        assert match?({:ok, {ec_point(), _}}, from_der(der))
        assert der == der |> from_der!() |> to_der()
      end
    end
  end
end
