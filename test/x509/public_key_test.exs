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
    end

    test "mul" do
      # This is actually the P-256 base point; would be better to find test
      # vectors with a different base point...
      p =
        point(
          :secp256r1,
          "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
          "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
        )

      assert X509.PublicKey.mul(p, 10) ==
               point(
                 :secp256r1,
                 "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F",
                 "878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773"
               )

      assert X509.PublicKey.mul(p, 112_233_445_566_778_899_112_233_445_566_778_899) ==
               point(
                 :secp256r1,
                 "1B7E046A076CC25E6D7FA5003F6729F665CC3241B5ADAB12B498CD32F2803264",
                 "BFEA79BE2B666B073DB69A2A241ADAB0738FE9D2DD28B5604EB8C8CF097C457B"
               )
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

    test "PEM decode and encode", context do
      pem = File.read!("test/data/prime256v1_pub.pem")
      assert match?({:ok, {ec_point(), _}}, from_pem(pem))

      assert context.ec_pub == context.ec_pub |> to_pem() |> from_pem!()
      # EC public key encoding always wraps, ignoring the `wrap: false` option,
      # so this test is effectively the same as the previous one
      assert context.ec_pub == context.ec_pub |> to_pem(wrap: false) |> from_pem!()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/prime256v1_pub.der")
      assert match?({:ok, {ec_point(), _}}, from_der(der))
      assert der == der |> from_der!() |> to_der()
    end
  end

  defp point(curve, x, y) do
    {{:ECPoint, <<4, Base.decode16!(x)::binary, Base.decode16!(y)::binary>>},
     {:namedCurve, curve}}
  end
end
