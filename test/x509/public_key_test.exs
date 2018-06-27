defmodule X509.PublicKeyTest do
  use ExUnit.Case
  import X509.{ASN1, PublicKey}

  doctest X509.PublicKey

  @otp_release :erlang.system_info(:otp_release) |> List.to_integer()

  setup_all do
    rsa =
      if @otp_release >= 20 do
        X509.PrivateKey.new(:rsa, 512)
      else
        {:RSAPrivateKey, :"two-prime",
         84_597_038_066_613_188_910_836_752_703_058_693_414_615_826_046_559_107_650_341_123_593_624_059_067_749,
         3,
         56_398_025_377_742_125_940_557_835_135_372_462_276_019_832_297_885_081_489_820_111_233_922_515_518_443,
         328_741_743_163_762_543_684_392_834_690_063_215_753,
         257_335_856_567_722_871_926_563_908_050_222_574_333,
         219_161_162_109_175_029_122_928_556_460_042_143_835,
         171_557_237_711_815_247_951_042_605_366_815_049_555,
         271_299_031_718_718_009_562_995_406_017_567_663_068, :asn1_NOVALUE}
      end

    ec = X509.PrivateKey.new(:ec, oid(:secp256k1))

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
      assert match?(rsa_public_key(), from_pem(pem))

      assert context.rsa_pub == context.rsa_pub |> to_pem() |> from_pem()
      assert context.rsa_pub == context.rsa_pub |> to_pem(wrap: false) |> from_pem()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/rsa_pub.der")
      assert match?(rsa_public_key(), from_der(der))
      assert der == der |> from_der() |> to_der()
    end
  end

  describe "EC" do
    test "derive", context do
      assert match?({ec_point(), _}, derive(context.ec_key))
      signature = :public_key.sign("message", :sha256, context.ec_key)
      assert :public_key.verify("message", :sha256, signature, derive(context.ec_key))
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
      pem = File.read!("test/data/secp256k1_pub.pem")
      assert match?({ec_point(), _}, from_pem(pem))

      assert context.ec_pub == context.ec_pub |> to_pem() |> from_pem()
      # EC public key encoding always wraps, ignoring the `wrap: false` option,
      # so this test is effectively the same as the previous one
      assert context.ec_pub == context.ec_pub |> to_pem(wrap: false) |> from_pem()
    end

    test "DER decode and encode" do
      der = File.read!("test/data/secp256k1_pub.der")
      assert match?({ec_point(), _}, from_der(der))
      assert der == der |> from_der() |> to_der()
    end
  end
end
