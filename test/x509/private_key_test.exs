defmodule X509.PrivateKeyTest do
  use ExUnit.Case
  import X509.{ASN1, PrivateKey}

  doctest X509.PrivateKey

  @otp_release :erlang.system_info(:otp_release) |> List.to_integer()

  setup_all do
    if @otp_release >= 20 do
      [rsa_key: new(:rsa, 512), ec_key: new(:ec, :secp256k1)]
    else
      # OTP 19 cannot generate RSA keys
      [
        {:RSAPrivateKey, :"two-prime",
         84_597_038_066_613_188_910_836_752_703_058_693_414_615_826_046_559_107_650_341_123_593_624_059_067_749,
         3,
         56_398_025_377_742_125_940_557_835_135_372_462_276_019_832_297_885_081_489_820_111_233_922_515_518_443,
         328_741_743_163_762_543_684_392_834_690_063_215_753,
         257_335_856_567_722_871_926_563_908_050_222_574_333,
         219_161_162_109_175_029_122_928_556_460_042_143_835,
         171_557_237_711_815_247_951_042_605_366_815_049_555,
         271_299_031_718_718_009_562_995_406_017_567_663_068, :asn1_NOVALUE},
        ec_key: new(:ec, oid(:secp256k1))
      ]
    end
  end

  describe "RSA" do
    if @otp_release >= 20 do
      test "new" do
        assert match?(rsa_private_key(), new(:rsa, 512))
        assert match?(rsa_private_key(), new(:rsa, 2048, exponent: 17))

        assert_raise(FunctionClauseError, fn -> new(:rsa, 192) end)
      end
    end

    test "wrap and unwrap", context do
      assert match?(private_key_info(), wrap(context.rsa_key))
      assert context.rsa_key == context.rsa_key |> wrap() |> unwrap()
    end

    test "PEM decode and encode", context do
      pem = File.read!("test/data/rsa.pem")
      assert match?(rsa_private_key(), from_pem(pem))

      assert context.rsa_key == context.rsa_key |> to_pem() |> from_pem()

      pem_des3 = File.read!("test/data/rsa_des3.pem")
      assert match?(rsa_private_key(), from_pem(pem_des3, password: "secret"))

      pem_aes = File.read!("test/data/rsa_aes.pem")
      assert match?(rsa_private_key(), from_pem(pem_aes, password: "secret"))
    end

    test "PKCS8 PEM decode and encode", context do
      pem = File.read!("test/data/rsa_pkcs8.pem")
      assert match?(rsa_private_key(), from_pem(pem))

      # pem_enc = File.read!("test/data/rsa_pkcs8_enc.pem")
      # assert match?(rsa_private_key(), from_pem(pem_enc, password: "secret"))

      if @otp_release >= 21 do
        # PEM encoding of PKCS8 PrivateKeyInfo requires OTP 21 or later
        assert context.rsa_key == context.rsa_key |> to_pem(wrap: true) |> from_pem()
      end
    end

    test "DER decode and encode" do
      der = File.read!("test/data/rsa.der")
      assert match?(rsa_private_key(), from_der(der))
      assert der == der |> from_der() |> to_der()
    end

    test "PKCS8 DER decode and encode" do
      der = File.read!("test/data/rsa_pkcs8.der")
      assert match?(rsa_private_key(), from_der(der))
      assert der == der |> from_der() |> to_der(wrap: true)
    end
  end

  describe "EC" do
    test "new" do
      if @otp_release >= 20 do
        assert match?(ec_private_key(), new(:ec, :secp256k1))
      end

      assert match?(ec_private_key(), new(:ec, oid(:secp256k1)))

      assert_raise(FunctionClauseError, fn -> new(:ec, :no_such_curve) end)
    end

    test "wrap and unwrap", context do
      assert match?(private_key_info(), wrap(context.ec_key))
      assert context.ec_key == context.ec_key |> wrap() |> unwrap()
    end

    test "PEM decode and encode", context do
      pem = File.read!("test/data/secp256k1.pem")
      assert match?(ec_private_key(), from_pem(pem))

      assert context.ec_key == context.ec_key |> to_pem() |> from_pem()

      pem_des3 = File.read!("test/data/secp256k1_des3.pem")
      assert match?(ec_private_key(), from_pem(pem_des3, password: "secret"))

      pem_aes = File.read!("test/data/secp256k1_aes.pem")
      assert match?(ec_private_key(), from_pem(pem_aes, password: "secret"))
    end

    test "PKCS8 PEM decode and encode", context do
      pem = File.read!("test/data/secp256k1_pkcs8.pem")
      assert match?(ec_private_key(), from_pem(pem))

      if @otp_release >= 21 do
        # PEM encoding of PKCS8 PrivateKeyInfo requires OTP 21 or later
        assert context.ec_key == context.ec_key |> to_pem(wrap: true) |> from_pem()
      end
    end

    test "DER decode and encode" do
      der = File.read!("test/data/secp256k1.der")
      assert match?(ec_private_key(), from_der(der))
      assert der == der |> from_der() |> to_der()
    end

    test "PKCS8 DER decode and encode" do
      der = File.read!("test/data/secp256k1_pkcs8.der")
      assert match?(ec_private_key(), from_der(der))
      assert der == der |> from_der() |> to_der(wrap: true)
    end
  end
end
