defmodule X509.PrivateKeyTest do
  use ExUnit.Case
  import X509.{ASN1, PrivateKey}

  doctest X509.PrivateKey

  @otp_release :erlang.system_info(:otp_release) |> List.to_integer()

  setup_all do
    [rsa_key: new(:rsa, 512), ec_key: new(:ec, :secp256k1)]
  end

  describe "RSA" do
    test "new" do
      assert match?(rsa_private_key(), new(:rsa, 512))
      assert match?(rsa_private_key(), new(:rsa, 2048, exponent: 17))

      assert_raise(FunctionClauseError, fn -> new(:rsa, 192) end)
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
      assert match?(ec_private_key(), new(:ec, :secp256k1))
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
