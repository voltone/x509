defmodule X509.PrivateKeyTest do
  use ExUnit.Case
  import X509.TestHelper
  import X509.{ASN1, PrivateKey}

  doctest X509.PrivateKey

  setup_all do
    [rsa_key: new_rsa(512), ec_key: new_ec(:secp256r1)]
  end

  describe "RSA" do
    test "new" do
      assert match?(rsa_private_key(), new_rsa(512))
      assert match?(rsa_private_key(), new_rsa(2048, exponent: 17))

      assert_raise(FunctionClauseError, fn -> new_rsa(192) end)
    end

    test "wrap and unwrap", context do
      assert match?(private_key_info(), wrap(context.rsa_key))
      assert context.rsa_key == context.rsa_key |> wrap() |> unwrap()
    end

    test "PEM decode and encode", context do
      pem = File.read!("test/data/rsa.pem")
      assert match?({:ok, rsa_private_key()}, from_pem(pem))

      assert context.rsa_key == context.rsa_key |> to_pem() |> from_pem!()

      pem_des3 = File.read!("test/data/rsa_des3.pem")
      assert match?({:ok, rsa_private_key()}, from_pem(pem_des3, password: "secret"))

      pem_aes = File.read!("test/data/rsa_aes.pem")
      assert match?({:ok, rsa_private_key()}, from_pem(pem_aes, password: "secret"))
    end

    test "PKCS8 PEM decode and encode", context do
      pem = File.read!("test/data/rsa_pkcs8.pem")
      assert match?({:ok, rsa_private_key()}, from_pem(pem))

      # pem_enc = File.read!("test/data/rsa_pkcs8_enc.pem")
      # assert match?(rsa_private_key(), from_pem(pem_enc, password: "secret"))

      if version(:public_key) >= [1, 6] do
        assert context.rsa_key == context.rsa_key |> to_pem(wrap: true) |> from_pem!()
      end
    end

    test "DER decode and encode" do
      der = File.read!("test/data/rsa.der")
      assert match?(rsa_private_key(), from_der!(der))
      assert der == der |> from_der!() |> to_der()
    end

    test "PKCS8 DER decode and encode" do
      der = File.read!("test/data/rsa_pkcs8.der")
      assert match?(rsa_private_key(), from_der!(der))
      assert der == der |> from_der!() |> to_der(wrap: true)
    end
  end

  describe "EC" do
    test "new" do
      assert match?(ec_private_key(), new_ec(:secp256r1))
      assert match?(ec_private_key(), new_ec(oid(:secp256r1)))
    end

    test "wrap and unwrap", context do
      assert match?(private_key_info(), wrap(context.ec_key))
      assert context.ec_key == context.ec_key |> wrap() |> unwrap()
    end

    test "PEM decode and encode", context do
      pem = File.read!("test/data/prime256v1.pem")
      assert match?({:ok, ec_private_key()}, from_pem(pem))

      assert context.ec_key == context.ec_key |> to_pem() |> from_pem!()

      pem_des3 = File.read!("test/data/prime256v1_des3.pem")
      assert match?({:ok, ec_private_key()}, from_pem(pem_des3, password: "secret"))

      pem_aes = File.read!("test/data/prime256v1_aes.pem")
      assert match?({:ok, ec_private_key()}, from_pem(pem_aes, password: "secret"))
    end

    test "PKCS8 PEM decode and encode", context do
      pem = File.read!("test/data/prime256v1_pkcs8.pem")
      assert match?({:ok, ec_private_key()}, from_pem(pem))

      if version(:public_key) >= [1, 6] do
        # PEM encoding of PKCS8 PrivateKeyInfo requires OTP 21 or later
        assert context.ec_key == context.ec_key |> to_pem(wrap: true) |> from_pem!()
      end
    end

    test "DER decode and encode" do
      der = File.read!("test/data/prime256v1.der")
      assert match?(ec_private_key(), from_der!(der))
      assert der == der |> from_der!() |> to_der()
    end

    test "PKCS8 DER decode and encode" do
      der = File.read!("test/data/prime256v1_pkcs8.der")
      assert match?(ec_private_key(), from_der!(der))
      assert der == der |> from_der!() |> to_der(wrap: true)
    end
  end
end
