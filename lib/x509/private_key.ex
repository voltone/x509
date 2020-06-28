defmodule X509.PrivateKey do
  import X509.ASN1

  @moduledoc """
  Functions for generating, reading and writing RSA and EC private keys.

  Note that this module uses Erlang/OTP's `:public_key` application, which
  does not support all curve names returned by the `:crypto.ec_curves/0`
  function. In particular, the NIST Prime curves must be selected by their
  SECG id, e.g. NIST P-256 is `:secp256r1` rather than `:prime256v1`. Please
  refer to [RFC4492 appendix A](https://tools.ietf.org/search/rfc4492#appendix-A)
  for a mapping table.

  ## Example use with `:public_key`

  ### Encryption and decryption

      iex> private_key = X509.PrivateKey.new_rsa(4096)
      iex> public_key = X509.PublicKey.derive(private_key)
      iex> plaintext = "Hello, world!"
      iex> ciphertext = :public_key.encrypt_public(plaintext, public_key)
      iex> :public_key.decrypt_private(ciphertext, private_key)
      "Hello, world!"

  Note that in practice it is not a good idea to directly encrypt a message
  with asymmetrical cryptography. The examples above are deliberate
  over-simpliciations intended to highlight the `:public_key` API calls.

  ### Signing and signature verification

      iex> private_key = X509.PrivateKey.new_ec(:secp256r1)
      iex> public_key = X509.PublicKey.derive(private_key)
      iex> message = "Hello, world!"
      iex> signature = :public_key.sign(message, :sha256, private_key)
      iex> :public_key.verify(message, :sha256, signature, public_key)
      true

  ### Key exchange

      iex> private_key1 = X509.PrivateKey.new_ec(:x25519)
      iex> {public_key1, _} = X509.PublicKey.derive(private_key1)
      iex> private_key2 = X509.PrivateKey.new_ec(:x25519)
      iex> {public_key2, _} = X509.PublicKey.derive(private_key2)
      iex> shared_secret1 = :public_key.compute_key(public_key2, private_key1)
      iex> shared_secret2 = :public_key.compute_key(public_key1, private_key2)
      iex> shared_secret1 == shared_secret2
      true

  Since `:public_key.compute_key/2.3` takes an EC point as its first parameter,
  we extract the point from the return value of `X509.PublicKey.derive/1` using
  pattern matching.
  """

  @typedoc "RSA or EC private key"
  @type t :: :public_key.rsa_private_key() | :public_key.ec_private_key()

  @private_key_records [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]
  @default_e 65537

  @doc """
  Generates a new RSA private key. To derive the public key, use
  `X509.PublicKey.derive/1`.

  The key length in bits must be specified as an integer (minimum 256 bits).
  The default exponent of #{@default_e} can be overridden using the `:exponent`
  option. Warning: the custom exponent value is not checked for safety!

  """
  @spec new_rsa(non_neg_integer(), Keyword.t()) :: :public_key.rsa_private_key()
  def new_rsa(keysize, opts \\ []) when is_integer(keysize) and keysize >= 256 do
    e = Keyword.get(opts, :exponent, @default_e)
    :public_key.generate_key({:rsa, keysize, e})
  end

  @doc """
  Generates a new EC private key. To derive the public key, use
  `X509.PublicKey.derive/1`.

  The curve can be specified as an atom or an OID tuple.
  """
  @spec new_ec(:crypto.ec_named_curve() | :public_key.oid()) :: :public_key.ec_private_key()
  def new_ec(curve) when is_atom(curve) or is_tuple(curve) do
    :public_key.generate_key({:namedCurve, curve})
  end

  @doc """
  Deterministically generates an EC private key from a (pseudo)random seed. To
  derive the public key, use `X509.PublicKey.derive/1`.

  The first parameter must specify a named curve. The curve can be specified
  as an atom or an OID tuple.

  The second parameter is the seed value, which is typically the output of a
  secure KDF:

    * If the selected curve is defined over a prime field or characteristic 2
      field the procedure in NIST FIPS-186-4 B.4.1 "Key Pair Generation Using
      Extra Random Bits" is used. The `returned_bits` argument must be a binary
      that is at least 64 bits (8 bytes) longer than the length of the order of
      the curve.

    * For the `:x22519` and `:x448` curves, the `returned_bits` argument must
      match the bit-size of the curve (i.e. 256 or 448 bits). The value is
      clamped according to the curve requirements and wrapped into an EC
      private key record.
  """
  @spec new_ec(:crypto.ec_named_curve() | :public_key.oid(), binary()) ::
          :public_key.ec_private_key()
  def new_ec(curve, returned_bits) when is_tuple(curve) do
    # FIXME: avoid calls to undocumented functions in :public_key app
    new_ec(:pubkey_cert_records.namedCurves(curve), returned_bits)
  end

  def new_ec(:x25519 = curve, <<returned_bits::little-size(256)>>) do
    import Bitwise

    clamped =
      returned_bits
      |> band(~~~7)
      |> band(~~~(128 <<< (8 * 31)))
      |> bor(64 <<< (8 * 31))

    priv = <<clamped::little-size(256)>>
    pub = :crypto.compute_key(:ecdh, <<9::integer-little-size(256)>>, priv, curve)
    ec_private_key(version: 1, privateKey: priv, parameters: {:namedCurve, curve}, publicKey: pub)
  end

  def new_ec(:x448 = curve, <<returned_bits::little-size(448)>>) do
    import Bitwise

    clamped =
      returned_bits
      |> band(~~~3)
      |> bor(128 <<< (8 * 55))

    priv = <<clamped::little-size(448)>>
    pub = :crypto.compute_key(:ecdh, <<5::integer-little-size(448)>>, priv, curve)
    ec_private_key(version: 1, privateKey: priv, parameters: {:namedCurve, curve}, publicKey: pub)
  end

  def new_ec(curve, returned_bits) when is_atom(curve) and is_binary(returned_bits) do
    {_field, _curve, _g, n, _h} = :crypto.ec_curve(curve)

    # NIST FIPS-186-4 B.4.1
    if byte_size(returned_bits) < byte_size(n) + 8,
      do: raise(ArgumentError, "`returned_bits` must be at least #{byte_size(n) + 8} bytes")

    d =
      returned_bits
      |> :binary.decode_unsigned()
      |> rem(:binary.decode_unsigned(n) - 1)
      |> Kernel.+(1)

    {pub, priv} = :crypto.generate_key(:ecdh, curve, d)
    ec_private_key(version: 1, privateKey: priv, parameters: {:namedCurve, curve}, publicKey: pub)
  end

  @doc """
  Wraps a private key in a PKCS#8 PrivateKeyInfo container.
  """
  @spec wrap(t()) :: X509.ASN.record(:private_key_info)
  def wrap(rsa_private_key() = private_key) do
    private_key_info(
      version: :v1,
      privateKeyAlgorithm:
        private_key_info_private_key_algorithm(
          algorithm: oid(:rsaEncryption),
          parameters: null()
        ),
      privateKey: to_der(private_key)
    )
  end

  def wrap(ec_private_key(parameters: parameters) = private_key) do
    private_key_info(
      version: :v1,
      privateKeyAlgorithm:
        private_key_info_private_key_algorithm(
          algorithm: oid(:"id-ecPublicKey"),
          parameters: open_type(:EcpkParameters, parameters)
        ),
      privateKey: to_der(ec_private_key(private_key, parameters: :asn1_NOVALUE))
    )
  end

  @doc """
  Extracts a private key from a PKCS#8 PrivateKeyInfo container.
  """
  @spec wrap(X509.ASN.record(:private_key_info)) :: t()
  def unwrap(
        private_key_info(version: :v1, privateKeyAlgorithm: algorithm, privateKey: private_key)
      ) do
    case algorithm do
      private_key_info_private_key_algorithm(algorithm: oid(:rsaEncryption)) ->
        :public_key.der_decode(:RSAPrivateKey, private_key)

      private_key_info_private_key_algorithm(
        algorithm: oid(:"id-ecPublicKey"),
        parameters: {:asn1_OPENTYPE, parameters_der}
      ) ->
        :public_key.der_decode(:ECPrivateKey, private_key)
        |> ec_private_key(parameters: :public_key.der_decode(:EcpkParameters, parameters_der))
    end
  end

  @doc """
  Converts a private key to DER (binary) format.

  ## Options:

    * `:wrap` - Wrap the private key in a PKCS#8 PrivateKeyInfo container
      (default: `false`)
  """
  @spec to_der(t(), Keyword.t()) :: binary()
  def to_der(private_key, opts \\ []) do
    if Keyword.get(opts, :wrap, false) do
      private_key
      |> wrap()
      |> der_encode()
    else
      private_key
      |> der_encode()
    end
  end

  @doc """
  Converts a private key to PEM format.

  ## Options:

    * `:wrap` - Wrap the private key in a PKCS#8 PrivateKeyInfo container
      (default: `false`)
    * `:password` - If a password is specified, the private key is encrypted
      using 3DES; to password will be required to decode the PEM entry
  """
  @spec to_pem(t(), Keyword.t()) :: String.t()
  def to_pem(private_key, opts \\ []) do
    if Keyword.get(opts, :wrap, false) do
      private_key
      |> wrap()
    else
      private_key
    end
    |> pem_entry_encode(Keyword.get(opts, :password))
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  @doc """
  Attempts to parse a private key in DER (binary) format. Raises in case of failure.

  Unwraps the PKCS#8 PrivateKeyInfo container, if present.
  """
  # @doc since: "0.3.0"
  @spec from_der!(binary()) :: t() | no_return()
  def from_der!(der) do
    {:ok, result} = from_der(der)
    result
  end

  @doc """
  Attempts to parse a private key in DER (binary) format.

  Unwraps the PKCS#8 PrivateKeyInfo container, if present.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a private key
  """
  @spec from_der(binary()) :: {:ok, t()} | {:error, :malformed}
  def from_der(der) do
    case X509.try_der_decode(der, @private_key_records) do
      nil ->
        {:error, :malformed}

      private_key_info() = pki ->
        # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
        {:ok, unwrap(pki)}

      result ->
        {:ok, result}
    end
  end

  @doc """
  Attempts to parse a private key in PEM format. Raises in case of failure.

  Processes the first PEM entry of type PRIVATE KEY, RSA PRIVATE KEY or EC
  PRIVATE KEY found in the input. Unwraps the PKCS#8 PrivateKeyInfo container,
  if present.

  ## Options:

    * `:password` - the password used to decrypt an encrypted private key; may
      be specified as a string or a charlist
  """
  # @doc since: "0.3.0"
  @spec from_pem!(String.t(), Keyword.t()) :: t() | no_return()
  def from_pem!(pem, opts \\ []) do
    {:ok, result} = from_pem(pem, opts)
    result
  end

  @doc """
  Attempts to parse a private key in PEM format.

  Processes the first PEM entry of type PRIVATE KEY, RSA PRIVATE KEY or EC
  PRIVATE KEY found in the input. Unwraps the PKCS#8 PrivateKeyInfo container,
  if present. Returns an `:ok` tuple in case of success, or an `:error` tuple
  in case of failure. Possible error reasons are:

    * `:not_found` - no PEM entry of a supported PRIVATE KEY type was found
    * `:malformed` - the entry could not be decoded as a private key

  ## Options:

    * `:password` - the password used to decrypt an encrypted private key; may
      be specified as a string or a charlist
  """
  @spec from_pem(String.t(), Keyword.t()) :: {:ok, t()} | {:error, :malformed | :not_found}
  def from_pem(pem, opts \\ []) do
    password =
      opts
      |> Keyword.get(:password, '')
      |> to_charlist()

    pem
    |> :public_key.pem_decode()
    |> Enum.find(&(elem(&1, 0) in @private_key_records))
    |> case do
      nil ->
        {:error, :not_found}

      entry ->
        try do
          :public_key.pem_entry_decode(entry, password)
        rescue
          MatchError -> {:error, :malformed}
        else
          # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
          private_key_info() = pki ->
            {:ok, unwrap(pki)}

          private_key ->
            {:ok, private_key}
        end
    end
  end

  #
  # Helpers
  #

  defp der_encode(rsa_private_key() = rsa_private_key) do
    :public_key.der_encode(:RSAPrivateKey, rsa_private_key)
  end

  defp der_encode(ec_private_key() = ec_private_key) do
    :public_key.der_encode(:ECPrivateKey, ec_private_key)
  end

  defp der_encode(private_key_info() = private_key_info) do
    :public_key.der_encode(:PrivateKeyInfo, private_key_info)
  end

  defp pem_entry_encode(rsa_private_key() = rsa_private_key, nil) do
    :public_key.pem_entry_encode(:RSAPrivateKey, rsa_private_key)
  end

  defp pem_entry_encode(ec_private_key() = ec_private_key, nil) do
    :public_key.pem_entry_encode(:ECPrivateKey, ec_private_key)
  end

  defp pem_entry_encode(private_key_info() = private_key_info, nil) do
    :public_key.pem_entry_encode(:PrivateKeyInfo, private_key_info)
  end

  defp pem_entry_encode(private_key, password) when is_binary(password) do
    pem_entry_encode(private_key, to_charlist(password))
  end

  defp pem_entry_encode(rsa_private_key() = rsa_private_key, password) do
    :public_key.pem_entry_encode(:RSAPrivateKey, rsa_private_key, {cipher_info(), password})
  end

  defp pem_entry_encode(ec_private_key() = ec_private_key, password) do
    :public_key.pem_entry_encode(:ECPrivateKey, ec_private_key, {cipher_info(), password})
  end

  defp pem_entry_encode(private_key_info() = private_key_info, password) do
    :public_key.pem_entry_encode(:PrivateKeyInfo, private_key_info, {cipher_info(), password})
  end

  defp cipher_info() do
    {'DES-EDE3-CBC', :crypto.strong_rand_bytes(8)}
  end
end
