defmodule X509.PrivateKey do
  import X509.ASN1

  @moduledoc """
  Functions for generating, reading and writing RSA and EC private keys.
  """

  @typedoc "RSA or EC private key"
  @type t :: :public_key.rsa_private_key() | :public_key.ec_private_key()

  @default_e 65537

  @doc """
  Generates a new private RSA private key. To derive the public key, use
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
  Generates a new private EC private key. To derive the public key, use
  `X509.PublicKey.derive/1`.

  The second parameter must specify a named curve. The curve can be specified
  as an atom or an OID tuple.

  Note that this function uses Erlang/OTP's `:public_key` application, which
  does not support all curve names returned by the `:crypto.ec_curves/0`
  function. In particular, the NIST Prime curves must be selected by their
  SECG id, e.g. NIST P-256 is `:secp256r1` rather than `:prime256v1`. Please
  refer to [RFC4492 appendix A](https://tools.ietf.org/search/rfc4492#appendix-A)
  for a mapping table.
  """
  @spec new_ec(:crypto.ec_named_curve() | :public_key.oid()) :: :public_key.ec_private_key()
  def new_ec(curve) when is_atom(curve) or is_tuple(curve) do
    :public_key.generate_key({:namedCurve, curve})
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
      |> X509.to_der()
    else
      private_key
      |> X509.to_der()
    end
  end

  @doc """
  Converts a private key to PEM format.

  ## Options:

    * `:wrap` - Wrap the private key in a PKCS#8 PrivateKeyInfo container
      (default: `false`)
  """
  @spec to_pem(t(), Keyword.t()) :: String.t()
  def to_pem(private_key, opts \\ []) do
    if Keyword.get(opts, :wrap, false) do
      private_key
      |> wrap()
      |> X509.to_pem()
    else
      private_key
      |> X509.to_pem()
    end
  end

  @doc """
  Attempts to parse a private key in DER (binary) format. Raises in case of failure.

  Unwraps the PKCS#8 PrivateKeyInfo container, if present.
  """
  @doc since: "0.3.0"
  @spec from_der!(binary()) :: t() | no_return()
  def from_der!(der) do
    case X509.try_der_decode(der, [:PrivateKeyInfo, :RSAPrivateKey, :ECPrivateKey]) do
      private_key_info() = pki ->
        # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
        unwrap(pki)

      rsa_private_key() = key ->
        key

      ec_private_key() = key ->
        key
    end
  end

  @doc """
  Attempts to parse a private key in DER (binary) format.

  Unwraps the PKCS#8 PrivateKeyInfo container, if present. If the data cannot
  be parsed as a supported private key type, `nil` is returned.

  *Note*: this function will be changed to return an `:ok` / `:error` tuple in
  the near future; in existing applications, consider using `from_der!/2` to
  ease the migration.
  """
  @spec from_der(binary()) :: t() | nil
  def from_der(der) do
    case X509.try_der_decode(der, [:PrivateKeyInfo, :RSAPrivateKey, :ECPrivateKey]) do
      nil ->
        nil

      private_key_info() = pki ->
        # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
        unwrap(pki)

      result ->
        result
    end
  end

  @doc """
  Attempts to parse a private key in PEM format. Raises in case of failure.

  Expects the input string to include exactly one PEM entry, which must be of
  type "PRIVATE KEY", "RSA PRIVATE KEY" or "EC PRIVATE KEY". Unwraps the PKCS#8
  PrivateKeyInfo container, if present.

  ## Options:

    * `:password` - the password used to decrypt an encrypted private key; may
      be specified as a string or a charlist

  """
  @doc since: "0.3.0"
  @spec from_pem!(String.t(), Keyword.t()) :: t() | no_return()
  def from_pem!(pem, opts \\ []) do
    pem
    |> :public_key.pem_decode()
    |> Enum.filter(&(elem(&1, 0) in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]))
    |> case do
      [{_, _, :not_encrypted} = entry] ->
        case :public_key.pem_entry_decode(entry) do
          # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
          private_key_info() = pki ->
            unwrap(pki)

          private_key ->
            private_key
        end

      [{_, _, _encryption} = entry] ->
        password =
          opts
          |> Keyword.fetch!(:password)
          |> to_charlist()

        case :public_key.pem_entry_decode(entry, password) do
          # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
          private_key_info() = pki ->
            unwrap(pki)

          private_key ->
            private_key
        end
    end
  end

  @doc """
  Attempts to parse a private key in PEM format.

  Expects the input string to include exactly one PEM entry, which must be of
  type "PRIVATE KEY", "RSA PRIVATE KEY" or "EC PRIVATE KEY". Unwraps the PKCS#8
  PrivateKeyInfo container, if present. If the data cannot be parsed as a
  supported private key type, `nil` is returned.

  *Note*: this function will be changed to return an `:ok` / `:error` tuple in
  the near future; in existing applications, consider using `from_der!/2` to
  ease the migration.

  ## Options:

    * `:password` - the password used to decrypt an encrypted private key; may
      be specified as a string or a charlist

  """
  @spec from_pem(String.t(), Keyword.t()) :: t() | nil
  def from_pem(pem, opts \\ []) do
    pem
    |> :public_key.pem_decode()
    |> Enum.filter(&(elem(&1, 0) in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]))
    |> case do
      [{_, _, :not_encrypted} = entry] ->
        case :public_key.pem_entry_decode(entry) do
          # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
          private_key_info() = pki ->
            unwrap(pki)

          private_key ->
            private_key
        end

      [{_, _, _encryption} = entry] ->
        password =
          opts
          |> Keyword.fetch!(:password)
          |> to_charlist()

        case :public_key.pem_entry_decode(entry, password) do
          # In OTP 21, :public_key unwraps PrivateKeyInfo, but older versions do not
          private_key_info() = pki ->
            unwrap(pki)

          private_key ->
            private_key
        end

      _ ->
        nil
    end
  end
end
