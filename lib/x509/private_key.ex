defmodule X509.PrivateKey do
  @moduledoc """
  Functions for generating, reading and writing RSA and EC private keys.

  ## Example use with `:public_key`

  Encryption and decryption:

      iex> private_key = X509.PrivateKey.new_rsa(2048)
      iex> public_key = X509.PublicKey.derive(private_key)
      iex> plaintext = "Hello, world!"
      iex> ciphertext = :public_key.encrypt_public(plaintext, public_key)
      iex> :public_key.decrypt_private(ciphertext, private_key)
      "Hello, world!"

  Signing and signature verification:

      iex> private_key = X509.PrivateKey.new_ec(:secp256r1)
      iex> public_key = X509.PublicKey.derive(private_key)
      iex> message = "Hello, world!"
      iex> signature = :public_key.sign(message, :sha256, private_key)
      iex> :public_key.verify(message, :sha256, signature, public_key)
      true

  Note that in practice it is not a good idea to directly encrypt a message
  with asymmetrical cryptography, and signatures should be calculated over
  message hashes rather than raw messages. The examples above are deliberate
  over-simpliciations intended to highlight the `:crypto` API calls.
  """

  @typedoc "RSA or EC private key"
  @type t :: :e509_private_key.private_key()

  @doc """
  Generates a new private RSA private key. To derive the public key, use
  `X509.PublicKey.derive/1`.

  The key length in bits must be specified as an integer (minimum 256 bits).
  The default exponent of 65537 can be overridden using the `:exponent`
  option. Warning: the custom exponent value is not checked for safety!

  """
  @spec new_rsa(non_neg_integer(), Keyword.t()) :: :public_key.rsa_private_key()
  defdelegate new_rsa(keysize), to: :e509_private_key
  defdelegate new_rsa(keysize, opts), to: :e509_private_key

  @doc """
  Generates a new private EC private key. To derive the public key, use
  `X509.PublicKey.derive/1`.

  The curve can be specified as an atom or an OID tuple.

  Note that this function uses Erlang/OTP's `:public_key` application, which
  does not support all curve names returned by the `:crypto.ec_curves/0`
  function. In particular, the NIST Prime curves must be selected by their
  SECG id, e.g. NIST P-256 is `:secp256r1` rather than `:prime256v1`. Please
  refer to [RFC4492 appendix A](https://tools.ietf.org/search/rfc4492#appendix-A)
  for a mapping table.
  """
  @spec new_ec(:crypto.ec_named_curve() | :public_key.oid()) :: :public_key.ec_private_key()
  defdelegate new_ec(curve), to: :e509_private_key

  @doc """
  Wraps a private key in a PKCS#8 PrivateKeyInfo container.
  """
  @spec wrap(t()) :: :e509_private_key.private_key_info()
  defdelegate wrap(private_key), to: :e509_private_key

  @doc """
  Extracts a private key from a PKCS#8 PrivateKeyInfo container.
  """
  @spec unwrap(:e509_private_key.private_key_info()) :: t()
  defdelegate unwrap(private_key_info), to: :e509_private_key

  @doc """
  Converts a private key to DER (binary) format.

  ## Options:

    * `:wrap` - Wrap the private key in a PKCS#8 PrivateKeyInfo container
      (default: `false`)
  """
  @spec to_der(t(), Keyword.t()) :: binary()
  defdelegate to_der(private_key), to: :e509_private_key
  defdelegate to_der(private_key, opts), to: :e509_private_key

  @doc """
  Converts a private key to PEM format.

  ## Options:

    * `:wrap` - Wrap the private key in a PKCS#8 PrivateKeyInfo container
      (default: `false`)
  """
  @spec to_pem(t(), Keyword.t()) :: String.t()
  defdelegate to_pem(private_key), to: :e509_private_key
  defdelegate to_pem(private_key, opts), to: :e509_private_key

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
  defdelegate from_der(der), to: :e509_private_key

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
  defdelegate from_pem(pem), to: :e509_private_key
  defdelegate from_pem(pem, opts), to: :e509_private_key
end
