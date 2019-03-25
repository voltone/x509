defmodule X509.PublicKey do
  @moduledoc """
  Functions for deriving, reading and writing RSA and EC public keys.
  """

  @typedoc "RSA or EC public key"
  @type t :: :e509_public_key.public_key()

  @typedoc "SubjectPublicKeyInfo container"
  @type spki :: :e509_public_key.spki()

  @doc """
  Derives the public key from the given RSA or EC private key.
  """
  @spec derive(X509.PrivateKey.t()) :: t()
  defdelegate derive(private_key), to: :e509_public_key

  @doc """
  Wraps a public key in a SubjectPublicKeyInfo (or similar) container.

  The following container types are supported:

    * `:SubjectPublicKeyInfo` - standard X.509 structure for storing public
      keys (default)
    * `:OTPSubjectPublicKeyInfo` - Erlang/OTP record variant of
      `:SubjectPublicKeyInfo`, for use in the `:OTPCertificate` record
    * `:CertificationRequestInfo_subjectPKInfo` - for use in a PKCS#10
      CertificationRequest (CSR)
  """
  @spec wrap(t()) :: spki()
  defdelegate wrap(public_key), to: :e509_public_key

  @spec wrap(t(), atom()) :: spki()
  defdelegate wrap(public_key, wrapper), to: :e509_public_key

  @doc """
  Extracts a public key from a SubjectPublicKeyInfo style container.

  Supports the same container structures as `wrap/2`.
  """
  @spec unwrap(spki()) :: t()
  defdelegate unwrap(spki), to: :e509_public_key

  @doc """
  Converts a public key to DER (binary) format.

  ## Options:

    * `:wrap` - Wrap the private key in a SubjectPublicKeyInfo container
      (default: `true`)
  """
  @spec to_der(t(), Keyword.t()) :: binary()
  defdelegate to_der(public_key), to: :e509_public_key
  defdelegate to_der(public_key, opts), to: :e509_public_key

  @doc """
  Converts a public key to PEM format.

  ## Options:

    * `:wrap` - Wrap the private key in a SubjectPublicKeyInfo container; for
      RSA public keys this defaults to `true`, but for EC public keys this
      option is ignored and the key is always exported in SubjectPublicKeyInfo
      format
  """
  @spec to_pem(t(), Keyword.t()) :: String.t()
  defdelegate to_pem(public_key), to: :e509_public_key
  defdelegate to_pem(public_key, opts), to: :e509_public_key

  @doc """
  Attempts to parse a public key in DER (binary) format. Raises in case of failure.

  Unwraps a SubjectPublicKeyInfo style container, if present.
  """
  # @doc since: "0.3.0"
  @spec from_der!(binary()) :: t() | no_return()
  def from_der!(der) do
    {:ok, result} = from_der(der)
    result
  end

  @doc """
  Attempts to parse a public key in DER (binary) format.

  Unwraps a SubjectPublicKeyInfo style container, if present.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a public key
  """
  @spec from_der(binary()) :: {:ok, t()} | {:error, :malformed}
  defdelegate from_der(der), to: :e509_public_key

  @doc """
  Attempts to parse a public key in PEM format. Raises in case of failure.

  Expects the input string to include exactly one PEM entry, which must be of
  type "PUBLIC KEY" or "RSA PUBLIC KEY". Unwraps a SubjectPublicKeyInfo style
  container, if present.
  """
  # @doc since: "0.3.0"
  @spec from_pem!(String.t()) :: t() | no_return()
  def from_pem!(pem) do
    {:ok, result} = from_pem(pem)
    result
  end

  @doc """
  Attempts to parse a public key in PEM format.

  Expects the input string to include exactly one PEM entry, which must be of
  type "PUBLIC KEY" or "RSA PUBLIC KEY". Unwraps a SubjectPublicKeyInfo
  style container, if present. Returns an `:ok` tuple in case of success, or
  an `:error` tuple in case of failure. Possible error reasons are:

    * `:not_found` - no PEM entry of a supported PRIVATE KEY type was found
    * `:malformed` - the entry could not be decoded as a public key
  """
  @spec from_pem(String.t()) :: {:ok, t()} | {:error, :malformed | :not_found}
  defdelegate from_pem(pem), to: :e509_public_key
end
