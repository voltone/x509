defmodule X509.PublicKey do
  import X509.ASN1

  @moduledoc """
  Functions for deriving, reading and writing RSA and EC public keys.
  """

  @typedoc "RSA or EC public key"
  @type t :: :public_key.rsa_public_key() | :public_key.ec_public_key()

  @typedoc "SubjectPublicKeyInfo container"
  @type spki ::
          X509.ASN.record(:subject_public_key_info)
          | X509.ASN.record(:otp_subject_public_key_info)
          | X509.ASN.record(:certification_request_subject_pk_info)

  @public_key_records [:RSAPublicKey, :SubjectPublicKeyInfo]

  @doc """
  Derives the public key from the given RSA or EC private key.

  The private key may be specified as an 'engine reference'. Please refer to
  documentation for Erlang/OTP's `:crypto` application for further information
  about engines. However, please note that `:crypto` may not support this API
  for all key types.
  """
  @spec derive(X509.PrivateKey.t() | :crypto.engine_key_ref()) :: t()
  def derive(%{algorithm: algorithm, engine: _} = private_key) do
    :crypto.privkey_to_pubkey(algorithm, private_key)
  end

  def derive(rsa_private_key(modulus: m, publicExponent: e)) do
    rsa_public_key(modulus: m, publicExponent: e)
  end

  def derive(ec_private_key(parameters: params, publicKey: pub)) do
    {ec_point(point: pub), params}
  end

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
  def wrap(public_key, wrapper \\ :SubjectPublicKeyInfo)

  def wrap(rsa_public_key() = public_key, :SubjectPublicKeyInfo) do
    subject_public_key_info(
      algorithm:
        algorithm_identifier(
          algorithm: oid(:rsaEncryption),
          # NULL, DER encoded
          parameters: <<5, 0>>
        ),
      subjectPublicKey: :public_key.der_encode(:RSAPublicKey, public_key)
    )
  end

  def wrap({ec_point(point: public_key), parameters}, :SubjectPublicKeyInfo) do
    subject_public_key_info(
      algorithm:
        algorithm_identifier(
          algorithm: oid(:"id-ecPublicKey"),
          parameters: :public_key.der_encode(:EcpkParameters, parameters)
        ),
      subjectPublicKey: public_key
    )
  end

  def wrap(rsa_public_key() = public_key, :OTPSubjectPublicKeyInfo) do
    otp_subject_public_key_info(
      algorithm:
        public_key_algorithm(
          algorithm: oid(:rsaEncryption),
          parameters: null()
        ),
      subjectPublicKey: public_key
    )
  end

  def wrap({ec_point() = public_key, parameters}, :OTPSubjectPublicKeyInfo) do
    otp_subject_public_key_info(
      algorithm:
        public_key_algorithm(
          algorithm: oid(:"id-ecPublicKey"),
          parameters: parameters
        ),
      subjectPublicKey: public_key
    )
  end

  def wrap(rsa_public_key() = public_key, :CertificationRequestInfo_subjectPKInfo) do
    certification_request_subject_pk_info(
      algorithm:
        certification_request_subject_pk_info_algorithm(
          algorithm: oid(:rsaEncryption),
          parameters: null()
        ),
      subjectPublicKey: :public_key.der_encode(:RSAPublicKey, public_key)
    )
  end

  def wrap({ec_point(point: public_key), parameters}, :CertificationRequestInfo_subjectPKInfo) do
    certification_request_subject_pk_info(
      algorithm:
        certification_request_subject_pk_info_algorithm(
          algorithm: oid(:"id-ecPublicKey"),
          parameters: open_type(:EcpkParameters, parameters)
        ),
      subjectPublicKey: public_key
    )
  end

  @doc """
  Extracts a public key from a SubjectPublicKeyInfo style container.

  Supports the same container structures as `wrap/2`.
  """
  @spec unwrap(spki()) :: t()
  def unwrap(subject_public_key_info(algorithm: algorithm, subjectPublicKey: public_key)) do
    case algorithm do
      algorithm_identifier(algorithm: oid(:rsaEncryption)) ->
        :public_key.der_decode(:RSAPublicKey, public_key)

      algorithm_identifier(algorithm: oid(:"id-ecPublicKey"), parameters: parameters) ->
        {ec_point(point: public_key), :public_key.der_decode(:EcpkParameters, parameters)}
    end
  end

  def unwrap(otp_subject_public_key_info(algorithm: algorithm, subjectPublicKey: public_key)) do
    case algorithm do
      public_key_algorithm(algorithm: oid(:rsaEncryption)) ->
        public_key

      public_key_algorithm(algorithm: oid(:"id-ecPublicKey"), parameters: parameters) ->
        {public_key, parameters}
    end
  end

  def unwrap(
        certification_request_subject_pk_info(algorithm: algorithm, subjectPublicKey: public_key)
      ) do
    case algorithm do
      certification_request_subject_pk_info_algorithm(algorithm: oid(:rsaEncryption)) ->
        :public_key.der_decode(:RSAPublicKey, public_key)

      certification_request_subject_pk_info_algorithm(
        algorithm: oid(:"id-ecPublicKey"),
        parameters: {:asn1_OPENTYPE, parameters}
      ) ->
        {ec_point(point: public_key), :public_key.der_decode(:EcpkParameters, parameters)}
    end
  end

  @doc """
  Converts a public key to DER (binary) format.

  ## Options:

    * `:wrap` - Wrap the private key in a SubjectPublicKeyInfo container
      (default: `true`)
  """
  @spec to_der(t(), Keyword.t()) :: binary()
  def to_der(public_key, opts \\ []) do
    if Keyword.get(opts, :wrap, true) do
      public_key
      |> wrap()
      |> der_encode()
    else
      public_key
      |> der_encode()
    end
  end

  @doc """
  Converts a public key to PEM format.

  ## Options:

    * `:wrap` - Wrap the private key in a SubjectPublicKeyInfo container; for
      RSA public keys this defaults to `true`, but for EC public keys this
      option is ignored and the key is always exported in SubjectPublicKeyInfo
      format
  """
  @spec to_pem(t(), Keyword.t()) :: String.t()
  def to_pem(public_key, opts \\ []) do
    if Keyword.get(opts, :wrap, true) or match?({ec_point(), _}, public_key) do
      public_key
      |> wrap()
    else
      public_key
    end
    |> pem_entry_encode()
    |> List.wrap()
    |> :public_key.pem_encode()
  end

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
  def from_der(der) do
    case X509.try_der_decode(der, @public_key_records) do
      nil ->
        {:error, :malformed}

      subject_public_key_info() = spki ->
        {:ok, unwrap(spki)}

      result ->
        {:ok, result}
    end
  end

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
  def from_pem(pem) do
    pem
    |> :public_key.pem_decode()
    |> Enum.find(&(elem(&1, 0) in @public_key_records))
    |> case do
      nil ->
        {:error, :not_found}

      entry ->
        try do
          :public_key.pem_entry_decode(entry)
        rescue
          MatchError ->
            {:error, :malformed}
        else
          public_key ->
            {:ok, public_key}
        end
    end
  end

  #
  # Helpers
  #

  defp der_encode(rsa_public_key() = rsa_public_key) do
    :public_key.der_encode(:RSAPublicKey, rsa_public_key)
  end

  defp der_encode(ec_point() = ec_point) do
    :public_key.der_encode(:ECPoint, ec_point)
  end

  defp der_encode(subject_public_key_info() = subject_public_key_info) do
    :public_key.der_encode(:SubjectPublicKeyInfo, subject_public_key_info)
  end

  defp pem_entry_encode(rsa_public_key() = rsa_public_key) do
    :public_key.pem_entry_encode(:RSAPublicKey, rsa_public_key)
  end

  defp pem_entry_encode(subject_public_key_info() = subject_public_key_info) do
    :public_key.pem_entry_encode(:SubjectPublicKeyInfo, subject_public_key_info)
  end
end
