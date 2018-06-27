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

  @doc """
  Derives the public key from the given RSA or EC private key.
  """
  @spec derive(X509.PrivateKey.t()) :: t()
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
          parameters: :NULL
        ),
      subjectPublicKey: :public_key.der_encode(:RSAPublicKey, public_key)
    )
  end

  def wrap({ec_point(point: public_key), parameters}, :OTPSubjectPublicKeyInfo) do
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
  @spec wrap(spki()) :: t()
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
        :public_key.der_decode(:RSAPublicKey, public_key)

      public_key_algorithm(algorithm: oid(:"id-ecPublicKey"), parameters: parameters) ->
        {ec_point(point: public_key), parameters}
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
      (default: `false`)
  """
  @spec to_der(t(), Keyword.t()) :: binary()
  def to_der(public_key, opts \\ []) do
    if Keyword.get(opts, :wrap, true) do
      public_key
      |> wrap()
      |> X509.to_der()
    else
      public_key
      |> X509.to_der()
    end
  end

  @doc """
  Converts a public key to PEM format.

  ## Options:

    * `:wrap` - Wrap the private key in a SubjectPublicKeyInfo container; for
      RSA public keys this defaults to `false`, but for EC public keys this
      option is ignored and the key is always exported in SubjectPublicKeyInfo
      format
  """
  @spec to_pem(t(), Keyword.t()) :: String.t()
  def to_pem(public_key, opts \\ []) do
    if Keyword.get(opts, :wrap, true) or match?({ec_point(), _}, public_key) do
      public_key
      |> wrap()
      |> X509.to_pem()
    else
      public_key
      |> X509.to_pem()
    end
  end

  @doc """
  Attempts to parse a public key in DER (binary) format. Unwraps a
  SubjectPublicKeyInfo style container, if present.

  If the data cannot be parsed as a supported public key type, `nil` is
  returned.
  """
  @spec from_der(binary()) :: t() | nil
  def from_der(der) do
    case X509.try_der_decode(der, [:RSAPublicKey, :SubjectPublicKeyInfo]) do
      nil ->
        nil

      subject_public_key_info() = spki ->
        unwrap(spki)

      result ->
        result
    end
  end

  @doc """
  Attempts to parse a public key in PEM format. Unwraps a SubjectPublicKeyInfo
  style container, if present.

  If the data cannot be parsed as a supported public key type, `nil` is
  returned.
  """
  @spec from_pem(String.t()) :: t() | nil
  def from_pem(pem) do
    case :public_key.pem_decode(pem) do
      [{type, _, :not_encrypted} = entry] when type in [:RSAPublicKey, :SubjectPublicKeyInfo] ->
        :public_key.pem_entry_decode(entry)

      _ ->
        nil
    end
  end
end
