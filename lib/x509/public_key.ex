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
  Extracts or calculates the public key from the given RSA or EC private key.
  """
  @spec derive(X509.PrivateKey.t()) :: t()
  def derive(rsa_private_key(modulus: m, publicExponent: e)) do
    rsa_public_key(modulus: m, publicExponent: e)
  end

  # If the public key is not available we have to calculate it ourselves
  def derive(ec_private_key(privateKey: priv, parameters: {:namedCurve, curve}, publicKey: :asn1_NOVALUE)) do
    derive(priv, curve)
  end

  def derive(ec_private_key(parameters: params, publicKey: pub)) do
    {ec_point(point: pub), params}
  end

  @doc """
  Extracts or calculates the public key from a raw EC private key.

  The private key may be specified as an integer or a binary. The curve can be
  specified as an atom or an OID tuple.
  """
  @spec derive(binary(), :crypto.ec_named_curve() | :public_key.oid()) :: t()
  def derive(priv, curve) when is_tuple(curve) do
    # FIXME: avoid calls to undocumented functions in :public_key app
    derive(priv, :pubkey_cert_records.namedCurves(curve))
  end

  def derive(<<priv::integer-little-size(256)>>, :x25519 = curve) do
    pub = :crypto.compute_key(:ecdh, <<9::integer-little-size(256)>>, priv, curve)
    {ec_point(point: pub), {:namedCurve, curve}}
  end

  def derive(<<priv::integer-little-size(448)>>, :x448 = curve) do
    pub = :crypto.compute_key(:ecdh, <<5::integer-little-size(448)>>, priv, curve)
    {ec_point(point: pub), {:namedCurve, curve}}
  end

  def derive(priv, curve) when is_binary(priv) and is_atom(curve) do
    {pub, _} = :crypto.generate_key(:ecdh, curve, priv)
    {ec_point(point: pub), {:namedCurve, curve}}
  end

  @doc """
  Performs point multiplication on an elliptic curve.

  The point may be specified as a public key tuple, an ECPoint record or a
  binary. These last two require the curve to be specified as an atom or OID.
  The multiplier may be specified as an integer or a binary.

  Returns a public key tuple containing the new ECPoint and the curve
  parameters.
  """
  @spec mul(t(), integer() | binary()) :: t()
  def mul({ec_point, {:namedCurve, curve}}, multiplier) do
    mul(ec_point, multiplier, curve)
  end

  @spec mul(binary(), integer() | binary(), :crypto.ec_named_curve() | :public_key.oid()) :: t()
  def mul(point, multiplier, curve) when is_tuple(curve) do
    # FIXME: avoid calls to undocumented functions in :public_key app
    mul(point, multiplier, :pubkey_cert_records.namedCurves(curve))
  end
  def mul(ec_point(point: point), multiplier, curve) do
    mul(point, multiplier, curve)
  end
  def mul(point, multiplier, curve) do
    # TODO: this doesn't work for x25519 and x448
    {f, c, _g, n, h} = :crypto.ec_curve(curve)
    {pub, _} = :crypto.generate_key(:ecdh, {f, c, point, n, h}, multiplier)
    {ec_point(point: pub), {:namedCurve, curve}}
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
