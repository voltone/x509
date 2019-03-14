defmodule X509.CSR do
  @moduledoc """
  Implements PKCS#10 Certificate Signing Requests (CSRs), formally known by
  their ASN.1 type CertificationRequest.
  """

  import X509.ASN1

  alias X509.RDNSequence

  @typedoc """
  `:CertificationRequest` record , as used in Erlang's `:public_key` module
  """
  @opaque t :: X509.ASN1.record(:certification_request)

  # CertificationRequest record version
  @version :v1

  @doc """
  Returns a `:CertificationRequest` record for the given key pair and subject.

  Supports RSA and EC private keys. The public key is extracted from the
  private key and encoded, together with the subject, in the CSR. The CSR is
  then signed with the private key, using a configurable hash algorithm.

  The default hash algorithm is `:sha256`. An alternative algorithm can be
  specified using the `:hash` option. Possible values include `:sha224`,
  `:sha256`, `:sha384`, `:sha512`.

  Older hash algorithms, supported for compatibility with older software only,
  include `:md5` (RSA only) and `:sha`. The use of these algorithms is
  discouraged.
  """
  @spec new(X509.PrivateKey.t(), String.t() | X509.RDNSequence.t(), Keyword.t()) :: t()
  def new(private_key, subject, opts \\ []) do
    hash = Keyword.get(opts, :hash, :sha256)

    algorithm =
      :e509_signature_algorithm.new(hash, private_key, :CertificationRequest_signatureAlgorithm)

    # Convert subject to RDNSequence, if necessary
    subject_rdn_sequence =
      case subject do
        {:rdnSequence, _} -> subject
        rdn -> RDNSequence.new(rdn)
      end

    # CertificationRequestInfo to be signed
    info =
      certification_request_info(
        version: @version,
        subject: subject_rdn_sequence,
        subjectPKInfo:
          private_key
          |> X509.PublicKey.derive()
          |> X509.PublicKey.wrap(:CertificationRequestInfo_subjectPKInfo),
        attributes: []
      )

    info_der = :public_key.der_encode(:CertificationRequestInfo, info)
    signature = :public_key.sign(info_der, hash, private_key)

    certification_request(
      certificationRequestInfo: info,
      signatureAlgorithm: algorithm,
      signature: signature
    )
  end

  @doc """
  Extracts the public key from the CSR.
  """
  @spec public_key(t()) :: X509.PublicKey.t()
  def public_key(certification_request(certificationRequestInfo: info)) do
    info
    |> certification_request_info(:subjectPKInfo)
    |> X509.PublicKey.unwrap()
  end

  @doc """
  Returns the Subject field of the CSR.
  """
  @spec subject(t()) :: X509.RDNSequence.t()
  def subject(certification_request(certificationRequestInfo: info)) do
    info
    |> certification_request_info(:subject)
  end

  @doc """
  Verifies whether a CSR has a valid signature.
  """
  @spec valid?(t()) :: boolean()
  def valid?(
        certification_request(
          certificationRequestInfo: info,
          signatureAlgorithm: algorithm,
          signature: signature
        ) = csr
      ) do
    info_der = :public_key.der_encode(:CertificationRequestInfo, info)

    {digest_type, _} =
      algorithm
      |> certification_request_signature_algorithm(:algorithm)
      |> :public_key.pkix_sign_types()

    :public_key.verify(info_der, digest_type, signature, public_key(csr))
  end

  @doc """
  Converts a CSR to DER (binary) format.
  """
  # @doc since: "0.3.0"
  @spec to_der(t()) :: binary()
  def to_der(certification_request() = csr) do
    :public_key.der_encode(:CertificationRequest, csr)
  end

  @doc """
  Converts a CSR to PEM format.
  """
  # @doc since: "0.3.0"
  @spec to_pem(t()) :: String.t()
  def to_pem(certification_request() = csr) do
    :public_key.pem_entry_encode(:CertificationRequest, csr)
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  @doc """
  Attempts to parse a CSR in DER (binary) format. Raises in case of failure.
  """
  # @doc since: "0.3.0"
  @spec from_der!(binary()) :: t() | no_return()
  def from_der!(der) do
    :public_key.der_decode(:CertificationRequest, der)
  end

  @doc """
  Parses a CSR in DER (binary) format.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a CSR
  """
  # @doc since: "0.3.0"
  @spec from_der(binary()) :: {:ok, t()} | {:error, :malformed}
  def from_der(der) do
    {:ok, from_der!(der)}
  rescue
    MatchError -> {:error, :malformed}
  end

  @doc """
  Attempts to parse a CSR in PEM format. Raises in case of failure.

  Processes the first PEM entry of type CERTIFICATE REQUEST found in the input.
  """
  # @doc since: "0.3.0"
  @spec from_pem!(String.t()) :: t() | no_return()
  def from_pem!(pem) do
    {:ok, csr} = from_pem(pem)
    csr
  end

  @doc """
  Parses a CSR in PEM format.

  Processes the first PEM entry of type CERTIFICATE REQUEST found in the input.
  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:not_found` - no PEM entry of type CERTIFICATE REQUEST was found
    * `:malformed` - the entry could not be decoded as a CSR
  """
  # @doc since: "0.3.0"
  @spec from_pem(String.t()) :: {:ok, t()} | {:error, :malformed | :not_found}
  def from_pem(pem) do
    pem
    |> :public_key.pem_decode()
    |> Enum.find(&match?({:CertificationRequest, _, :not_encrypted}, &1))
    |> case do
      nil -> {:error, :not_found}
      {:CertificationRequest, der, :not_encrypted} -> from_der(der)
    end
  end
end
