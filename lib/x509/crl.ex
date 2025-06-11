defmodule X509.CRL do
  @moduledoc """
  Module for generating and parsing Certificate Revocation Lists (CRLs).

  The corresponding ASN.1 data type, used in Erlang's `:public_key` module, is
  called `:CertificateList`.

  Please note that maintaining a CRL typically requires keeping state: the list
  of revoked certificates, along with their revocation date and expiry date
  (when they can be removed from the CRL), as well as the CRLs sequence number
  and the date/time of the next update. This module offers a purely functional
  interface for generating CRLs based on state kept by the caller.

  Delta CRLs are not currently supported.
  """

  import X509.ASN1, except: [extension: 2]

  alias X509.{Certificate, SignatureAlgorithm}
  alias X509.CRL.{Entry, Extension}
  alias X509.Util

  @typedoc """
  `:CertificateList` record, as used in Erlang's `:public_key` module
  """
  @opaque t :: X509.ASN1.record(:CertificateList)

  @seconds_per_day 24 * 60 * 60
  @next_update_days 30

  @doc """
  Returns a new `:CertificateList` record for the specified CRL entries.

  The first argument is a, possibly empty, list of CRL entries. Use
  `X509.CRL.Entry.new/3` to create a CRL entry for a given certificate.

  The second and third argument are the issuing certificate and the associated
  private key. The certificate must include the `:cRLSign` key usage.

  ## Options:

  * `:hash` - the hashing algorithm to use when signing the CRL (default:
    `:sha256`)
  * `:this_update` - a `DateTime` struct specifying the timestamp of the CRL
    update (default: the current time)
  * `:next_update` - a `DateTime` struct specifying the timestamp of next
    scheduled CRL update (default: see `:next_update_in_days`)
  * `:next_update_in_days` - if no `:next_update` timestamp is specified, this
    parameter defines the number of days in the future the next CRL update is
    expected (default: #{@next_update_days})
  * `:extensions` - a keyword list of extension names and values; by default
    the `authority_key_identifier` extension will be included, with a value
    derived from the issuer's `subject_key_identifier` (if present); to disable
    this extension, specify `authority_key_identifier: false`; other extension
    values will be included in the CRL as-is
  """
  # @doc since: "0.5.0"
  @spec new([Entry.t()], Certificate.t(), X509.PrivateKey.t(), Keyword.t()) :: t()
  def new(revoked, issuer, issuer_key, opts \\ []) do
    hash = Keyword.get(opts, :hash, :sha256)
    {algorithm1, algorithm2} = signature_algorithms(hash, issuer_key)

    this_update =
      opts
      |> Keyword.get(:this_update, DateTime.utc_now())
      |> X509.DateTime.new()

    next_update =
      case Keyword.get(opts, :next_update) do
        nil ->
          days = Keyword.get(opts, :next_update_in_days, @next_update_days)
          X509.DateTime.new(days * @seconds_per_day)

        date ->
          X509.DateTime.new(date)
      end

    crl_extensions =
      opts
      |> Keyword.get(:extensions, [])
      |> Keyword.put_new(:authority_key_identifier, true)
      |> Keyword.update!(:authority_key_identifier, &update_aki(&1, issuer))
      |> Keyword.values()
      |> Enum.reject(&(&1 == false))
      |> Enum.map(&encode_extension/1)

    # FIXME: avoid calls to undocumented functions in :public_key app
    tbs =
      tbs_cert_list(
        version: :v2,
        signature: algorithm1,
        issuer: issuer_subject(issuer),
        thisUpdate: this_update,
        nextUpdate: next_update,
        revokedCertificates: revoked_certificates(revoked),
        crlExtensions: crl_extensions
      )

    tbs_der = :public_key.der_encode(:TBSCertList, tbs)

    certificate_list(
      tbsCertList: tbs,
      signatureAlgorithm: algorithm2,
      signature: :public_key.sign(tbs_der, hash, issuer_key)
    )
  end

  if Util.app_version(:public_key) >= [1, 18] do
    defp signature_algorithms(hash, issuer_key) do
      {
        SignatureAlgorithm.new(hash, issuer_key, :TBSCertList_signature),
        SignatureAlgorithm.new(hash, issuer_key, :CertificateList_algorithmIdentifier)
      }
    end

    defp issuer_subject(cert) do
      cert |> Certificate.subject()
    end
  else
    defp signature_algorithms(hash, issuer_key) do
      algorithm = SignatureAlgorithm.new(hash, issuer_key, :AlgorithmIdentifier)
      {algorithm, algorithm}
    end

    defp issuer_subject(cert) do
      cert |> Certificate.subject() |> :pubkey_cert_records.transform(:encode)
    end
  end

  @doc """
  Verifies whether a CRL matches the given issuer certificate and has a valid
  signature.
  """
  # @doc since: "0.5.0"
  @spec valid?(t(), X509.Certificate.t()) :: boolean()
  def valid?(crl, issuer) do
    :public_key.pkix_is_issuer(crl, issuer) and :public_key.pkix_crl_verify(crl, issuer)
  end

  @doc """
  Returns the list of CRL entries included in a CRL.
  """
  # @doc since: "0.5.0"
  @spec list(t()) :: [X509.CRL.Entry.t()]
  def list(certificate_list(tbsCertList: tbs)) do
    case tbs_cert_list(tbs, :revokedCertificates) do
      :asn1_NOVALUE -> []
      list -> list
    end
  end

  @doc """
  Returns the Issuer field of the CRL.
  """
  # @doc since: "0.5.0"
  @spec issuer(t()) :: X509.RDNSequence.t()
  def issuer(certificate_list(tbsCertList: tbs)) do
    tbs
    |> tbs_cert_list(:issuer)
  end

  @doc """
  Returns the date and time when the CRL was issued.
  """
  # @doc since: "0.5.0"
  @spec this_update(t()) :: DateTime.t()
  def this_update(certificate_list(tbsCertList: tbs)) do
    tbs
    |> tbs_cert_list(:thisUpdate)
    |> X509.DateTime.to_datetime()
  end

  @doc """
  Returns the date and time when the next CRL update is expected.
  """
  # @doc since: "0.5.0"
  @spec next_update(t()) :: DateTime.t()
  def next_update(certificate_list(tbsCertList: tbs)) do
    tbs
    |> tbs_cert_list(:nextUpdate)
    |> X509.DateTime.to_datetime()
  end

  @doc """
  Converts a CRL to DER (binary) format.
  """
  # @doc since: "0.5.0"
  @spec to_der(t()) :: binary()
  def to_der(certificate_list() = crl) do
    :public_key.der_encode(:CertificateList, crl)
  end

  @doc """
  Converts a CRL to PEM format.
  """
  # @doc since: "0.5.0"
  @spec to_pem(t()) :: String.t()
  def to_pem(certificate_list() = crl) do
    :public_key.pem_entry_encode(:CertificateList, crl)
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  @doc """
  Attempts to parse a CRL in DER (binary) format. Raises in case of failure.
  """
  # @doc since: "0.5.0"
  @spec from_der!(binary()) :: t() | no_return()
  def from_der!(der) do
    :public_key.der_decode(:CertificateList, der)
  end

  @doc """
  Parses a CRL in DER (binary) format.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a CRL
  """
  # @doc since: "0.5.0"
  @spec from_der(binary()) :: {:ok, t()} | {:error, :malformed}
  def from_der(der) do
    {:ok, from_der!(der)}
  rescue
    MatchError -> {:error, :malformed}
  end

  @doc """
  Attempts to parse a CRL in PEM format. Raises in case of failure.

  Processes the first PEM entry of type X509 CRL found in the input.
  """
  # @doc since: "0.5.0"
  @spec from_pem!(String.t()) :: t() | no_return()
  def from_pem!(pem) do
    {:ok, csr} = from_pem(pem)
    csr
  end

  @doc """
  Parses a CRL in PEM format.

  Processes the first PEM entry of type X509 CRL found in the input. Returns an
  `:ok` tuple in case of success, or an `:error` tuple in case of failure.
  Possible error reasons are:

    * `:not_found` - no PEM entry of type X509 CRL was found
    * `:malformed` - the entry could not be decoded as a CRL
  """
  # @doc since: "0.5.0"
  @spec from_pem(String.t()) :: {:ok, t()} | {:error, :malformed | :not_found}
  def from_pem(pem) do
    pem
    |> :public_key.pem_decode()
    |> Enum.find(&match?({:CertificateList, _, :not_encrypted}, &1))
    |> case do
      nil -> {:error, :not_found}
      {:CertificateList, der, :not_encrypted} -> from_der(der)
    end
  end

  @doc """
  Returns the list of extensions included in a CRL.
  """
  # @doc since: "0.5.0"
  @spec extensions(t()) :: [X509.CRL.Extension.t()]
  def extensions(certificate_list(tbsCertList: tbs)) do
    tbs_cert_list(tbs, :crlExtensions)
  end

  @doc """
  Looks up the value of a specific extension in a CRL.

  The desired extension can be specified as an atom or an OID value. Returns
  `nil` if the specified extension is not present in the CRL.
  """
  # @doc since: "0.5.0"
  @spec extension(
          t(),
          X509.CRL.Extension.extension_id()
          | :public_key.oid()
        ) :: X509.CRL.Extension.t() | nil
  def extension(crl, extension_id) do
    crl
    |> extensions()
    |> Extension.find(extension_id)
  end

  defp revoked_certificates([]), do: :asn1_NOVALUE
  defp revoked_certificates(list) when is_list(list), do: list

  defp update_aki(false, _), do: false

  defp update_aki(true, issuer) do
    case X509.Certificate.extension(issuer, :subject_key_identifier) do
      nil ->
        false

      extension(extnValue: id) ->
        X509.Certificate.Extension.authority_key_identifier(id)
    end
  end

  defp update_aki(id, _) when is_binary(id) do
    X509.Certificate.Extension.authority_key_identifier(id)
  end

  defp update_aki(extension(extnID: oid(:"id-ce-authorityKeyIdentifier")) = aki, _) do
    aki
  end

  # Certificate extension generated by x509.Certificate.Extension are intended
  # for use in OTPCertificate records, and are therefore not DER encoded; in
  # CertificateList records (CRLs) the extension value must be DER encoded,
  # line in Certificate records
  defp encode_extension(extension(extnValue: der) = ext) when is_binary(der), do: ext

  defp encode_extension(extension(extnValue: record) = ext) when is_tuple(record) do
    type = elem(record, 0)
    der = :public_key.der_encode(type, record)
    X509.ASN1.extension(ext, extnValue: der)
  end
end
