defmodule X509.CRL.Entry do
  @moduledoc """
  CRL entries identify revoked certificates and contain metadata about the
  revocation.
  """

  import X509.ASN1

  @typedoc """
  `:TBSCertList_revokedCertificates_SEQOF` record, as used in Erlang's
  `:public_key` module
  """
  @opaque t :: X509.ASN1.record(:tbs_cert_list_revoked_certificate)

  @doc """
  Returns a new CRL entry for the given certificate or serial number. The
  revocation date must be specified, and additional metadata may be specified
  as one or more `X509.CRL.Extension` entries.
  """
  # @doc since: "0.5.0"
  @spec new(X509.Certificate.t() | pos_integer(), DateTime.t(), [X509.CRL.Extension.t()]) :: t()
  def new(certificate, date, extensions \\ [])

  def new(serial, %DateTime{} = date, extensions)
      when is_integer(serial) and is_list(extensions) do
    tbs_cert_list_revoked_certificate(
      userCertificate: serial,
      revocationDate: X509.DateTime.new(date),
      crlEntryExtensions: extensions
    )
  end

  def new(certificate, %DateTime{} = date, extensions) when is_list(extensions) do
    certificate
    |> X509.Certificate.serial()
    |> new(date, extensions)
  end

  @doc """
  Returns the certificate serial number for a CRL entry.
  """
  # @doc since: "0.5.0"
  @spec serial(t()) :: pos_integer()
  def serial(tbs_cert_list_revoked_certificate(userCertificate: number)), do: number

  @doc """
  Returns the certificate recocation date for a CRL entry.
  """
  # @doc since: "0.5.0"
  @spec revocation_date(t()) :: DateTime.t()
  def revocation_date(tbs_cert_list_revoked_certificate(revocationDate: date)) do
    X509.DateTime.to_datetime(date)
  end

  @doc """
  Returns the list of extensions in a CRL entry.
  """
  # @doc since: "0.5.0"
  @spec extensions(t()) :: [X509.CRL.Extension.t()]
  def extensions(tbs_cert_list_revoked_certificate(crlEntryExtensions: extensions)) do
    extensions
  end

  @doc """
  Looks up a specific extension in a CRL entry.

  The desired extension can be specified as an atom or an OID value. Returns
  `nil` if the specified extension is not present in the CRL entry.
  """
  # @doc since: "0.5.0"
  @spec extension(
          t(),
          X509.CRL.Extension.extension_id()
          | :public_key.oid()
        ) :: X509.CRL.Extension.t() | nil
  def extension(entry, extension_id) do
    entry
    |> extensions()
    |> X509.CRL.Extension.find(extension_id)
  end
end
