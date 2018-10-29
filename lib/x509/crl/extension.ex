defmodule X509.CRL.Extension do
  @moduledoc """
  Convenience functions for creating `:Extension` records for use in
  CRLs or CRL entries.

  Some extensions defined in `X509.Certificate.Extension` may also be used
  in CRLs (e.g. `authority_key_identifier`). Please use the functions in
  that module to create such extension records.
  """

  import X509.ASN1

  @typedoc "`:Extension` record, as used in Erlang's `:public_key` module"
  @opaque t :: X509.ASN1.record(:extension)

  @type extension_id ::
          :crl_reason
          | :crl_number
          | :authority_key_identifier

  @typedoc "Supported values in the reason code extension"
  @type reason_code_value ::
          :keyCompromise
          | :cACompromise
          | :affiliationChanged
          | :superseded
          | :cessationOfOperation
          | :certificateHold
          | :removeFromCRL
          | :privilegeWithdrawn
          | :aACompromise

  @doc """
  The CRL number conveys a monotonically increasing sequence number for a
  given CRL scope and CRL issuer. This extension allows users to easily
  determine when a particular CRL supersedes another CRL.

  This extension is marked as non-critical.

  Example:

      iex> X509.CRL.Extension.crl_number(12)
      {:Extension, {2, 5, 29, 20}, false, <<2, 1, 12>>}
  """
  # @doc since: "0.5.0"
  @spec crl_number(non_neg_integer()) :: t()
  def crl_number(number) do
    extension(
      extnID: oid(:"id-ce-cRLNumber"),
      critical: false,
      extnValue: :public_key.der_encode(:CRLNumber, number)
    )
  end

  @doc """
  The reason code identifies the reason for the certificate revocation.
  CRL issuers are strongly encouraged to include meaningful reason codes
  in CRL entries.

  The value `:removeFromCRL` is reserved for use in delta CRLs.

  This extension is marked as non-critical.

  Example:

      iex> X509.CRL.Extension.reason_code(:keyCompromise)
      {:Extension, {2, 5, 29, 21}, false, <<10, 1, 1>>}
  """
  # @doc since: "0.5.0"
  @spec reason_code(reason_code_value()) :: t()
  def reason_code(reason) do
    extension(
      extnID: oid(:"id-ce-cRLReasons"),
      critical: false,
      extnValue: :public_key.der_encode(:CRLReason, reason)
    )
  end

  @doc """
  Looks up the value of a specific extension in a list.

  The desired extension can be specified as an atom or an OID value. Returns
  `nil` if the specified extension is not present in the certificate.
  """
  # @doc since: "0.5.0"
  @spec find([t()], extension_id() | :public_key.oid()) :: t() | nil
  def find(list, :reason_code), do: find(list, oid(:"id-ce-cRLReasons"))
  def find(list, :crl_number), do: find(list, oid(:"id-ce-cRLNumber"))
  def find(list, :authority_key_identifier), do: find(list, oid(:"id-ce-authorityKeyIdentifier"))

  def find(list, extension_oid) do
    Enum.find(list, &match?(extension(extnID: ^extension_oid), &1))
  end
end
