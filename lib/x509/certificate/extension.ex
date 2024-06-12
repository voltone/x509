defmodule X509.Certificate.Extension do
  @moduledoc """
  Convenience functions for creating `:Extension` records for use in
  certificates.
  """

  import X509.ASN1, except: [basic_constraints: 2, authority_key_identifier: 1]

  alias X509.Util

  @typedoc "`:Extension` record, as used in Erlang's `:public_key` module"
  @type t :: X509.ASN1.record(:extension)

  @type extension_id ::
          :basic_constraints
          | :key_usage
          | :ext_key_usage
          | :subject_key_identifier
          | :authority_key_identifier
          | :subject_alt_name
          | :crl_distribution_point
          | :authority_information_access
          | :ocsp_nocheck

  @typedoc "Supported values in the key usage extension"
  @type key_usage_value ::
          :digitalSignature
          | :nonRepudiation
          | :keyEncipherment
          | :dataEncipherment
          | :keyAgreement
          | :keyCertSign
          | :cRLSign
          | :encipherOnly
          | :decipherOnly

  @typedoc """
  An entry for use in the subject alternate name extension. Strings are mapped
  to DNSName values, tuples must contain values supported by Erlang's
  `:public_key` module
  """
  @type san_value :: String.t() | {atom(), charlist()}

  @type aia_access_method ::
          :ocsp
          | :ca_issuers
          | :time_stamping
          | :ca_repository

  # This OID is not defined in the :public_key ASN.1 headers
  @ocsp_nocheck_oid {1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

  @doc """
  The basic constraints extension identifies whether the subject of the
  certificate is a CA and the maximum depth of valid certification
  paths that include this certificate.

  This extension is always marked as critical for CA certificates, and
  non-critical when CA is set to false.

  Examples:

      iex> X509.Certificate.Extension.basic_constraints(false)
      {:Extension, {2, 5, 29, 19}, false,
       {:BasicConstraints, false, :asn1_NOVALUE}}

      iex> X509.Certificate.Extension.basic_constraints(true)
      {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, :asn1_NOVALUE}}

      iex> X509.Certificate.Extension.basic_constraints(true, 0)
      {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, true, 0}}
  """
  @spec basic_constraints(boolean, integer | :asn1_NOVALUE) :: t()
  def basic_constraints(ca, path_len_constraint \\ :asn1_NOVALUE)

  def basic_constraints(false, :asn1_NOVALUE) do
    extension(
      extnID: oid(:"id-ce-basicConstraints"),
      critical: false,
      extnValue: X509.ASN1.basic_constraints(cA: false, pathLenConstraint: :asn1_NOVALUE)
    )
  end

  def basic_constraints(true, path_len_constraint) do
    extension(
      extnID: oid(:"id-ce-basicConstraints"),
      critical: true,
      extnValue: X509.ASN1.basic_constraints(cA: true, pathLenConstraint: path_len_constraint)
    )
  end

  @doc """
  The key usage extension defines the purpose (e.g., encipherment,
  signature, certificate signing) of the key contained in the
  certificate.

  Each of the key usage values must be one of the atoms recognized by Erlang's
  `:public_key` module, though this is not verified by this function.

  This extension is always marked as critical.

  Example:

      iex> X509.Certificate.Extension.key_usage([:digitalSignature, :keyEncipherment])
      {:Extension, {2, 5, 29, 15}, true, [:digitalSignature, :keyEncipherment]}
  """
  @spec key_usage([key_usage_value()]) :: t()
  def key_usage(list) do
    extension(
      extnID: oid(:"id-ce-keyUsage"),
      critical: true,
      extnValue: list
    )
  end

  @doc """
  This extension indicates one or more purposes for which the certified
  public key may be used, in addition to or in place of the basic
  purposes indicated in the key usage extension.  In general, this
  extension will appear only in end entity certificates.

  Each of the values in the list must be an OID, either in raw tuple format or
  as an atom representing a well-known OID. Typical examples include:

  * `:serverAuth` - TLS WWW server authentication
  * `:clientAuth` - TLS WWW client authentication
  * `:codeSigning` - Signing of downloadable executable code
  * `:emailProtection` - Email protection
  * `:timeStamping` - Binding the hash of an object to a time
  * `:ocspSigning` - Signing OCSP responses

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.ext_key_usage([:serverAuth, :clientAuth])
      {:Extension, {2, 5, 29, 37}, false,
       [{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 3, 6, 1, 5, 5, 7, 3, 2}]}
  """
  @spec ext_key_usage([atom() | :public_key.oid()]) :: t()
  def ext_key_usage(list) do
    extension(
      extnID: oid(:"id-ce-extKeyUsage"),
      critical: false,
      extnValue: Enum.map(list, &ext_key_usage_oid/1)
    )
  end

  defp ext_key_usage_oid(:any), do: oid(:anyExtendedKeyUsage)
  defp ext_key_usage_oid(:serverAuth), do: oid(:"id-kp-serverAuth")
  defp ext_key_usage_oid(:clientAuth), do: oid(:"id-kp-clientAuth")
  defp ext_key_usage_oid(:codeSigning), do: oid(:"id-kp-codeSigning")
  defp ext_key_usage_oid(:emailProtection), do: oid(:"id-kp-emailProtection")
  defp ext_key_usage_oid(:timeStamping), do: oid(:"id-kp-timeStamping")
  defp ext_key_usage_oid(:ocspSigning), do: oid(:"id-kp-OCSPSigning")
  defp ext_key_usage_oid(:OCSPSigning), do: oid(:"id-kp-OCSPSigning")

  defp ext_key_usage_oid(oid) when is_tuple(oid), do: oid

  @doc """
  The subject key identifier extension provides a means of identifying
  certificates that contain a particular public key.

  The value should be a public key record or a pre-calculated binary SHA-1
  value.

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.subject_key_identifier({:RSAPublicKey, 55, 3})
      {:Extension, {2, 5, 29, 14}, false,
       <<187, 230, 143, 92, 27, 37, 166, 93, 176, 137, 154, 111, 62, 152,
        215, 114, 3, 214, 71, 170>>}
  """
  @spec subject_key_identifier(X509.PublicKey.t() | binary()) :: t()
  def subject_key_identifier(rsa_public_key() = public_key) do
    :crypto.hash(:sha, X509.PublicKey.to_der(public_key))
    |> subject_key_identifier()
  end

  def subject_key_identifier({ec_point(), _parameters} = public_key) do
    :crypto.hash(:sha, X509.PublicKey.to_der(public_key))
    |> subject_key_identifier()
  end

  def subject_key_identifier(id) when is_binary(id) do
    extension(
      extnID: oid(:"id-ce-subjectKeyIdentifier"),
      critical: false,
      extnValue: id
    )
  end

  @doc """
  The authority key identifier extension provides a means of identifying the
  public key corresponding to the private key used to sign a certificate.

  The value should be a public key record. It is possible to pass a
  pre-calculated SHA-1 value, though it is preferred to let the function
  calculate the correct value over the original public key.

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.authority_key_identifier({:RSAPublicKey, 55, 3})
      {:Extension, {2, 5, 29, 35}, false,
       {:AuthorityKeyIdentifier,
        <<187, 230, 143, 92, 27, 37, 166, 93, 176, 137, 154, 111, 62, 152,
         215, 114, 3, 214, 71, 170>>, :asn1_NOVALUE, :asn1_NOVALUE}}
  """
  @spec authority_key_identifier(X509.PublicKey.t() | binary()) :: t()
  def authority_key_identifier(rsa_public_key() = public_key) do
    :crypto.hash(:sha, X509.PublicKey.to_der(public_key))
    |> authority_key_identifier()
  end

  def authority_key_identifier({ec_point(), _parameters} = public_key) do
    :crypto.hash(:sha, X509.PublicKey.to_der(public_key))
    |> authority_key_identifier()
  end

  def authority_key_identifier(id) when is_binary(id) do
    extension(
      extnID: oid(:"id-ce-authorityKeyIdentifier"),
      critical: false,
      extnValue: X509.ASN1.authority_key_identifier(keyIdentifier: id)
    )
  end

  @doc """
  The subject alternative name extension allows identities to be bound
  to the subject of the certificate.  These identities may be included
  in addition to or in place of the identity in the subject field of
  the certificate.  Defined options include an Internet electronic mail
  address, a DNS name, an IP address, and a Uniform Resource Identifier
  (URI).

  Typically the subject alternative name extension is used to define the
  DNS domains or hostnames for which a certificate is valid, so this
  function maps string values to DNSName entries. Values of other types
  can be passed in a type/value tuples as supported by Erlang's `:public_key`
  module, if required. Note that Erlang will typically require the value
  to be a character list.

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.subject_alt_name(["www.example.com", "example.com"])
      {:Extension, {2, 5, 29, 17}, false,
       [dNSName: ~c"www.example.com", dNSName: ~c"example.com"]}

      iex> X509.Certificate.Extension.subject_alt_name(emailAddress: ~c"user@example.com")
      {:Extension, {2, 5, 29, 17}, false,
       [emailAddress: ~c"user@example.com"]}
  """
  @spec subject_alt_name([san_value()]) :: t()
  def subject_alt_name(value) do
    extension(
      extnID: oid(:"id-ce-subjectAltName"),
      critical: false,
      extnValue: Enum.map(value, &san_entry/1)
    )
  end

  # Prepare an entry for use in SubjectAlternateName: strings are mapped to
  # DNSName entries, and {type, value} tuples are returned as-is
  defp san_entry(dns_name) when is_binary(dns_name) do
    {:dNSName, to_charlist(dns_name)}
  end

  defp san_entry({_type, _value} = entry), do: entry

  @doc """
  The CRL distribution points extension identifies how CRL information
  is obtained.

  The list of distribution points must be specified as a list of strings
  containing HTTP, FTP and/or LDAP URIs. Other types of distribution points are
  defined in RFC 5280, but are not supported by this function at this time.

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.crl_distribution_points(["http://crl.example.org/root.crl"])
      {:Extension, {2, 5, 29, 31}, false,
       [
         {:DistributionPoint,
          {:fullName, [uniformResourceIdentifier: ~c"http://crl.example.org/root.crl"]},
          :asn1_NOVALUE, :asn1_NOVALUE}
       ]}
  """
  # @doc since: "0.5.0"
  @spec crl_distribution_points([String.t()]) :: t()
  def crl_distribution_points(uri_list) do
    extension(
      extnID: oid(:"id-ce-cRLDistributionPoints"),
      critical: false,
      extnValue: Enum.map(uri_list, &crl_distribution_point/1)
    )
  end

  defp crl_distribution_point(uri) when is_binary(uri) do
    {
      :DistributionPoint,
      {:fullName, [uniformResourceIdentifier: to_charlist(uri)]},
      :asn1_NOVALUE,
      :asn1_NOVALUE
    }
  end

  @doc """
  The authority information access extension indicates how to access
  information and services for the issuer of the certificate in which the
  extension appears.

  Information and services may include on-line validation services and CA
  policy data. This extension may be included in end entity or CA certificates.

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.authority_info_access(
      ...>   ocsp: "http://ocsp.example.net/"
      ...> )
      {:Extension, {1, 3, 6, 1, 5, 5, 7, 1, 1}, false,
       [
         {:AccessDescription, {1, 3, 6, 1, 5, 5, 7, 48, 1},
          {:uniformResourceIdentifier, "http://ocsp.example.net/"}}
       ]}
  """
  # @doc since: "0.7.0"
  @spec authority_info_access([{aia_access_method(), String.t()}]) :: t()
  def authority_info_access(access_methods) do
    extension(
      extnID: oid(:"id-pe-authorityInfoAccess"),
      critical: false,
      extnValue: Enum.map(access_methods, &aia_access_method/1)
    )
  end

  defp aia_access_method({:ocsp, uri}) do
    access_description(
      accessMethod: oid(:"id-ad-ocsp"),
      accessLocation: {:uniformResourceIdentifier, uri}
    )
  end

  defp aia_access_method({:ca_issuers, uri}) do
    access_description(
      accessMethod: oid(:"id-ad-caIssuers"),
      accessLocation: {:uniformResourceIdentifier, uri}
    )
  end

  defp aia_access_method({:time_stamping, uri}) do
    access_description(
      accessMethod: oid(:"id-ad-timeStamping"),
      accessLocation: {:uniformResourceIdentifier, uri}
    )
  end

  defp aia_access_method({:ca_repository, uri}) do
    access_description(
      accessMethod: oid(:"id-ad-caRepository"),
      accessLocation: {:uniformResourceIdentifier, uri}
    )
  end

  @doc """
  The OCSP Nocheck extension indicates that the OCSP client can trust this
  OCSP responder certificate for the lifetime of the certificate, and no
  revocation checks are needed.

  This extension has no value, it acts as a flag simply by being present in a
  certificate's extension list.

  This extension is marked as non-critical.

  Example:

      iex> X509.Certificate.Extension.ocsp_nocheck()
      {:Extension, {1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, false, <<5, 0>>}
  """
  # @doc since: "0.7.0"
  @spec ocsp_nocheck() :: t()
  def ocsp_nocheck() do
    extension(
      extnID: @ocsp_nocheck_oid,
      critical: false,
      extnValue: <<5, 0>>
    )
  end

  @doc """
  Looks up the value of a specific extension in a list.

  The desired extension can be specified as an atom or an OID value. Returns
  `nil` if the specified extension is not present in the certificate.
  """
  @spec find([t()], extension_id() | :public_key.oid()) :: t() | nil
  def find(:asn1_NOVALUE, _), do: nil
  def find(list, :basic_constraints), do: find(list, oid(:"id-ce-basicConstraints"))
  def find(list, :key_usage), do: find(list, oid(:"id-ce-keyUsage"))
  def find(list, :ext_key_usage), do: find(list, oid(:"id-ce-extKeyUsage"))
  def find(list, :subject_key_identifier), do: find(list, oid(:"id-ce-subjectKeyIdentifier"))
  def find(list, :authority_key_identifier), do: find(list, oid(:"id-ce-authorityKeyIdentifier"))
  def find(list, :subject_alt_name), do: find(list, oid(:"id-ce-subjectAltName"))

  def find(list, :crl_distribution_points) do
    case find(list, oid(:"id-ce-cRLDistributionPoints")) do
      extension(extnValue: der) = ext when is_binary(der) ->
        # Older OTP versions decoded this automatically, but newer ones don't...
        extension(ext, extnValue: :public_key.der_decode(:CRLDistributionPoints, der))

      crl_distribution_points ->
        crl_distribution_points
    end
  end

  def find(list, :authority_info_access), do: find(list, oid(:"id-pe-authorityInfoAccess"))
  def find(list, :ocsp_nocheck), do: find(list, @ocsp_nocheck_oid)

  def find(list, extension_oid) do
    Enum.find(list, &match?(extension(extnID: ^extension_oid), &1))
  end

  @doc false
  # Intended for internal use only
  def to_der(list) when is_list(list) do
    :public_key.der_encode(:OTPExtensions, Enum.map(list, &encode/1))
  end

  def to_der(extension() = ext) do
    :public_key.der_encode(:Extension, encode(ext))
  end

  @doc false
  # Intended for internal use only
  def from_der!(der, type \\ :Extension)

  def from_der!(der, :OTPExtensions) do
    :public_key.der_decode(:OTPExtensions, der)
    |> Enum.map(&decode/1)
  end

  def from_der!(der, :Extension) do
    :public_key.der_decode(:Extension, der)
    |> decode()
  end

  @doc false
  # Intended for internal use only
  def prepare(extension(extnID: oid(:"id-ce-cRLDistributionPoints"), extnValue: value) = ext)
      when is_list(value) do
    # Older OTP versions encoded this automatically, but newer ones don't...
    if Util.app_version(:public_key) >= [1, 13, 3] do
      encode(ext)
    else
      ext
    end
  end

  def prepare(ext), do: ext

  defp encode(extension(extnID: oid(:"id-ce-basicConstraints"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:BasicConstraints, value))
  end

  defp encode(extension(extnID: oid(:"id-ce-keyUsage"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:KeyUsage, value))
  end

  defp encode(extension(extnID: oid(:"id-ce-extKeyUsage"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:ExtKeyUsageSyntax, value))
  end

  defp encode(extension(extnID: oid(:"id-ce-subjectKeyIdentifier"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:SubjectKeyIdentifier, value))
  end

  defp encode(extension(extnID: oid(:"id-ce-authorityKeyIdentifier"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:AuthorityKeyIdentifier, value))
  end

  defp encode(extension(extnID: oid(:"id-ce-subjectAltName"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:SubjectAltName, value))
  end

  defp encode(extension(extnID: oid(:"id-ce-cRLDistributionPoints"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:CRLDistributionPoints, value))
  end

  defp encode(extension(extnID: oid(:"id-pe-authorityInfoAccess"), extnValue: value) = ext) do
    extension(ext, extnValue: :public_key.der_encode(:AuthorityInfoAccessSyntax, value))
  end

  defp encode(extension(extnID: @ocsp_nocheck_oid) = ext) do
    ext
  end

  defp decode(extension(extnID: oid(:"id-ce-basicConstraints"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:BasicConstraints, der))
  end

  defp decode(extension(extnID: oid(:"id-ce-keyUsage"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:KeyUsage, der))
  end

  defp decode(extension(extnID: oid(:"id-ce-extKeyUsage"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:ExtKeyUsageSyntax, der))
  end

  defp decode(extension(extnID: oid(:"id-ce-subjectKeyIdentifier"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:SubjectKeyIdentifier, der))
  end

  defp decode(extension(extnID: oid(:"id-ce-authorityKeyIdentifier"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:AuthorityKeyIdentifier, der))
  end

  defp decode(extension(extnID: oid(:"id-ce-subjectAltName"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:SubjectAltName, der))
  end

  defp decode(extension(extnID: oid(:"id-ce-cRLDistributionPoints"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:CRLDistributionPoints, der))
  end

  defp decode(extension(extnID: oid(:"id-pe-authorityInfoAccess"), extnValue: der) = ext) do
    extension(ext, extnValue: :public_key.der_decode(:AuthorityInfoAccessSyntax, der))
  end

  defp decode(extension(extnID: @ocsp_nocheck_oid) = ext) do
    ext
  end
end
