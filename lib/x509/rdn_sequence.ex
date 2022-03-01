defmodule X509.RDNSequence do
  @moduledoc """
  Convenience functions for creating `:rdnSquence` tuples, as defined in
  Erlang's `:public_key` module as the `issuer_name()` type, and representing
  the X.509 RDNSequence type. RDNSequences are primarily used for the Subject
  and Issuer fields of certificates, as well as the Subject field of CSRs.

  Note that this module implements a commonly used subset of RDNSequence
  values. It supports only a single attribute type/value pair for each element
  in the sequence, and it implements the attribute types specified in RFC5280,
  section 4.1.2.4, with a few extensions from LDAP:

  * countryName (C)
  * organizationName (O)
  * organizationalUnitName (OU)
  * dnQualifier
  * stateOrProvinceName (ST)
  * commonName (CN)
  * serialNumber
  * localityName (L)
  * title
  * name
  * surname (SN)
  * givenName (GN)
  * initials
  * pseudonym
  * generationQualifier
  * domainComponent (DC)
  * emailAddress (E)

  This module encodes values as UTF8String where possible, or else
  PrintableString/IA5String where required.
  """

  import X509.ASN1

  @typedoc "RDN sequence for use in OTP certificate and CSR records"
  @type t :: :public_key.issuer_name()

  @typedoc """
  RDN type/value pair.

  The first element must be a string (short or long form) or atom (long form)
  matching one of the supported attribute types. The second element is the
  associated string value, which will be encoded as appropriate for
  the attribute type.

  Alternatively, the attribute_type can be specified as an OID, in which case
  the value is passed to Erlang's `:public_key` module as-is. Examples of
  acceptable values include `'character list'` and `{:utf8String, "string"}`.
  """
  @type attr :: {binary() | atom(), binary()} | {:public_key.oid() | term()}

  @typedoc "List of RDN type/value pairs"
  @type attr_list :: [attr]

  @doc """
  Creates a new `:rdnSquence` tuple.

  The value can be specified in one of the following formats:

    * A string specifying the attributes in hierarchical format, e.g.
      "/C=US/ST=NT/L=Springfield/O=ACME Inc."
    * A string specifying a comma-separated list of attributes, e.g.
      "C=US, ST=NT, L=Springfield, O=ACME Inc."
    * An RDN attribute list (see type documentation)

  Note that the string parsers for the first two formats do not (currently)
  recognize escape characters: separator characters ('/' and ',', respectively)
  are not allowed in attribute values.

  The optional second parameter can be used to select the output format:

    * `:plain` - for use in `:Certificate` and `:CertificationRequest` records
      (default)
    * `:otp` - for use in `:OTPCertificate` records (see `X509.Certificate`)

  Raises an error when the given value cannot be parsed, contains unsupported
  attribute types, when attribute values exceed the maximum length
  ('upper bound' in the RFC) or when values cannot be coerced into the
  expected ASN.1 type.

  ## Examples:

      iex> X509.RDNSequence.new("/C=US/CN=Bob")
      {:rdnSequence,
       [
         [{:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 85, 83>>}],
         [{:AttributeTypeAndValue, {2, 5, 4, 3}, <<12, 3, 66, 111, 98>>}]
       ]}

      iex> X509.RDNSequence.new("C=CN, givenName=麗")
      {:rdnSequence,
       [
         [{:AttributeTypeAndValue, {2, 5, 4, 6}, <<19, 2, 67, 78>>}],
         [{:AttributeTypeAndValue, {2, 5, 4, 42}, <<12, 3, 233, 186, 151>>}]
       ]}

      iex> X509.RDNSequence.new(commonName: "Elixir")
      {:rdnSequence,
       [
         [{:AttributeTypeAndValue, {2, 5, 4, 3}, <<12, 6, 69, 108, 105, 120, 105, 114>>}]
       ]}

      iex> X509.RDNSequence.new(language: "Elixir")
      ** (FunctionClauseError) no function clause matching in X509.RDNSequence.new_attr/1

      iex> X509.RDNSequence.new("C=!!")
      ** (ArgumentError) unsupported character(s) in `PrintableString` attribute

  """
  @spec new(String.t() | attr_list(), :plain | :otp) :: t()
  def new(rdn, type \\ :plain)

  def new("/" <> string, type) do
    string
    |> String.split("/")
    |> Enum.map(&split_attr/1)
    |> new(type)
  end

  def new(string, type) when is_binary(string) do
    string
    |> String.split(~r/,\s*/)
    |> Enum.map(&split_attr/1)
    |> new(type)
  end

  def new(list, :plain) do
    # FIXME: avoid calls to undocumented functions in :public_key app
    list
    |> new(:otp)
    |> :pubkey_cert_records.transform(:encode)
  end

  def new(list, :otp) do
    {:rdnSequence, Enum.map(list, &[new_attr(&1)])}
  end

  @doc """
  Converts an `:rdnSquence` tuple to a human readable string, in hierarchical
  format.

  ## Examples:

      iex> X509.RDNSequence.new("C=CN, givenName=麗") |> X509.RDNSequence.to_string
      "/C=CN/GN=麗"
  """
  @spec to_string(t()) :: String.t()
  def to_string({:rdnSequence, sequence}) do
    "/" <>
      (sequence
       |> List.flatten()
       |> Enum.map(&attr_to_string/1)
       |> Enum.join("/"))
  end

  @doc """
  Extracts the values for the specified attributes from a `:rdnSquence` tuple.

  The attribute type may be specified as an attribute name (long or short form,
  as a string, or long from as an atom) or an OID tuple. Refer to the
  documentation at the top of this module for a list of supported attributes.

  Since an attribute may appear more than once in an RDN sequence the result is
  a list of values.

  ## Examples:

      iex> X509.RDNSequence.new("/C=US/CN=Bob") |> X509.RDNSequence.get_attr(:countryName)
      ["US"]
      iex> X509.RDNSequence.new("/C=US/CN=Bob") |> X509.RDNSequence.get_attr("commonName")
      ["Bob"]
      iex> X509.RDNSequence.new("C=CN, givenName=麗") |> X509.RDNSequence.get_attr("GN")
      ["麗"]
  """
  @spec get_attr(t(), binary() | atom() | :public_key.oid()) :: [String.t()]
  def get_attr({:rdnSequence, sequence}, attr_type) do
    oid = attr_type_to_oid(attr_type)

    for {:AttributeTypeAndValue, ^oid, value} = attr <- List.flatten(sequence) do
      if is_binary(value) do
        # FIXME: avoid calls to undocumented functions in :public_key app
        {_, _, value} = :pubkey_cert_records.transform(attr, :decode)
        attr_value_to_string(value)
      else
        attr_value_to_string(value)
      end
    end
  end

  defp attr_type_to_oid(oid) when is_tuple(oid), do: oid

  defp attr_type_to_oid(type) when type in ["countryName", "C", :countryName],
    do: oid(:"id-at-countryName")

  defp attr_type_to_oid(type) when type in ["organizationName", "O", :organizationName],
    do: oid(:"id-at-organizationName")

  defp attr_type_to_oid(type)
       when type in ["organizationalUnitName", "OU", :organizationalUnitName],
       do: oid(:"id-at-organizationalUnitName")

  defp attr_type_to_oid(type) when type in ["dnQualifier", :dnQualifier],
    do: oid(:"id-at-dnQualifier")

  defp attr_type_to_oid(type)
       when type in ["stateOrProvinceName", "ST", :stateOrProvinceName],
       do: oid(:"id-at-stateOrProvinceName")

  defp attr_type_to_oid(type) when type in ["commonName", "CN", :commonName],
    do: oid(:"id-at-commonName")

  defp attr_type_to_oid(type) when type in ["serialNumber", :serialNumber],
    do: oid(:"id-at-serialNumber")

  defp attr_type_to_oid(type) when type in ["localityName", "L", :localityName],
    do: oid(:"id-at-localityName")

  defp attr_type_to_oid(type) when type in ["title", :title], do: oid(:"id-at-title")
  defp attr_type_to_oid(type) when type in ["name", :name], do: oid(:"id-at-name")

  defp attr_type_to_oid(type) when type in ["surname", "SN", :surname],
    do: oid(:"id-at-surname")

  defp attr_type_to_oid(type) when type in ["givenName", "GN", :givenName],
    do: oid(:"id-at-givenName")

  defp attr_type_to_oid(type) when type in ["initials", :initials],
    do: oid(:"id-at-initials")

  defp attr_type_to_oid(type) when type in ["pseudonym", :pseudonym],
    do: oid(:"id-at-pseudonym")

  defp attr_type_to_oid(type) when type in ["generationQualifier", :generationQualifier],
    do: oid(:"id-at-generationQualifier")

  defp attr_type_to_oid(type) when type in ["domainComponent", "DC", :domainComponent],
    do: oid(:"id-domainComponent")

  defp attr_type_to_oid(type) when type in ["emailAddress", "E", :emailAddress],
    do: oid(:"id-emailAddress")

  defp attr_to_string({:AttributeTypeAndValue, _, value} = attr) when is_binary(value) do
    # FIXME: avoid calls to undocumented functions in :public_key app
    attr
    |> :pubkey_cert_records.transform(:decode)
    |> attr_to_string()
  end

  defp attr_to_string({:AttributeTypeAndValue, oid, value}) do
    attr_oid_to_string(oid) <> "=" <> attr_value_to_string(value)
  end

  defp attr_oid_to_string(oid(:"id-at-countryName")), do: "C"
  defp attr_oid_to_string(oid(:"id-at-organizationName")), do: "O"
  defp attr_oid_to_string(oid(:"id-at-organizationalUnitName")), do: "OU"
  defp attr_oid_to_string(oid(:"id-at-dnQualifier")), do: "dnQualifier"
  defp attr_oid_to_string(oid(:"id-at-stateOrProvinceName")), do: "ST"
  defp attr_oid_to_string(oid(:"id-at-commonName")), do: "CN"
  defp attr_oid_to_string(oid(:"id-at-serialNumber")), do: "serialNumber"
  defp attr_oid_to_string(oid(:"id-at-localityName")), do: "L"
  defp attr_oid_to_string(oid(:"id-at-title")), do: "title"
  defp attr_oid_to_string(oid(:"id-at-name")), do: "name"
  defp attr_oid_to_string(oid(:"id-at-surname")), do: "SN"
  defp attr_oid_to_string(oid(:"id-at-givenName")), do: "GN"
  defp attr_oid_to_string(oid(:"id-at-initials")), do: "initials"
  defp attr_oid_to_string(oid(:"id-at-pseudonym")), do: "pseudonym"
  defp attr_oid_to_string(oid(:"id-at-generationQualifier")), do: "generationQualifier"
  defp attr_oid_to_string(oid(:"id-domainComponent")), do: "DC"
  defp attr_oid_to_string(oid(:"id-emailAddress")), do: "E"

  defp attr_oid_to_string(oid) do
    oid
    |> Tuple.to_list()
    |> Enum.map(&Integer.to_string/1)
    |> Enum.join(".")
  end

  defp attr_value_to_string({:utf8String, value}), do: value
  defp attr_value_to_string({:printableString, value}), do: List.to_string(value)
  defp attr_value_to_string({:ia5String, value}), do: List.to_string(value)
  # FIXME: for 8-bit teletexString this requires mapping (see RFC1345)
  defp attr_value_to_string({:teletexString, value}), do: List.to_string(value)
  defp attr_value_to_string(value), do: List.to_string(value)

  # Splits an attribute in the form of "type=value" into a {type, value} tuple
  defp split_attr(string) do
    string
    |> String.split("=", parts: 2)
    |> List.to_tuple()
  end

  # From RFC5280, Annex A.1
  @x520name_ub 131_072

  # Short name string mapping
  defp new_attr({"C", value}), do: new_attr({:countryName, value})
  defp new_attr({"O", value}), do: new_attr({:organizationName, value})
  defp new_attr({"OU", value}), do: new_attr({:organizationalUnitName, value})
  defp new_attr({"ST", value}), do: new_attr({:stateOrProvinceName, value})
  defp new_attr({"CN", value}), do: new_attr({:commonName, value})
  defp new_attr({"L", value}), do: new_attr({:localityName, value})
  defp new_attr({"SN", value}), do: new_attr({:surname, value})
  defp new_attr({"GN", value}), do: new_attr({:givenName, value})
  defp new_attr({"DC", value}), do: new_attr({:domainComponent, value})
  defp new_attr({"E", value}), do: new_attr({:emailAddress, value})

  # Full name string mapping
  defp new_attr({"countryName", value}), do: new_attr({:countryName, value})
  defp new_attr({"organizationName", value}), do: new_attr({:organizationName, value})
  defp new_attr({"organizationalUnitName", value}), do: new_attr({:organizationalUnitName, value})
  defp new_attr({"dnQualifier", value}), do: new_attr({:dnQualifier, value})
  defp new_attr({"stateOrProvinceName", value}), do: new_attr({:stateOrProvinceName, value})
  defp new_attr({"commonName", value}), do: new_attr({:commonName, value})
  defp new_attr({"serialNumber", value}), do: new_attr({:serialNumber, value})
  defp new_attr({"localityName", value}), do: new_attr({:localityName, value})
  defp new_attr({"title", value}), do: new_attr({:title, value})
  defp new_attr({"name", value}), do: new_attr({:name, value})
  defp new_attr({"surname", value}), do: new_attr({:surname, value})
  defp new_attr({"givenName", value}), do: new_attr({:givenName, value})
  defp new_attr({"initials", value}), do: new_attr({:initials, value})
  defp new_attr({"pseudonym", value}), do: new_attr({:pseudonym, value})
  defp new_attr({"generationQualifier", value}), do: new_attr({:generationQualifier, value})
  defp new_attr({"domainComponent", value}), do: new_attr({:domainComponent, value})
  defp new_attr({"emailAddress", value}), do: new_attr({:emailAddress, value})

  defp new_attr({:name, value}) when byte_size(value) <= @x520name_ub do
    attribute_type_and_value(type: oid(:"id-at-name"), value: {:utf8String, value})
  end

  defp new_attr({:surname, value}) when byte_size(value) <= @x520name_ub do
    attribute_type_and_value(type: oid(:"id-at-surname"), value: {:utf8String, value})
  end

  defp new_attr({:givenName, value}) when byte_size(value) <= @x520name_ub do
    attribute_type_and_value(type: oid(:"id-at-givenName"), value: {:utf8String, value})
  end

  defp new_attr({:initials, value}) when byte_size(value) <= @x520name_ub do
    attribute_type_and_value(type: oid(:"id-at-initials"), value: {:utf8String, value})
  end

  defp new_attr({:generationQualifier, value}) when byte_size(value) <= @x520name_ub do
    attribute_type_and_value(type: oid(:"id-at-generationQualifier"), value: {:utf8String, value})
  end

  defp new_attr({:dnQualifier, value}) do
    attribute_type_and_value(type: oid(:"id-at-dnQualifier"), value: printableString(value))
  end

  defp new_attr({:countryName, value}) do
    attribute_type_and_value(type: oid(:"id-at-countryName"), value: printableString(value))
  end

  defp new_attr({:serialNumber, value}) do
    attribute_type_and_value(type: oid(:"id-at-serialNumber"), value: printableString(value, 64))
  end

  defp new_attr({:commonName, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(type: oid(:"id-at-commonName"), value: {:utf8String, value})
  end

  defp new_attr({:localityName, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(type: oid(:"id-at-localityName"), value: {:utf8String, value})
  end

  defp new_attr({:stateOrProvinceName, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(type: oid(:"id-at-stateOrProvinceName"), value: {:utf8String, value})
  end

  defp new_attr({:organizationName, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(type: oid(:"id-at-organizationName"), value: {:utf8String, value})
  end

  defp new_attr({:organizationalUnitName, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(
      type: oid(:"id-at-organizationalUnitName"),
      value: {:utf8String, value}
    )
  end

  defp new_attr({:title, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(type: oid(:"id-at-title"), value: {:utf8String, value})
  end

  defp new_attr({:pseudonym, value}) when byte_size(value) <= 256 do
    attribute_type_and_value(type: oid(:"id-at-pseudonym"), value: {:utf8String, value})
  end

  defp new_attr({:domainComponent, value}) when byte_size(value) <= 63 do
    attribute_type_and_value(type: oid(:"id-domainComponent"), value: ia5String(value))
  end

  defp new_attr({:emailAddress, value}) when byte_size(value) <= 255 do
    attribute_type_and_value(type: oid(:"id-emailAddress"), value: ia5String(value))
  end

  # Opaque values can be specified by OID; the value is not interpreted
  defp new_attr({oid, value}) when is_tuple(oid) do
    attribute_type_and_value(type: oid, value: value)
  end

  @printableString [
                     ?A..?Z |> Enum.into([]),
                     ?a..?z |> Enum.into([]),
                     ?0..?9 |> Enum.into([]),
                     ' \'()+,-./:=?'
                   ]
                   |> List.flatten()

  # Concert a string (or character list) to ASN.1 PrintableString format.
  # Raises ArgumentError if the string contains unsupported characters or
  # exceeds the given maximum length
  defp printableString(string, ub \\ nil)

  defp printableString(string, ub) when is_binary(string) do
    string
    |> String.to_charlist()
    |> printableString(ub)
  end

  defp printableString(charlist, ub) do
    if Enum.all?(charlist, &(&1 in @printableString)) do
      if is_nil(ub) or length(charlist) <= ub do
        charlist
      else
        raise ArgumentError, "attribute value exceeds maximum length"
      end
    else
      raise ArgumentError, "unsupported character(s) in `PrintableString` attribute"
    end
  end

  # Only allow printable IA5 characters
  @ia5String 32..125 |> Enum.into([])

  # Concert a string (or character list) to ASN.1 IA5String format.
  # Raises ArgumentError if the string contains unsupported characters or
  # exceeds the given maximum length
  defp ia5String(string, ub \\ nil)

  defp ia5String(string, ub) when is_binary(string) do
    string
    |> String.to_charlist()
    |> ia5String(ub)
  end

  defp ia5String(charlist, ub) do
    if Enum.all?(charlist, &(&1 in @ia5String)) do
      if is_nil(ub) or length(charlist) <= ub do
        charlist
      else
        raise ArgumentError, "attribute value exceeds maximum length"
      end
    else
      raise ArgumentError, "unsupported character(s) in `IA5String` attribute"
    end
  end
end
