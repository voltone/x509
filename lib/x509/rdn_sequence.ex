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
      ** (FunctionClauseError) no function clause matching in :e509_rdn_sequence.new_attr/1

      iex> X509.RDNSequence.new("C=!!")
      ** (ArgumentError) argument error

  """
  @spec new(String.t() | attr_list(), :plain | :otp) :: t()
  def new(rdn, type \\ :plain)

  def new(string, type) when is_binary(string) do
    string
    |> to_charlist()
    |> :e509_rdn_sequence.from_string(type)
  end

  def new(list, type) when is_list(list) do
    :e509_rdn_sequence.from_attr_list(list, type)
  end

  @doc """
  Converts an `:rdnSquence` tuple to a human readable string, in hierarchical
  format.

  ## Examples:

      iex> X509.RDNSequence.new("C=CN, givenName=麗") |> X509.RDNSequence.to_string
      "/C=CN/GN=麗"
  """
  @spec to_string(t()) :: String.t()
  def to_string(rdn_sequence) do
    rdn_sequence |> :e509_rdn_sequence.to_string() |> Kernel.to_string()
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
  def get_attr(rdn_sequence, attr_type) when is_binary(attr_type) do
    get_attr(rdn_sequence, to_charlist(attr_type))
  end

  def get_attr(rdn_sequence, attr_type) do
    rdn_sequence
    |> :e509_rdn_sequence.get_attr(attr_type)
    |> Enum.map(&Kernel.to_string/1)
  end
end
