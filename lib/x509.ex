defmodule X509 do
  @moduledoc """
  This top-level module includes generic, entity-independent conversion
  functions to/from DER and PEM format.

  Note that the `X509.PublicKey` and `X509.PrivateKey` modules offer
  specialized implementations of these functions for dealing with public and
  private keys, respectively.
  """

  @doc """
  Converts an X.509 or related record to DER (binary) format.
  """
  @spec to_der(tuple()) :: binary()
  def to_der(entity) when is_tuple(entity) do
    entity
    |> elem(0)
    |> :public_key.der_encode(entity)
  end

  @doc """
  Converts an X.509 or related record to PEM format.
  """
  @spec to_pem(tuple()) :: String.t()
  def to_pem(entity) when is_tuple(entity) do
    entity
    |> elem(0)
    |> :public_key.pem_entry_encode(entity)
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  @doc """
  Decodes an X.509 or related record in DER (binary) format.
  """
  @spec from_der(binary(), :public_key.pki_asn1_type()) :: tuple()
  def from_der(der, type) when is_binary(der) and is_atom(type) do
    :public_key.der_decode(type, der)
  end

  @doc """
  Scans the given string for PEM encoded entities.

  An optional list of data types may be specified to filter the result down
  to entries of the given types. If an empty list is specified (the default),
  the results are not filtered.
  """
  @spec from_pem(String.t(), :public_key.pki_asn1_type() | [:public_key.pki_asn1_type()]) :: [
          tuple()
        ]
  def from_pem(pem, types \\ [])

  def from_pem(pem, []) when is_binary(pem) do
    pem
    |> :public_key.pem_decode()
    |> Enum.map(&:public_key.pem_entry_decode/1)
  end

  def from_pem(pem, types) do
    pem
    |> :public_key.pem_decode()
    |> Enum.filter(&(elem(&1, 0) in List.wrap(types)))
    |> Enum.map(&:public_key.pem_entry_decode/1)
  end

  # Try to decode a DER binary as one of the given record types, returning
  # `nil` if none of the types produced a valid result. Intended for internal
  # use only
  @doc false
  def try_der_decode(_, []), do: nil

  def try_der_decode(der, [type | more]) do
    :public_key.der_decode(type, der)
  rescue
    MatchError ->
      try_der_decode(der, more)
  end
end
