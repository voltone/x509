defmodule X509 do
  @moduledoc """
  Generic functions for working with X.509 entities.
  """

  @doc """
  Scans the given string for PEM encoded entities.

  An optional list of data types may be specified to filter the result down
  to entries of the given types. If an empty list is specified (the default),
  the result is not filtered.
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
