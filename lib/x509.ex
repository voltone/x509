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

  def from_pem(pem, types) do
    :e509.from_pem(types, pem)
  end

  # Try to decode a DER binary as one of the given record types, returning
  # `nil` if none of the types produced a valid result. Intended for internal
  # use only
  # TODO: remove this once the migration to e509 is complete
  @doc false
  def try_der_decode(der, types) do
    case :e509.try_der_decode(List.wrap(types), der) do
      :undefined -> nil
      entry -> entry
    end
  end
end
