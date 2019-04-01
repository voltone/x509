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
  @spec from_pem(String.t()) :: [tuple()]
  @spec from_pem(String.t(), :public_key.pki_asn1_type() | [:public_key.pki_asn1_type()]) :: [
          tuple()
        ]
  defdelegate from_pem(pem, types \\ []), to: :e509
end
