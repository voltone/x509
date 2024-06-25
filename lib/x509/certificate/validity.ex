defmodule X509.Certificate.Validity do
  @moduledoc """
  Convenience functions for creating `:Validity` records for use in
  certificates. The `:Validity` record represents the X.509 Validity
  type, defining the validity of a certificate in terms of `notBefore`
  and `notAfter` timestamps.
  """

  import X509.ASN1

  @typedoc "X.509 Time type (UTCTime or GeneralizedTime)"
  @type time :: {:utcTime | :generalTime, charlist()}

  @typedoc "`:Validity` record, as used in Erlang's `:public_key` module"
  @type t :: X509.ASN1.record(:validity)

  @default_backdate_seconds 5 * 60
  @seconds_per_day 24 * 60 * 60

  @doc """
  Creates a new `:Validity` record with the given start and end timestamps
  in DateTime format.

  ## Examples:

      iex> {:ok, not_before, 0} = DateTime.from_iso8601("2018-01-01T00:00:00Z")
      iex> {:ok, not_after, 0} = DateTime.from_iso8601("2018-12-31T23:59:59Z")
      iex> X509.Certificate.Validity.new(not_before, not_after)
      {:Validity, {:utcTime, ~c"180101000000Z"}, {:utcTime, ~c"181231235959Z"}}

      iex> {:ok, not_before, 0} = DateTime.from_iso8601("2051-01-01T00:00:00Z")
      iex> {:ok, not_after, 0} = DateTime.from_iso8601("2051-12-31T23:59:59Z")
      iex> X509.Certificate.Validity.new(not_before, not_after)
      {:Validity, {:generalTime, ~c"20510101000000Z"},
        {:generalTime, ~c"20511231235959Z"}}
  """
  @spec new(DateTime.t(), DateTime.t()) :: t()
  def new(%DateTime{} = not_before, %DateTime{} = not_after) do
    validity(
      notBefore: X509.DateTime.new(not_before),
      notAfter: X509.DateTime.new(not_after)
    )
  end

  @doc """
  Creates a new `:Validity` record with an `notAfter` value a given number of
  days in the future. The `notBefore` value can be backdated (by default
  #{@default_backdate_seconds} seconds) to avoid newly issued certificates
  from being rejected by peers due to poorly synchronized clocks.

  For CA certificates, consider using `new/2` instead, with a `not_before`
  value that does not reveal the exact time when the key pair was generated.
  This minimizes information leakage about the state of the RNG.
  """
  @spec days_from_now(integer(), non_neg_integer()) :: t()
  def days_from_now(days, backdate_seconds \\ @default_backdate_seconds) do
    validity(
      notBefore: X509.DateTime.new(-backdate_seconds),
      notAfter: X509.DateTime.new(days * @seconds_per_day)
    )
  end
end
