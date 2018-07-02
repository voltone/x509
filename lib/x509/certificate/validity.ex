defmodule X509.Certificate.Validity do
  @moduledoc """
  Convenience functions for creating `:Validity` records for use in
  certificates. The `:Validity` record represents the X.509 Validity
  type, defining the validity of a certificate in terms of `notBefore`
  and `notAfter` timestamps.
  """

  import X509.ASN1

  @typedoc "X.509 Time type (UTCTime or GeneralizedTime)"
  @type time :: {:utcTime | :generalizedTime, charlist()}

  @typedoc "`:Validity` record, as used in Erlang's `:public_key` module"
  @opaque t :: X509.ASN1.record(:validity)

  @default_backdate_seconds 5 * 60
  @seconds_per_day 24 * 60 * 60

  @doc """
  Creates a new `:Validity` record with the given start and end timestamps
  in DateTime format.

  ## Examples:

      iex> {:ok, not_before, 0} = DateTime.from_iso8601("2018-01-01T00:00:00Z")
      iex> {:ok, not_after, 0} = DateTime.from_iso8601("2018-12-31T23:59:59Z")
      iex> X509.Certificate.Validity.new(not_before, not_after)
      {:Validity, {:utcTime, '180101000000Z'}, {:utcTime, '181231235959Z'}}

      iex> {:ok, not_before, 0} = DateTime.from_iso8601("2051-01-01T00:00:00Z")
      iex> {:ok, not_after, 0} = DateTime.from_iso8601("2051-12-31T23:59:59Z")
      iex> X509.Certificate.Validity.new(not_before, not_after)
      {:Validity, {:generalizedTime, '20510101000000Z'},
        {:generalizedTime, '20511231235959Z'}}
  """
  @spec new(DateTime.t(), DateTime.t()) :: t()
  def new(%DateTime{} = not_before, %DateTime{} = not_after) do
    validity(
      notBefore: to_asn1(not_before),
      notAfter: to_asn1(not_after)
    )
  end

  @doc """
  Creates a new `:Validity` record with an `notAfter` value a given number of
  days in the future. The `notBefore` value can be backdated (by default
  #{@default_backdate_seconds} seconds) to avoid newly issued certificates
  from being rejected by peers due to poorly synchronized clocks.

  For CA certificates, consider using `new/2` instead, with a `not_before`
  value that does not reveal the exact time when the keypair was generated.
  This minimizes information leakage about the state of the RNG.
  """
  @spec days_from_now(pos_integer(), non_neg_integer()) :: t()
  def days_from_now(days, backdate_seconds \\ @default_backdate_seconds) do
    not_before =
      DateTime.utc_now()
      |> shift(-backdate_seconds)

    not_after = shift(not_before, days * @seconds_per_day)
    new(not_before, not_after)
  end

  # Shifts a DateTime value by a number of seconds (positive or negative)
  defp shift(datetime, seconds) do
    datetime
    |> DateTime.to_unix()
    |> Kernel.+(seconds)
    |> DateTime.from_unix!()
  end

  # Converts a DateTime value to ASN.1 UTCTime (for years prior to 2050) or
  # GeneralizedTime (for years starting with 2050)
  defp to_asn1(%DateTime{year: year} = datetime) when year < 2050 do
    iso = DateTime.to_iso8601(datetime, :basic)
    [_, date, time] = Regex.run(~r/^\d\d(\d{6})T(\d{6})Z$/, iso)
    {:utcTime, '#{date}#{time}Z'}
  end

  defp to_asn1(datetime) do
    iso = DateTime.to_iso8601(datetime, :basic)
    [_, date, time] = Regex.run(~r/^(\d{8})T(\d{6})Z$/, iso)
    {:generalizedTime, '#{date}#{time}Z'}
  end
end
