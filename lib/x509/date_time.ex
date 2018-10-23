defmodule X509.DateTime do
  @moduledoc false

  # Builts an ASN.1 UTCTime (for years prior to 2050) or GeneralizedTime (for
  # years starting with 2050)
  def new() do
    DateTime.utc_now() |> new()
  end

  def new(seconds) when is_integer(seconds) do
    DateTime.utc_now() |> shift(seconds) |> new()
  end

  def new(%DateTime{year: year} = datetime) when year < 2050 do
    iso = DateTime.to_iso8601(datetime, :basic)
    [_, date, time] = Regex.run(~r/^\d\d(\d{6})T(\d{6})(?:\.\d+)?Z$/, iso)
    {:utcTime, '#{date}#{time}Z'}
  end

  def new(datetime) do
    iso = DateTime.to_iso8601(datetime, :basic)
    [_, date, time] = Regex.run(~r/^(\d{8})T(\d{6})(?:\.\d+)?Z$/, iso)
    {:generalizedTime, '#{date}#{time}Z'}
  end

  # Shifts a DateTime value by a number of seconds (positive or negative)
  defp shift(%DateTime{} = datetime, seconds) do
    datetime
    |> DateTime.to_unix()
    |> Kernel.+(seconds)
    |> DateTime.from_unix!()
  end
end
