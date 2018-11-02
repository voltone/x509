defmodule X509.DateTime do
  @moduledoc false

  # Builds an ASN.1 UTCTime (for years prior to 2050) or GeneralizedTime (for
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

  def to_datetime({:utcTime, time}) do
    "20#{time}" |> to_datetime()
  end

  def to_datetime({:generalizedTime, time}) do
    time |> to_string() |> to_datetime()
  end

  def to_datetime(
        <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
          minute::binary-size(2), second::binary-size(2), "Z"::binary>>
      ) do
    %DateTime{
      year: String.to_integer(year),
      month: String.to_integer(month),
      day: String.to_integer(day),
      hour: String.to_integer(hour),
      minute: String.to_integer(minute),
      second: String.to_integer(second),
      time_zone: "Etc/UTC",
      zone_abbr: "UTC",
      utc_offset: 0,
      std_offset: 0
    }
  end

  # Shifts a DateTime value by a number of seconds (positive or negative)
  defp shift(%DateTime{} = datetime, seconds) do
    datetime
    |> DateTime.to_unix()
    |> Kernel.+(seconds)
    |> DateTime.from_unix!()
  end
end
