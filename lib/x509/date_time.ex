defmodule X509.DateTime do
  @moduledoc false

  # Builds an ASN.1 UTCTime (for years prior to 2050) or GeneralizedTime (for
  # years starting with 2050)
  def new(seconds \\ 0)

  def new(seconds) when is_integer(seconds) do
    DateTime.utc_now() |> shift(seconds) |> new()
  end

  def new(%DateTime{year: year} = datetime) when year < 2050 do
    {:utcTime, utc_time(datetime)}
  end

  def new(datetime) do
    {:generalTime, general_time(datetime)}
  end

  # Builds ASN.1 UTCTime as charlist
  def utc_time(seconds \\ 0)

  def utc_time(seconds) when is_integer(seconds) do
    DateTime.utc_now() |> shift(seconds) |> utc_time()
  end

  def utc_time(%DateTime{} = datetime) do
    iso = DateTime.to_iso8601(datetime, :basic)
    [_, date, time] = Regex.run(~r/^\d\d(\d{6})T(\d{6})(?:\.\d+)?Z$/, iso)
    ~c"#{date}#{time}Z"
  end

  # Builds ASN.1 GeneralTime as charlist
  def general_time(seconds \\ 0)

  def general_time(seconds) when is_integer(seconds) do
    DateTime.utc_now() |> shift(seconds) |> general_time()
  end

  def general_time(%DateTime{} = datetime) do
    iso = DateTime.to_iso8601(datetime, :basic)
    [_, date, time] = Regex.run(~r/^(\d{8})T(\d{6})(?:\.\d+)?Z$/, iso)
    ~c"#{date}#{time}Z"
  end

  def to_datetime({:utcTime, time}) do
    "20#{time}" |> to_datetime()
  end

  def to_datetime({:generalTime, time}) do
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
