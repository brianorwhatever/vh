defmodule VHLog.VersionTime do
  @moduledoc """
  `versionTime` parsing (profile §4): `YYYY-MM-DDTHH:MM:SSZ` or
  `YYYY-MM-DDTHH:MM:SS+00:00`, a valid calendar date and time, and no
  fractional seconds. Times are compared as instants (Unix seconds).

  Years before 0100 are rejected, matching the reference implementation
  (ECMAScript's `Date.UTC` maps two-digit years to the 1900s).
  """

  @pattern ~r/\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:Z|\+00:00)\z/
  @unix_epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})

  @doc """
  Parses a `versionTime` to Unix seconds.

      iex> VHLog.VersionTime.parse("2026-01-01T00:00:00+00:00")
      {:ok, 1767225600}
      iex> VHLog.VersionTime.parse("2026-02-30T00:00:00Z")
      :error
  """
  @spec parse(term()) :: {:ok, integer()} | :error
  def parse(value) when is_binary(value) do
    with [_ | parts] <- Regex.run(@pattern, value),
         [y, mo, d, h, mi, s] = Enum.map(parts, &String.to_integer/1),
         true <- y >= 100 and :calendar.valid_date(y, mo, d) and h < 24 and mi < 60 and s < 60 do
      {:ok, :calendar.datetime_to_gregorian_seconds({{y, mo, d}, {h, mi, s}}) - @unix_epoch}
    else
      _ -> :error
    end
  end

  def parse(_), do: :error

  @doc "True if `value` is a valid `versionTime`."
  @spec valid?(term()) :: boolean()
  def valid?(value), do: parse(value) != :error
end
