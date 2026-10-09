defmodule VHLog.URL do
  @moduledoc """
  A small approximation of the WHATWG URL parser's `URL.canParse` (used by
  the reference implementation to validate `watchers`): an absolute URL with
  a scheme; the special schemes `http`, `https`, `ws`, `wss` and `ftp` also
  need a non-empty, well-formed host and a numeric port, if any.
  """

  @special ~w(http https ws wss ftp)
  @forbidden_host ~c" #%/:<>?@[\\]^|"

  @doc """
  True if `value` parses as an absolute URL.

      iex> VHLog.URL.valid?("https://w1.example/path")
      true
      iex> VHLog.URL.valid?("not a url")
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(value) when is_binary(value) do
    trimmed = value |> trim() |> String.replace(["\t", "\n", "\r"], "")

    case Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.\-]*):(.*)\z/s, trimmed) do
      [_, scheme, rest] ->
        if String.downcase(scheme) in @special, do: special_ok?(rest), else: true

      nil ->
        false
    end
  end

  def valid?(_), do: false

  # Leading/trailing C0 controls and spaces are stripped.
  defp trim(s), do: Regex.replace(~r/\A[\x00-\x20]+|[\x00-\x20]+\z/, s, "")

  defp special_ok?(rest) do
    authority =
      rest
      |> String.trim_leading("/")
      |> String.trim_leading("\\")
      |> String.split(["/", "\\", "?", "#"], parts: 2)
      |> hd()

    host_port = authority |> String.split("@") |> List.last()

    case host_port do
      "[" <> _ ->
        Regex.match?(~r/\A\[[0-9A-Fa-f:.]+\](:\d*)?\z/, host_port)

      _ ->
        {host, port} =
          case String.split(host_port, ":", parts: 2) do
            [h] -> {h, ""}
            [h, p] -> {h, p}
          end

        host != "" and
          not Enum.any?(String.to_charlist(host), &(&1 in @forbidden_host or &1 < 0x20)) and
          (port == "" or (Regex.match?(~r/\A\d+\z/, port) and String.to_integer(port) <= 65_535))
    end
  end
end
