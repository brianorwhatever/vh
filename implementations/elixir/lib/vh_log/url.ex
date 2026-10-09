defmodule VHLog.URL do
  @moduledoc """
  Watcher URL validation (profile §4): an `http` or `https` URL made only of
  printable ASCII (U+0021–U+007E), with a non-empty authority. Concretely, the
  value starts with `https://` or `http://` (lowercase) and the remainder's
  first character is not `/`, `?` or `#`. Nothing else is checked.
  """

  @doc """
  True if `value` is a valid watcher URL.

      iex> VHLog.URL.valid?("https://w1.example/path")
      true
      iex> VHLog.URL.valid?("not a url")
      false
      iex> VHLog.URL.valid?("HTTPS://w.example")
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(value) when is_binary(value), do: printable_ascii?(value) and authority?(value)
  def valid?(_), do: false

  defp authority?("https://" <> rest), do: non_empty_authority?(rest)
  defp authority?("http://" <> rest), do: non_empty_authority?(rest)
  defp authority?(_), do: false

  defp non_empty_authority?(<<c, _::binary>>), do: c not in ~c"/?#"
  defp non_empty_authority?(<<>>), do: false

  defp printable_ascii?(<<>>), do: true
  defp printable_ascii?(<<c, rest::binary>>) when c in 0x21..0x7E, do: printable_ascii?(rest)
  defp printable_ascii?(_), do: false
end
