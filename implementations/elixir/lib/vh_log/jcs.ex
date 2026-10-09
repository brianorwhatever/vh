defmodule VHLog.JCS do
  @moduledoc """
  RFC 8785 JSON Canonicalization Scheme.

  * Numbers are IEEE-754 doubles serialised with ECMAScript's
    `Number::toString` (`1e21` → `"1e+21"`, `1e-7` → `"1e-7"`, `-0.0` → `"0"`).
  * Strings escape only `"`, `\\` and control characters, using the short
    forms `\\b \\t \\n \\f \\r` and lowercase `\\u00xx` otherwise.
  * Object members are sorted by the UTF-16 code units of their keys.
  """

  import Bitwise

  @max_safe 9_007_199_254_740_992

  @doc ~S"""
  Canonicalises a decoded JSON value.

      iex> VHLog.JCS.canonicalize(%{"b" => 1, "a" => [true, nil, 1.0e21]})
      ~s({"a":[true,null,1e+21],"b":1})
  """
  @spec canonicalize(VHLog.JSON.value()) :: String.t()
  def canonicalize(value), do: value |> encode() |> IO.iodata_to_binary()

  @doc "Parses JSON text and canonicalises it."
  @spec canonicalize_text(binary()) :: {:ok, String.t()} | {:error, term()}
  def canonicalize_text(text) do
    with {:ok, value} <- VHLog.JSON.decode(text), do: {:ok, canonicalize(value)}
  end

  defp encode(nil), do: "null"
  defp encode(true), do: "true"
  defp encode(false), do: "false"
  defp encode(n) when is_number(n), do: number(n)
  defp encode(s) when is_binary(s), do: string(s)

  defp encode(list) when is_list(list),
    do: [?[, list |> Enum.map(&encode/1) |> Enum.intersperse(?,), ?]]

  defp encode(map) when is_map(map) do
    members =
      map
      |> Enum.map(fn {k, v} -> {to_key(k), v} end)
      |> Enum.sort_by(fn {k, _} -> utf16(k) end)
      |> Enum.map(fn {k, v} -> [string(k), ?:, encode(v)] end)
      |> Enum.intersperse(?,)

    [?{, members, ?}]
  end

  defp encode(other), do: raise(ArgumentError, "JCS: unsupported value #{inspect(other)}")

  defp to_key(k) when is_binary(k), do: k
  defp to_key(k) when is_atom(k), do: Atom.to_string(k)

  # Big-endian UTF-16 bytes compare exactly like the code-unit sequence.
  defp utf16(key), do: :unicode.characters_to_binary(key, :utf8, {:utf16, :big})

  @doc ~S"""
  Serialises a number as ECMAScript `Number::toString` does.

      iex> Enum.map([1.0e21, 1.0e-7, -0.0, 1.0, 123456789012345678, 0.1], &VHLog.JCS.number/1)
      ["1e+21", "1e-7", "0", "1", "123456789012345680", "0.1"]
  """
  @spec number(number()) :: String.t()
  def number(n) when is_integer(n) and abs(n) < @max_safe, do: Integer.to_string(n)
  def number(n) when is_integer(n), do: number(:erlang.float(n))
  def number(f) when is_float(f) and f == 0, do: "0"
  def number(f) when is_float(f) and f < 0, do: "-" <> number(-f)

  def number(f) when is_float(f) do
    {digits, n} = decompose(f)
    k = byte_size(digits)

    cond do
      k <= n and n <= 21 ->
        digits <> String.duplicate("0", n - k)

      0 < n and n <= 21 ->
        binary_part(digits, 0, n) <> "." <> binary_part(digits, n, k - n)

      -6 < n and n <= 0 ->
        "0." <> String.duplicate("0", -n) <> digits

      true ->
        e = n - 1
        exp = if e >= 0, do: "e+#{e}", else: "e-#{-e}"

        case digits do
          <<d>> -> <<d>> <> exp
          <<d, rest::binary>> -> <<d, ?.>> <> rest <> exp
        end
    end
  end

  # Shortest round-trip digits `d1..dk` and the exponent `n` such that
  # f = 0.d1..dk × 10^n (ECMA-262 Number::toString, step 5).
  defp decompose(f) do
    {mantissa, exp} =
      case String.split(:erlang.float_to_binary(f, [:short]), "e") do
        [m] -> {m, 0}
        [m, e] -> {m, String.to_integer(e)}
      end

    {int, frac} =
      case String.split(mantissa, ".") do
        [i] -> {i, ""}
        [i, fr] -> {i, fr}
      end

    raw = int <> frac
    trimmed = String.trim_leading(raw, "0")
    point = byte_size(int) + exp - (byte_size(raw) - byte_size(trimmed))
    {String.trim_trailing(trimmed, "0"), point}
  end

  @doc ~S"""
  Serialises a string as JSON, escaping as RFC 8785 requires.

      iex> VHLog.JCS.string("a\"\n\u000f€")
      ~s("a\\"\\n\\u000f€")
  """
  @spec string(String.t()) :: String.t()
  def string(s), do: IO.iodata_to_binary([?", escape(s, []), ?"])

  defp escape(<<>>, acc), do: Enum.reverse(acc)
  defp escape(<<?", rest::binary>>, acc), do: escape(rest, ["\\\"" | acc])
  defp escape(<<?\\, rest::binary>>, acc), do: escape(rest, ["\\\\" | acc])
  defp escape(<<?\b, rest::binary>>, acc), do: escape(rest, ["\\b" | acc])
  defp escape(<<?\t, rest::binary>>, acc), do: escape(rest, ["\\t" | acc])
  defp escape(<<?\n, rest::binary>>, acc), do: escape(rest, ["\\n" | acc])
  defp escape(<<?\f, rest::binary>>, acc), do: escape(rest, ["\\f" | acc])
  defp escape(<<?\r, rest::binary>>, acc), do: escape(rest, ["\\r" | acc])

  defp escape(<<c, rest::binary>>, acc) when c < 0x20,
    do: escape(rest, ["\\u00" <> hex(c >>> 4) <> hex(c &&& 0xF) | acc])

  # Bytes >= 0x80 belong to multi-byte UTF-8 sequences and are copied verbatim.
  defp escape(<<c, rest::binary>>, acc), do: escape(rest, [c | acc])

  defp hex(n), do: binary_part("0123456789abcdef", n, 1)
end
