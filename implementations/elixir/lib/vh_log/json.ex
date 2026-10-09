defmodule VHLog.JSON do
  @moduledoc """
  JSON parsing and serialisation with JavaScript (I-JSON) semantics.

  RFC 8785 treats every JSON number as an IEEE-754 double, so `decode/1`
  reads every number as a double, then represents integral values in the safe
  integer range (|n| < 2^53) as Elixir integers and everything else as floats.
  `123456789012345678` therefore decodes to `1.2345678901234568e17`, `1.0` to
  `1` and `-0` to `0`. Duplicate object keys keep the last value, as
  `JSON.parse` does.

  Built on Elixir's standard-library `JSON` (OTP's `:json`).
  """

  @typedoc "A decoded JSON value."
  @type value :: nil | boolean() | number() | String.t() | [value()] | %{String.t() => value()}

  @max_safe 9_007_199_254_740_992

  @decoders [
    integer: &__MODULE__.number/1,
    float: &__MODULE__.number/1,
    object_finish: &__MODULE__.object_finish/2
  ]

  @doc """
  Parses a complete JSON text.

      iex> VHLog.JSON.decode(~s({"a": 1.0, "b": 123456789012345678, "a": 2}))
      {:ok, %{"a" => 2, "b" => 1.2345678901234568e17}}
  """
  @spec decode(binary()) :: {:ok, value()} | {:error, term()}
  def decode(text) when is_binary(text) do
    case JSON.decode(text, :ok, @decoders) do
      {value, :ok, rest} ->
        if whitespace?(rest), do: {:ok, value}, else: {:error, :trailing_data}

      {:error, _} = error ->
        error
    end
  rescue
    e -> {:error, e}
  end

  def decode(_), do: {:error, :not_a_string}

  @doc """
  Parses JSON text as ECMAScript's `JSON.parse` would, accepting what
  `decode/1` rejects as not I-JSON-safe: a lone surrogate escape becomes
  U+FFFD and a number beyond the double range becomes `nil`. Used only to
  read `versionId`/`versionTime` from lines that may be invalid.
  """
  @spec decode_lenient(binary()) :: {:ok, value()} | {:error, term()}
  def decode_lenient(text) when is_binary(text) do
    decoders =
      Keyword.put(@decoders, :float, &lenient_number/1)
      |> Keyword.put(:integer, &lenient_number/1)

    case JSON.decode(replace_lone_surrogates(text), :ok, decoders) do
      {value, :ok, rest} -> if whitespace?(rest), do: {:ok, value}, else: {:error, :trailing_data}
      {:error, _} = error -> error
    end
  rescue
    e -> {:error, e}
  end

  def decode_lenient(_), do: {:error, :not_a_string}

  @doc false
  def lenient_number(text) do
    number(text)
  rescue
    ArgumentError -> nil
  end

  # Rewrites `\uD800`-style escapes that are not part of a surrogate pair to
  # `\uFFFD`, leaving everything else byte-for-byte.
  defp replace_lone_surrogates(text), do: scan(text, false, []) |> IO.iodata_to_binary()

  defp scan(<<>>, _in_string, acc), do: Enum.reverse(acc)
  defp scan(<<?", rest::binary>>, in_string, acc), do: scan(rest, not in_string, [?" | acc])

  defp scan(<<?\\, ?u, a::binary-size(4), ?\\, ?u, b::binary-size(4), rest::binary>>, true, acc) do
    case {surrogate(a), surrogate(b)} do
      {:high, :low} -> scan(rest, true, ["\\u" <> b, "\\u" <> a | acc])
      {:none, _} -> scan(<<?\\, ?u, b::binary, rest::binary>>, true, ["\\u" <> a | acc])
      _ -> scan(<<?\\, ?u, b::binary, rest::binary>>, true, ["\\uFFFD" | acc])
    end
  end

  defp scan(<<?\\, ?u, a::binary-size(4), rest::binary>>, true, acc) do
    escape = if surrogate(a) == :none, do: "\\u" <> a, else: "\\uFFFD"
    scan(rest, true, [escape | acc])
  end

  defp scan(<<?\\, c, rest::binary>>, true, acc), do: scan(rest, true, [c, ?\\ | acc])
  defp scan(<<c, rest::binary>>, in_string, acc), do: scan(rest, in_string, [c | acc])

  defp surrogate(hex) do
    case Integer.parse(hex, 16) do
      {n, ""} when n in 0xD800..0xDBFF -> :high
      {n, ""} when n in 0xDC00..0xDFFF -> :low
      _ -> :none
    end
  end

  @doc "Like `decode/1` but raises `ArgumentError` on invalid JSON."
  @spec decode!(binary()) :: value()
  def decode!(text) do
    case decode(text) do
      {:ok, value} -> value
      {:error, reason} -> raise ArgumentError, "invalid JSON: #{inspect(reason)}"
    end
  end

  @doc "Serialises a value as compact JSON."
  @spec encode!(value()) :: String.t()
  def encode!(value), do: JSON.encode!(value)

  @doc false
  # Number decoder: the text is read as a double (correctly rounded by strtod).
  @spec number(binary()) :: number()
  def number(text) do
    text
    |> float_text()
    |> :erlang.binary_to_float()
    |> normalize()
  end

  @doc """
  Normalises a number to the representation `decode/1` produces: integral
  doubles below 2^53 become integers, everything else a float.
  """
  @spec normalize(number()) :: number()
  def normalize(n) when is_integer(n) and abs(n) < @max_safe, do: n
  def normalize(n) when is_integer(n), do: normalize(:erlang.float(n))

  def normalize(f) when is_float(f) do
    if abs(f) < @max_safe and trunc(f) == f, do: trunc(f), else: f
  end

  @doc false
  # Keep the last value for a duplicated key (the accumulator is newest-first).
  def object_finish(acc, old_acc), do: {acc |> Enum.reverse() |> Map.new(), old_acc}

  # `binary_to_float/1` needs a fraction: "1E30" -> "1.0E30", "-0" -> "-0.0".
  defp float_text(text) do
    if String.contains?(text, ".") do
      text
    else
      case :binary.match(text, ["e", "E"]) do
        {pos, _} ->
          binary_part(text, 0, pos) <> ".0" <> binary_part(text, pos, byte_size(text) - pos)

        :nomatch ->
          text <> ".0"
      end
    end
  end

  defp whitespace?(<<>>), do: true
  defp whitespace?(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: whitespace?(rest)
  defp whitespace?(_), do: false
end
