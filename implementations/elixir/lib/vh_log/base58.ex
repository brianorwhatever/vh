defmodule VHLog.Base58 do
  @moduledoc """
  base58btc (Bitcoin alphabet) without a multibase prefix.

  Each leading zero byte is written as `1`; the rest is the big-endian
  integer in base 58.
  """

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @values @alphabet |> Enum.with_index() |> Map.new()

  @doc """
  Encodes bytes.

      iex> VHLog.Base58.encode(<<0, 0, 1, 2>>)
      "115T"
  """
  @spec encode(binary()) :: String.t()
  def encode(bytes) when is_binary(bytes) do
    {zeros, rest} = split_leading(bytes, ?\0)
    ones = String.duplicate("1", zeros)

    case rest do
      <<>> -> ones
      _ -> ones <> digits(:binary.decode_unsigned(rest), [])
    end
  end

  for {char, value} <- Enum.with_index(@alphabet) do
    defp digit(unquote(value)), do: unquote(char)
  end

  defp digits(0, acc), do: List.to_string(acc)
  defp digits(n, acc), do: digits(div(n, 58), [digit(rem(n, 58)) | acc])

  @doc """
  Decodes a base58btc string; `:error` if it contains a non-alphabet character.

      iex> VHLog.Base58.decode("115T")
      {:ok, <<0, 0, 1, 2>>}
      iex> VHLog.Base58.decode("0OIl")
      :error
  """
  @spec decode(String.t()) :: {:ok, binary()} | :error
  def decode(string) when is_binary(string) do
    {zeros, rest} = split_leading(string, ?1)

    rest
    |> :binary.bin_to_list()
    |> Enum.reduce_while(0, fn char, acc ->
      case @values do
        %{^char => value} -> {:cont, acc * 58 + value}
        _ -> {:halt, :error}
      end
    end)
    |> case do
      :error -> :error
      0 -> {:ok, :binary.copy(<<0>>, zeros)}
      n -> {:ok, :binary.copy(<<0>>, zeros) <> :binary.encode_unsigned(n)}
    end
  end

  defp split_leading(bin, byte, count \\ 0)
  defp split_leading(<<b, rest::binary>>, b, count), do: split_leading(rest, b, count + 1)
  defp split_leading(rest, _byte, count), do: {count, rest}
end
