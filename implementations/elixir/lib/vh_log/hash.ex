defmodule VHLog.Hash do
  @moduledoc """
  SHA-256 multihashes, the only hash `vh-log:1.0` permits (profile §1).

  `b58/1` computes `base58btc(0x12 0x20 ‖ SHA-256(data))`, the encoding of
  SCIDs, entry hashes and pre-rotation key hashes.
  """

  alias VHLog.Base58

  @sha256 0x12
  @length 32

  @doc "Raw SHA-256 digest."
  @spec sha256(iodata()) :: <<_::256>>
  def sha256(data), do: :crypto.hash(:sha256, data)

  @doc """
  `base58btc(multihash(SHA-256(data)))`.

      iex> VHLog.Hash.b58("abc")
      "QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY"
  """
  @spec b58(iodata()) :: String.t()
  def b58(data), do: Base58.encode(<<@sha256, @length>> <> sha256(data))

  @doc """
  Pre-rotation key hash: the multikey *string* is hashed.
  """
  @spec key_hash(String.t()) :: String.t()
  def key_hash(multikey), do: b58(multikey)

  @doc """
  Classifies a string as a base58btc SHA-256 multihash (`:ok`), some other
  multihash or byte string (`:unsupported_algorithm`), or not base58btc at
  all (`:not_base58`).
  """
  @spec check_sha256(String.t()) :: :ok | :not_base58 | :unsupported_algorithm
  def check_sha256(value) when is_binary(value) do
    case Base58.decode(value) do
      {:ok, <<@sha256, @length, _::binary-size(@length)>>} -> :ok
      {:ok, <<_, _::binary>>} -> :unsupported_algorithm
      _ -> :not_base58
    end
  end

  def check_sha256(_), do: :not_base58
end
