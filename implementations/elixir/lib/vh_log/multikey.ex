defmodule VHLog.Multikey do
  @moduledoc """
  Ed25519 keys as multikeys: `"z" <> base58btc(0xed 0x01 ‖ public_key)`,
  which always start with `z6Mk` (profile §1). Keys are derived from 32-byte
  seeds (RFC 8032 §5.1.5) with `:crypto`.
  """

  alias VHLog.Base58

  @prefix <<0xED, 0x01>>

  @typedoc "An Ed25519 key pair derived from a seed."
  @type keypair :: %{multikey: String.t(), public: <<_::256>>, private: <<_::256>>}

  @doc """
  Encodes a raw 32-byte Ed25519 public key.
  """
  @spec from_public_key(<<_::256>>) :: String.t()
  def from_public_key(<<_::binary-size(32)>> = public),
    do: "z" <> Base58.encode(@prefix <> public)

  @doc """
  Decodes an Ed25519 multikey to the raw public key.

      iex> {:ok, key} = VHLog.Multikey.to_public_key("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
      iex> byte_size(key)
      32
      iex> VHLog.Multikey.to_public_key("zQm")
      :error
  """
  @spec to_public_key(term()) :: {:ok, <<_::256>>} | :error
  def to_public_key("z" <> encoded) do
    case Base58.decode(encoded) do
      {:ok, <<0xED, 0x01, public::binary-size(32)>>} -> {:ok, public}
      _ -> :error
    end
  end

  def to_public_key(_), do: :error

  @doc "True if `value` is an Ed25519 multikey."
  @spec valid?(term()) :: boolean()
  def valid?(value), do: match?({:ok, _}, to_public_key(value))

  @doc """
  Derives a key pair from a hex-encoded 32-byte seed. Raises `ArgumentError`
  for anything else.

      iex> VHLog.Multikey.from_seed(String.duplicate("00", 32)).multikey
      "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
  """
  @spec from_seed(String.t()) :: keypair()
  def from_seed(seed) do
    seed = seed_bytes(seed)
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    %{multikey: from_public_key(public), public: public, private: private}
  end

  @doc "Signs `message` with Ed25519."
  @spec sign(keypair(), iodata()) :: <<_::512>>
  def sign(%{private: private}, message),
    do: :crypto.sign(:eddsa, :none, message, [private, :ed25519])

  @doc "Verifies an Ed25519 signature; never raises."
  @spec verify(binary(), iodata(), binary()) :: boolean()
  def verify(<<_::binary-size(32)>> = public, message, <<_::binary-size(64)>> = signature) do
    :crypto.verify(:eddsa, :none, message, signature, [public, :ed25519])
  rescue
    _ -> false
  end

  def verify(_public, _message, _signature), do: false

  defp seed_bytes(<<_::binary-size(64)>> = hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, seed} -> seed
      :error -> raise ArgumentError, "invalid hex seed: #{hex}"
    end
  end

  defp seed_bytes(other),
    do: raise(ArgumentError, "Ed25519 seed must be 32 bytes of hex, got #{inspect(other)}")
end
