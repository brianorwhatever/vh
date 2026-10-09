defmodule VHLog.PrimitivesTest do
  use ExUnit.Case, async: true

  alias VHLog.{Base58, Hash, JCS, JSON, Log, Multikey, Proof}
  import VHLog.TestVectors, only: [same?: 2]

  @vectors VHLog.TestVectors.load("primitives.json")

  describe "JCS" do
    for {c, i} <- Enum.with_index(@vectors["jcs"]) do
      test "vector #{i}" do
        c = unquote(Macro.escape(c))
        assert JCS.canonicalize_text(c["text"]) == {:ok, c["output"]}
      end
    end

    test "numbers follow ECMAScript Number::toString" do
      cases = [
        {1.0e21, "1e+21"},
        {1.0e20, "100000000000000000000"},
        {1.0e-7, "1e-7"},
        {1.0e-6, "0.000001"},
        {-0.0, "0"},
        {-1.5, "-1.5"},
        {123_456_789_012_345_678, "123456789012345680"},
        {5.0e-324, "5e-324"},
        {1.7976931348623157e308, "1.7976931348623157e+308"}
      ]

      for {n, s} <- cases, do: assert(JCS.number(n) == s, "#{inspect(n)}")
    end

    test "keys sort by UTF-16 code units, not UTF-8 bytes" do
      # U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16.
      assert JCS.canonicalize(%{"\u{FB33}" => 1, "\u{1F600}" => 2}) ==
               ~s({"\u{1F600}":2,"\u{FB33}":1})
    end

    test "JSON numbers decode as doubles and duplicate keys keep the last value" do
      assert JSON.decode(~s({"n": 9007199254740993, "f": 1.0, "n": 2})) ==
               {:ok, %{"n" => 2, "f" => 1}}

      assert JSON.decode("[1] x") == {:error, :trailing_data}
    end
  end

  test "base58 round-trips, including leading zeros" do
    for bytes <- [<<>>, <<0>>, <<0, 0, 255>>, :crypto.strong_rand_bytes(34)] do
      assert Base58.decode(Base58.encode(bytes)) == {:ok, bytes}
    end
  end

  test "hash" do
    for c <- @vectors["hash"], do: assert(Hash.b58(c["data"]) == c["output"])
  end

  test "multikey" do
    for c <- @vectors["multikey"],
        do: assert(Multikey.from_seed(c["seed"]).multikey == c["multikey"])
  end

  test "key hash" do
    for c <- @vectors["keyHash"], do: assert(Hash.key_hash(c["multikey"]) == c["output"])
  end

  test "SHA-256 multihash classification" do
    assert Hash.check_sha256(Hash.b58("x")) == :ok

    assert Hash.check_sha256(Base58.encode(<<0x13, 0x40>> <> :binary.copy(<<1>>, 64))) ==
             :unsupported_algorithm

    assert Hash.check_sha256("0OIl") == :not_base58
    assert Hash.check_sha256("") == :not_base58
  end

  test "SCID" do
    for c <- @vectors["scid"], do: assert(Log.scid(c["entry"]) == c["scid"])
  end

  test "entry hash" do
    for c <- @vectors["entryHash"],
        do: assert(Log.entry_hash(c["entry"], c["previousVersionId"]) == c["hash"])
  end

  describe "eddsa-jcs-2022" do
    for {c, i} <- Enum.with_index(@vectors["sign"]) do
      test "sign and verify vector #{i}" do
        c = unquote(Macro.escape(c))
        opts = if c["created"], do: [created: c["created"]], else: []
        proof = Proof.create(c["document"], c["seed"], opts)
        assert same?(proof, c["proof"])
        assert Proof.verify(c["document"], c["proof"])
        refute Proof.verify(Map.put(c["document"], "extra", 1), c["proof"])
      end
    end

    test "rejects malformed proofs" do
      [c | _] = @vectors["sign"]
      proof = c["proof"]

      for {key, value} <- [
            {"type", "Other"},
            {"cryptosuite", "eddsa-rdfc-2022"},
            {"proofPurpose", "authentication"},
            {"proofValue", "not-multibase"},
            {"proofValue", "z0OIl"},
            {"verificationMethod", "did:key:z6Mk#other"}
          ] do
        refute Proof.verify(c["document"], Map.put(proof, key, value)), "#{key}=#{value}"
      end

      refute Proof.verify(c["document"], Map.delete(proof, "proofPurpose"))
      refute Proof.verify(c["document"], "not a proof")
    end
  end
end
