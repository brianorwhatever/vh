defmodule VHLog.RulesTest do
  @moduledoc "Profile rules consolidated after the first interop round."
  use ExUnit.Case, async: true

  alias VHLog.{Error, JSON, Multikey, URL, VersionTime}

  @k1 "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
  @now "2026-06-01T00:00:00Z"

  describe "versionTime" do
    test "every four-digit year is valid, with proleptic Gregorian leap years" do
      for t <-
            ~w(0000-01-01T00:00:00Z 0001-12-31T23:59:59Z 0099-06-15T12:00:00+00:00
                  0000-02-29T00:00:00Z 2000-02-29T00:00:00Z 2024-02-29T00:00:00Z 9999-12-31T23:59:59Z) do
        assert VersionTime.valid?(t), t
      end

      assert {:ok, a} = VersionTime.parse("0099-12-31T23:59:59Z")
      assert {:ok, b} = VersionTime.parse("0100-01-01T00:00:00Z")
      assert b - a == 1
    end

    test "rejects impossible dates, times and zones" do
      for t <-
            ~w(1900-02-29T00:00:00Z 2023-02-29T00:00:00Z 2026-00-01T00:00:00Z 2026-13-01T00:00:00Z
                  2026-04-31T00:00:00Z 2026-01-00T00:00:00Z 2026-01-01T24:00:00Z 2026-01-01T23:60:00Z
                  2026-01-01T23:59:60Z 2026-01-01T00:00:00z 2026-01-01T00:00:00-00:00
                  2026-01-01T00:00:00.5Z 2026-01-01T00:00:00) ++
              ["2026-01-01T00:00:00Z\n", " 2026-01-01T00:00:00Z", "２026-01-01T00:00:00Z"] do
        refute VersionTime.valid?(t), inspect(t)
      end
    end
  end

  describe "watcher URLs" do
    test "accepts lowercase http(s) URLs of printable ASCII with an authority" do
      for u <-
            ~w(https://w.example http://w.example:8080/a?b#c https://user@w.example https://[::1]/x https://w.example/%20) do
        assert URL.valid?(u), u
      end
    end

    test "rejects everything else" do
      for u <- [
            "ftp://w.example",
            "HTTPS://w.example",
            "Http://w.example",
            "https:///log",
            "https://?q",
            "https://#f",
            "https://",
            "https:w.example",
            "https://w.example/a b",
            "https://wätcher.example",
            "https://w.example/\t",
            "https://w.example\u007f",
            "//w.example",
            "",
            42
          ] do
        refute URL.valid?(u), inspect(u)
      end
    end

    test "an invalid watcher URL fails the entry with invalid-parameter" do
      key = Multikey.from_seed(@k1).multikey

      {:ok, %{log: log}} =
        VHLog.create(
          state: %{},
          parameters: %{"updateKeys" => [key], "watchers" => ["ftp://w.example"]},
          version_time: "2026-01-01T00:00:00Z",
          signers: [@k1]
        )

      assert {:error, %Error{code: :invalid_parameter, version: 1}} =
               VHLog.resolve(log, now: @now)
    end
  end

  describe "I-JSON-safe log lines" do
    setup do
      key = Multikey.from_seed(@k1).multikey

      {:ok, %{log: log}} =
        VHLog.create(
          state: %{},
          parameters: %{"updateKeys" => [key]},
          version_time: "2026-01-01T00:00:00Z",
          signers: [@k1]
        )

      %{log: log}
    end

    test "decode/1 rejects non-finite numbers and lone surrogates" do
      for text <- [
            ~S([1e400]),
            ~S([-1e400]),
            ~S(["\ud800"]),
            ~S(["\udc00"]),
            ~S(["\ud800A"]),
            ~S({"\ud83d":1})
          ] do
        assert {:error, _} = JSON.decode(text), text
      end

      assert JSON.decode(~S(["😀", 1e308])) == {:ok, ["\u{1F600}", 1.0e308]}
      assert JSON.decode(~S({"a":1,"a":2})) == {:ok, %{"a" => 2}}
    end

    test "an unsafe line is invalid-log for that line", %{log: log} do
      for bad <- [
            ~S({"versionId":"2-x","n":1e400}),
            ~S({"versionId":"2-x","s":"\udfff"}),
            ~S({"\ud800":1})
          ] do
        assert {:ok, %{first_invalid_version: 2, error: %Error{code: :invalid_log, version: 2}}} =
                 VHLog.resolve(log <> bad <> "\n", now: @now)
      end
    end

    test "decode_lenient/1 reads unsafe lines as JSON.parse does" do
      assert {:ok, %{"versionId" => "2-x", "s" => "\u{FFFD}", "n" => nil, "e" => "\\ud800"}} =
               JSON.decode_lenient(~S({"versionId":"2-x","s":"\ud800","n":1e400,"e":"\\ud800"}))
    end
  end

  describe "witness file" do
    setup do
      key = Multikey.from_seed(@k1).multikey
      witness = %{"threshold" => 1, "witnesses" => [%{"id" => "did:key:" <> key}]}

      {:ok, %{log: log}} =
        VHLog.create(
          state: %{},
          parameters: %{"updateKeys" => [key], "witness" => witness},
          version_time: "2026-01-01T00:00:00Z",
          signers: [@k1]
        )

      %{log: log}
    end

    test "explicit null is malformed; omitted means none found", %{log: log} do
      assert {:error, %Error{code: :invalid_witness_file}} =
               VHLog.resolve(log, now: @now, witness: nil)

      assert {:error, %Error{code: :witness_threshold_not_met}} = VHLog.resolve(log, now: @now)
    end
  end
end
