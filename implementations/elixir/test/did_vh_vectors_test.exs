defmodule VHLog.DidVhVectorsTest do
  @moduledoc "Runs the vectors/didvh cases through `VHLog.DidVh` and the driver."
  use ExUnit.Case, async: true

  alias VHLog.Driver
  import VHLog.TestVectors, only: [same?: 2]

  for {file, op, field} <- [
        {"ref.json", "didvh-ref", "ref"},
        {"src.json", "didvh-src", "src"},
        {"did-url.json", "didvh-did-url", "didUrl"}
      ] do
    @external_resource Path.join([VHLog.TestVectors.dir(), "didvh", file])

    describe file do
      for c <- VHLog.TestVectors.load("didvh/#{file}")["cases"] do
        test c["name"] do
          c = unquote(Macro.escape(c))
          got = Driver.handle(unquote(op), %{unquote(field) => c[unquote(field)]})
          assert same?(got, c["expect"]), inspect(got)
        end
      end
    end
  end

  for file <-
        VHLog.TestVectors.dir()
        |> Path.join("didvh/resolution/*.json")
        |> Path.wildcard()
        |> Enum.sort() do
    group = Path.basename(file, ".json")
    @external_resource file

    describe "resolution/#{group}" do
      for c <- VHLog.TestVectors.load("didvh/resolution/#{group}.json")["cases"] do
        test c["name"] do
          c = unquote(Macro.escape(c))
          assert_matches(c["expect"], Driver.handle("didvh-resolve", c["input"]))
        end
      end
    end
  end

  # Mirrors compareDidResolution in harness/run.ts.
  defp assert_matches(expect, got) do
    meta = got["didResolutionMetadata"]

    if expect["error"] do
      assert meta["error"] == expect["error"], inspect(meta)

      if expect["vhLogError"],
        do: assert(meta["problemDetails"]["vhLog"]["code"] == expect["vhLogError"])

      assert got["didDocument"] == nil
    else
      assert meta["error"] == nil, inspect(meta)
      assert meta["contentType"] == "application/did+json"
      assert same?(got["didDocument"], expect["didDocument"])
      assert same?(got["didDocumentMetadata"], expect["didDocumentMetadata"])
      warnings = (meta["warnings"] || []) |> Enum.map(& &1["code"]) |> Enum.sort()
      assert warnings == (expect["warnings"] || [])

      for key <- ~w(didLog didWitness),
          do: assert(same?(meta[key], expect[key]), "didResolutionMetadata.#{key}")
    end
  end
end
