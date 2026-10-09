defmodule VHLog.ResolutionVectorsTest do
  @moduledoc "Runs every vectors/resolution case through `VHLog.Resolver`."
  use ExUnit.Case, async: true

  alias VHLog.{Resolution, Resolver}
  import VHLog.TestVectors, only: [same?: 2]

  for file <-
        VHLog.TestVectors.dir()
        |> Path.join("resolution/*.json")
        |> Path.wildcard()
        |> Enum.sort() do
    group = Path.basename(file, ".json")
    @external_resource file

    describe group do
      for c <- VHLog.TestVectors.load("resolution/#{group}.json")["cases"] do
        test c["name"] do
          c = unquote(Macro.escape(c))
          got = c["input"] |> Resolver.resolve() |> Resolution.to_json()
          assert_matches(c["expect"], got)
        end
      end
    end
  end

  # Mirrors compareResolution in harness/run.ts.
  defp assert_matches(expect, got) do
    assert got["valid"] == expect["valid"], inspect(got["error"])

    case expect["error"] do
      nil ->
        assert got["error"] == nil

      error ->
        assert got["error"]["code"] in (error["oneOf"] || [error["code"]])
        if Map.has_key?(error, "version"), do: assert(got["error"]["version"] == error["version"])
    end

    if expect["valid"] do
      assert same?(got["state"], expect["state"])
      assert got["firstInvalidVersion"] == expect["firstInvalidVersion"]

      assert got["metadata"]["warnings"] |> Enum.map(& &1["code"]) |> Enum.sort() ==
               (expect["warnings"] || [])

      for {k, v} <- expect["metadata"] || %{} do
        assert same?(got["metadata"][k], v), "metadata.#{k}: #{inspect(got["metadata"][k])}"
      end
    end
  end
end
