defmodule VHLog.LogTest do
  use ExUnit.Case, async: true

  alias VHLog.{Error, Hash, JSON, Multikey}
  import VHLog.TestVectors, only: [same?: 2]

  @k1 "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
  @k2 "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6"
  @w1 "b2f56f12a0b0513455e61f01bb11b5af580fdf1bd4ea1b560bc4bf96ee1e0162"
  @now "2026-06-01T00:00:00Z"

  defp mk(seed), do: Multikey.from_seed(seed).multikey

  defp genesis(parameters \\ %{}) do
    {:ok, created} =
      VHLog.create(
        state: %{"id" => "example:{SCID}"},
        parameters: Map.merge(%{"updateKeys" => [mk(@k1)]}, parameters),
        version_time: "2026-01-01T00:00:00Z",
        signers: [@k1]
      )

    created
  end

  defp update(log, day, opts \\ []) do
    {:ok, %{log: log}} =
      VHLog.update(
        log,
        Keyword.merge(
          [state: %{"day" => day}, version_time: "2026-01-0#{day}T00:00:00Z", signers: [@k1]],
          opts
        )
      )

    log
  end

  describe "generation vectors" do
    for sc <- VHLog.TestVectors.load("generation.json")["scenarios"] do
      test sc["name"] do
        sc = unquote(Macro.escape(sc))

        {log, _scid, ids} =
          Enum.reduce(sc["steps"], {"", nil, []}, fn step, {log, scid, ids} ->
            input = step["input"]

            {log, scid, id} =
              case step["op"] do
                "create" ->
                  {:ok, r} =
                    VHLog.create(
                      state: input["state"],
                      parameters: input["parameters"],
                      version_time: input["versionTime"],
                      signers: input["signers"]
                    )

                  assert r.scid == step["expect"]["scid"]
                  {r.log, r.scid, r.version_id}

                "update" ->
                  input =
                    input |> JSON.encode!() |> String.replace("{SCID}", scid) |> JSON.decode!()

                  {:ok, r} =
                    VHLog.update(log,
                      state: input["state"],
                      parameters: input["parameters"] || %{},
                      version_time: input["versionTime"],
                      signers: input["signers"]
                    )

                  {r.log, scid, r.version_id}
              end

            assert id == step["expect"]["versionId"]

            assert same?(
                     log |> String.split("\n", trim: true) |> List.last() |> JSON.decode!(),
                     step["expect"]["line"]
                   )

            {log, scid, ids ++ [id]}
          end)

        witness =
          for w <- sc["witness"] || [] do
            id = Enum.at(ids, w["step"] - 1)
            %{"versionId" => id, "proof" => Enum.map(w["seeds"], &VHLog.witness_proof(id, &1))}
          end

        if sc["witness"], do: assert(same?(witness, sc["witnessFile"]))

        opts = [now: sc["resolve"]["now"]] ++ if(sc["witness"], do: [witness: witness], else: [])
        assert {:ok, resolution} = VHLog.resolve(log, opts)
        assert resolution.error == nil
        assert same?(resolution.state, sc["resolve"]["state"])
        assert resolution.metadata["versionId"] == sc["resolve"]["versionId"]
      end
    end
  end

  test "create, update and resolve" do
    %{log: log, scid: scid, version_id: v1} = genesis()
    assert String.starts_with?(scid, "Qm")
    assert v1 =~ ~r/\A1-Qm/

    log = log |> update(2) |> update(3)
    assert {:ok, entries} = VHLog.verify(log, now: @now)
    assert length(entries) == 3

    assert {:ok, r} = VHLog.resolve(log, now: @now)
    assert r.state == %{"day" => 3}
    assert r.metadata["versionNumber"] == 3
    assert r.metadata["scid"] == scid
    assert r.metadata["created"] == "2026-01-01T00:00:00Z"
    assert r.metadata["updated"] == "2026-01-03T00:00:00Z"

    assert {:ok, %{state: %{"id" => "example:" <> ^scid}}} =
             VHLog.resolve(log, now: @now, version_id: v1)

    assert {:ok, %{state: %{"day" => 2}}} = VHLog.resolve(log, now: @now, version_number: 2)

    assert {:ok, %{state: %{"day" => 2}}} =
             VHLog.resolve(log, now: @now, version_time: "2026-01-02T12:00:00Z")

    assert {:error, %Error{code: :not_found}} = VHLog.resolve(log, now: @now, version_number: 4)

    assert {:error, %Error{code: :invalid_option}} =
             VHLog.resolve(log, now: @now, version_number: 1, version_id: v1)

    assert {:error, %Error{code: :invalid_option}} = VHLog.resolve(log, now: @now, bogus: 1)
  end

  test "a tampered later entry leaves the valid prefix resolvable" do
    log = genesis().log |> update(2) |> update(3)
    tampered = String.replace(log, ~s("day":3), ~s("day":4))

    assert {:ok, r} = VHLog.resolve(tampered, now: @now)
    assert r.state == %{"day" => 2}
    assert r.first_invalid_version == 3
    # Proofs are checked before the entry hash (profile §4).
    assert %Error{code: :invalid_proof, version: 3} = r.error
    assert [%{"code" => "invalid-entries"}] = r.metadata["warnings"]

    assert {:error, %Error{code: :invalid_proof}} =
             VHLog.resolve(tampered, now: @now, version_number: 3)

    assert {:error, %Error{code: :invalid_proof, version: 3}} = VHLog.verify(tampered, now: @now)
  end

  test "an unauthorised signer is rejected" do
    log = genesis().log

    {:ok, %{log: bad}} =
      VHLog.update(log, state: %{}, version_time: "2026-01-02T00:00:00Z", signers: [@k2])

    assert {:ok, %{error: %Error{code: :unauthorized_key, version: 2}}} =
             VHLog.resolve(bad, now: @now)
  end

  test "pre-rotation: the next key must be committed" do
    log = genesis(%{"nextKeyHashes" => [Hash.key_hash(mk(@k2))]}).log

    rotated =
      update(log, 2,
        parameters: %{"updateKeys" => [mk(@k2)], "nextKeyHashes" => []},
        signers: [@k2]
      )

    assert {:ok, %{error: nil, metadata: %{"updateKeys" => [_]}}} =
             VHLog.resolve(rotated, now: @now)

    bad = update(log, 2, parameters: %{"updateKeys" => [mk(@k1)], "nextKeyHashes" => []})
    assert {:ok, %{error: %Error{code: :prerotation_violation}}} = VHLog.resolve(bad, now: @now)
  end

  test "deactivation" do
    log = genesis().log |> update(2, parameters: %{"deactivated" => true})
    assert {:ok, %{metadata: %{"deactivated" => true}}} = VHLog.resolve(log, now: @now)

    assert {:ok, %{metadata: %{"deactivated" => true}}} =
             VHLog.resolve(log, now: @now, version_number: 1)

    after_deactivation = update(log, 3)

    assert {:ok, %{error: %Error{code: :entry_after_deactivation, version: 3}}} =
             VHLog.resolve(after_deactivation, now: @now)
  end

  test "witnessing" do
    witness = %{"threshold" => 1, "witnesses" => [%{"id" => "did:key:" <> mk(@w1)}]}
    %{log: log, version_id: v1} = genesis(%{"witness" => witness})

    assert {:error, %Error{code: :witness_threshold_not_met, version: 1}} =
             VHLog.resolve(log, now: @now)

    file = [%{"versionId" => v1, "proof" => [VHLog.witness_proof(v1, @w1)]}]
    assert {:ok, %{error: nil}} = VHLog.resolve(log, now: @now, witness: file)

    assert {:error, %Error{code: :invalid_witness_file}} =
             VHLog.resolve(log, now: @now, witness: %{})
  end

  test "copies: a diverging verified copy is a fork" do
    base = genesis().log
    a = update(base, 2)
    b = update(base, 2, state: %{"other" => true})

    assert {:ok, %{metadata: %{"copies" => [%{"status" => "current"}, %{"status" => "current"}]}}} =
             VHLog.resolve(a, now: @now, copies: [%{"source" => "https://w.example", "log" => a}])

    assert {:error, %Error{code: :fork_detected, fork: %{version: 2}}} =
             VHLog.resolve(a, now: @now, copies: [%{"source" => "https://w.example", "log" => b}])

    assert {:error, %Error{code: :min_copies_not_met}} =
             VHLog.resolve(a,
               now: @now,
               min_copies: 2,
               copies: [%{"source" => "https://w.example", "unavailable" => "timeout"}]
             )
  end

  test "error codes have wire names" do
    assert "witness-threshold-not-met" in Enum.map(Error.codes(), &Error.code_string/1)
    assert length(Error.codes()) == 20
  end
end
