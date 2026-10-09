defmodule VHLog.Verifier do
  @moduledoc """
  Verifies a whole log: the per-entry checks of profile §4 as a fold over
  the lines, then witness verification over the valid prefix.

  Each entry runs the checks in the profile's order — the first failing
  check gives the error code:

  1. no earlier deactivating entry (`entry-after-deactivation`)
  2. structure (`invalid-entry`)
  3. parameters (`invalid-parameter`, `unsupported-log-version`,
     `prerotation-violation`)
  4. proofs (`invalid-proof`, `unauthorized-key`)
  5. `versionId` (`invalid-version-id`, `invalid-hash-algorithm`,
     `entry-hash-mismatch`)
  6. `versionTime` (`invalid-version-time`, `future-version-time`)
  7. entry 1 only: SCID (`invalid-hash-algorithm`, `scid-mismatch`)
  """

  alias VHLog.{Error, Hash, JSON, Log, Parameters, Proof, VersionTime}

  @future_tolerance 300
  @entry_keys ~w(versionId versionTime parameters state proof)

  defmodule Entry do
    @moduledoc "An entry that passed every per-entry check."
    @type t :: %__MODULE__{
            entry: map(),
            version_number: pos_integer(),
            time: integer(),
            parameters: VHLog.Parameters.t(),
            witness_rule: VHLog.Parameters.witness_config() | nil
          }
    @enforce_keys [:entry, :version_number, :time, :parameters, :witness_rule]
    defstruct @enforce_keys
  end

  defmodule Result do
    @moduledoc """
    The outcome of verifying a log: the valid (and witnessed) prefix
    `entries`, the raw `lines` (for copy comparison) and the first `failure`.
    """
    @type t :: %__MODULE__{
            entries: [VHLog.Verifier.Entry.t()],
            lines: [String.t()],
            failure: VHLog.Error.t() | nil
          }
    defstruct entries: [], lines: [], failure: nil

    @doc "True when every line is a valid, witnessed entry."
    @spec fully_valid?(t()) :: boolean()
    def fully_valid?(%__MODULE__{failure: nil, entries: e, lines: l}), do: length(e) == length(l)
    def fully_valid?(%__MODULE__{}), do: false
  end

  @doc """
  The future tolerance for `versionTime`, in seconds.
  """
  @spec future_tolerance() :: pos_integer()
  def future_tolerance, do: @future_tolerance

  @doc """
  Verifies `log` (JSON Lines text) against `witness` (the decoded witness
  file, or `:absent`) at Unix time `now`.
  """
  @spec verify_log(String.t(), term(), integer()) :: Result.t()
  def verify_log(log, witness, now) do
    case Log.lines(log) do
      [] ->
        %Result{failure: Error.new(:invalid_log, "log is empty")}

      lines ->
        {entries, failure} =
          lines
          |> Enum.with_index(1)
          |> Enum.reduce_while({[], nil}, fn {line, n}, {acc, nil} ->
            with {:ok, raw} <- parse_line(line, n),
                 {:ok, verified} <- verify_entry(raw, List.first(acc), now) do
              {:cont, {[verified | acc], nil}}
            else
              {:error, error} -> {:halt, {acc, error}}
            end
          end)

        entries = Enum.reverse(entries)

        case check_witnesses(entries, witness) do
          :ok ->
            %Result{entries: entries, lines: lines, failure: failure}

          {:error, index, error} ->
            %Result{entries: Enum.take(entries, index), lines: lines, failure: error}
        end
    end
  end

  defp parse_line(line, n) do
    case JSON.decode(line) do
      {:ok, %{} = raw} -> {:ok, raw}
      {:ok, _} -> {:error, Error.new(:invalid_log, "line #{n} is not a JSON object", n)}
      {:error, _} -> {:error, Error.new(:invalid_log, "line #{n} is not JSON", n)}
    end
  end

  @doc """
  Runs the per-entry checks on one parsed line, given the previous verified
  entry (`nil` for the first).
  """
  @spec verify_entry(map(), Entry.t() | nil, integer()) :: {:ok, Entry.t()} | {:error, Error.t()}
  def verify_entry(raw, previous, now) do
    version = if previous, do: previous.version_number + 1, else: 1

    with :ok <- check_not_deactivated(previous, version),
         :ok <- check_structure(raw, version),
         {:ok, params} <-
           Parameters.apply(raw["parameters"], previous && previous.parameters, version),
         {active_keys, witness_rule} = authority(raw, params, previous),
         :ok <- verify_proofs(raw, active_keys, version),
         :ok <- verify_version_id(raw, version, previous_version_id(previous, params)),
         {:ok, time} <- verify_version_time(raw["versionTime"], previous, now, version),
         :ok <- verify_scid(raw, params, previous) do
      {:ok,
       %Entry{
         entry: raw,
         version_number: version,
         time: time,
         parameters: params,
         witness_rule: witness_rule
       }}
    end
  end

  defp check_not_deactivated(%Entry{parameters: %Parameters{deactivated: true}}, version),
    do:
      {:error,
       Error.new(:entry_after_deactivation, "entry follows a deactivating entry", version)}

  defp check_not_deactivated(_previous, _version), do: :ok

  defp check_structure(
         %{
           "versionId" => version_id,
           "versionTime" => version_time,
           "parameters" => %{},
           "state" => %{},
           "proof" => proof
         } = raw,
         _version
       )
       when map_size(raw) == length(@entry_keys) and is_binary(version_id) and
              is_binary(version_time) and
              is_list(proof),
       do: :ok

  defp check_structure(_raw, version),
    do:
      {:error,
       Error.new(:invalid_entry, "entry does not have the required properties and types", version)}

  # Which keys may sign this entry, and which witness list it must satisfy
  # (profile §3).
  defp authority(_raw, params, nil), do: {params.update_keys, params.witness}

  defp authority(raw, params, %Entry{parameters: prev}) do
    keys = if prev.next_key_hashes != [], do: params.update_keys, else: prev.update_keys
    enables = Map.has_key?(raw["parameters"], "witness") and prev.witness == nil
    {keys, if(enables, do: params.witness, else: prev.witness)}
  end

  defp previous_version_id(nil, params), do: params.scid
  defp previous_version_id(%Entry{entry: entry}, _params), do: entry["versionId"]

  defp verify_proofs(%{"proof" => []}, _keys, version),
    do: {:error, Error.new(:invalid_proof, "proof array is empty", version)}

  defp verify_proofs(%{"proof" => proofs} = entry, keys, version) do
    document = Map.delete(entry, "proof")

    Enum.reduce_while(proofs, :ok, fn proof, :ok ->
      case check_proof(document, proof, keys, version) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp check_proof(document, proof, keys, version) do
    vm = if is_map(proof), do: proof["verificationMethod"]

    with {:vm, {:ok, multikey}} <- {:vm, Proof.multikey_from_verification_method(vm)},
         {:key, true} <- {:key, multikey in keys},
         {:sig, true} <- {:sig, Proof.verify(document, proof)} do
      :ok
    else
      {:vm, :error} ->
        {:error,
         Error.new(:invalid_proof, "proof verificationMethod is not did:key:<mk>#<mk>", version)}

      {:key, false} ->
        {:error, Error.new(:unauthorized_key, "#{vm} is not an active update key", version)}

      {:sig, false} ->
        {:error, Error.new(:invalid_proof, "proof failed verification", version)}
    end
  end

  defp verify_version_id(entry, expected, previous_version_id) do
    version_id = entry["versionId"]

    with {:format, [_, number, hash]} <-
           {:format, Regex.run(~r/\A([1-9][0-9]*)-([^-]+)\z/, version_id)},
         {:format, ^expected} <- {:format, String.to_integer(number)},
         {:hash, :ok} <- {:hash, Hash.check_sha256(hash)},
         {:match, true} <- {:match, Log.entry_hash(entry, previous_version_id) == hash} do
      :ok
    else
      {:format, _} ->
        {:error,
         Error.new(
           :invalid_version_id,
           "expected versionId #{expected}-<hash>, got #{version_id}",
           expected
         )}

      {:hash, :not_base58} ->
        {:error, Error.new(:invalid_version_id, "entry hash is not base58btc", expected)}

      {:hash, :unsupported_algorithm} ->
        {:error,
         Error.new(:invalid_hash_algorithm, "entry hash is not a SHA-256 multihash", expected)}

      {:match, false} ->
        {:error, Error.new(:entry_hash_mismatch, "entry hash does not match", expected)}
    end
  end

  defp verify_version_time(value, previous, now, version) do
    case VersionTime.parse(value) do
      :error ->
        {:error, Error.new(:invalid_version_time, "invalid versionTime #{value}", version)}

      {:ok, time} when previous != nil and time <= previous.time ->
        {:error,
         Error.new(
           :invalid_version_time,
           "versionTime must be later than the previous entry's",
           version
         )}

      {:ok, time} when time > now + @future_tolerance ->
        {:error, Error.new(:future_version_time, "versionTime is in the future", version)}

      {:ok, time} ->
        {:ok, time}
    end
  end

  # SCID verification (Read step 5): textually replace the SCID with the
  # placeholder in the serialised entry and recompute.
  defp verify_scid(_entry, _params, %Entry{}), do: :ok

  defp verify_scid(entry, %Parameters{scid: scid}, nil) do
    placeholder = Log.scid_placeholder()

    case Hash.check_sha256(scid) do
      :unsupported_algorithm ->
        {:error, Error.new(:invalid_hash_algorithm, "SCID is not a SHA-256 multihash", 1)}

      :not_base58 ->
        {:error, Error.new(:scid_mismatch, "SCID is not base58btc", 1)}

      :ok ->
        preliminary =
          entry
          |> Map.delete("proof")
          |> Map.put("versionId", placeholder)
          |> Log.replace_text(scid, placeholder)

        if Log.scid(preliminary) == scid,
          do: :ok,
          else: {:error, Error.new(:scid_mismatch, "SCID does not match", 1)}
    end
  end

  # ---------------------------------------------------------------- witnesses

  # Verifying Witness Proofs During Resolution: returns the index of the first
  # entry that is not witnessed, with the error.
  defp check_witnesses(entries, witness) do
    case Enum.find_index(entries, &(&1.witness_rule != nil)) do
      nil ->
        :ok

      first ->
        case witness_file(witness) do
          {:ok, file} ->
            approvals = approvals(entries, file)

            entries
            |> Enum.with_index()
            |> Enum.drop(first)
            |> Enum.find_value(:ok, fn {entry, i} -> unwitnessed(entry, i, approvals) end)

          :error ->
            {:error, first,
             Error.new(:invalid_witness_file, "witness file is malformed", first + 1)}
        end
    end
  end

  defp witness_file(:absent), do: {:ok, []}

  defp witness_file(file) when is_list(file) do
    if Enum.all?(
         file,
         &match?(%{"versionId" => v, "proof" => p} when is_binary(v) and is_list(p), &1)
       ),
       do: {:ok, file},
       else: :error
  end

  defp witness_file(_), do: :error

  # Every attributable witness proof for a versionId in the log, in file
  # order. A proof for entry j approves every entry <= j. Signatures are
  # checked lazily (see `unwitnessed/3`).
  defp approvals(entries, file) do
    position = entries |> Enum.with_index() |> Map.new(fn {e, i} -> {e.entry["versionId"], i} end)

    for %{"versionId" => version_id, "proof" => proofs} <- file,
        index = Map.get(position, version_id),
        index != nil,
        proof <- proofs,
        vm = if(is_map(proof), do: proof["verificationMethod"]),
        {:ok, multikey} <- [Proof.multikey_from_verification_method(vm)] do
      %{
        id: :unicode.characters_to_nfc_binary("did:key:" <> multikey),
        index: index,
        proof: proof,
        version_id: version_id
      }
    end
  end

  defp unwitnessed(%Entry{witness_rule: nil}, _i, _approvals), do: nil

  defp unwitnessed(%Entry{witness_rule: rule}, i, approvals) do
    ids = MapSet.new(rule["witnesses"], &:unicode.characters_to_nfc_binary(&1["id"]))
    threshold = rule["threshold"]

    approved =
      Enum.reduce(approvals, MapSet.new(), fn a, approved ->
        if a.index >= i and MapSet.member?(ids, a.id) and not MapSet.member?(approved, a.id) and
             Proof.verify(%{"versionId" => a.version_id}, a.proof),
           do: MapSet.put(approved, a.id),
           else: approved
      end)

    count = MapSet.size(approved)

    if count < threshold do
      message = "entry #{i + 1} has #{count} of #{threshold} required witness approvals"
      {:error, i, Error.new(:witness_threshold_not_met, message, i + 1)}
    end
  end
end
