defmodule VHLog.Parameters do
  @moduledoc """
  The active parameters of a log, and the rules for applying an entry's
  `parameters` to them (spec *Read* step 1, plus the pre-rotation rule of step
  7, which only concerns parameters).

  Unknown parameters are ignored. `deactivated` is not inherited: it is
  `false` unless the entry sets it.
  """

  alias VHLog.{Error, Hash, Log, Multikey, URL}

  @supported_log_versions [Log.log_version()]
  @max_ttl 2_147_483_648

  @typedoc "A witness configuration: `threshold` and the original `witnesses` objects."
  @type witness_config :: %{String.t() => term()}

  @type t :: %__MODULE__{
          log_version: String.t(),
          scid: String.t(),
          update_keys: [String.t()],
          next_key_hashes: [String.t()],
          witness: witness_config() | nil,
          watchers: [String.t()],
          deactivated: boolean(),
          ttl: non_neg_integer()
        }

  @enforce_keys [:log_version, :scid, :update_keys]
  defstruct [
    :log_version,
    :scid,
    :update_keys,
    next_key_hashes: [],
    witness: nil,
    watchers: [],
    deactivated: false,
    ttl: 3600
  ]

  @doc """
  Applies an entry's raw `parameters` object to the previously active set
  (`nil` for the first entry).
  """
  @spec apply(map(), t() | nil, pos_integer()) :: {:ok, t()} | {:error, Error.t()}
  def apply(raw, previous, version) do
    with :ok <- check_no_nulls(raw, version),
         :ok <- check_log_version(raw, previous, version),
         :ok <- check_scid_and_required(raw, previous, version),
         :ok <-
           check(
             raw,
             "updateKeys",
             &multikeys?/1,
             version,
             "updateKeys must be an array of Ed25519 multikeys"
           ),
         :ok <-
           check(
             raw,
             "nextKeyHashes",
             &key_hashes?/1,
             version,
             "nextKeyHashes must be an array of SHA-256 multihashes"
           ),
         {:ok, witness} <- witness(raw, previous, version),
         :ok <- check(raw, "watchers", &urls?/1, version, "watchers must be an array of URLs"),
         :ok <- check(raw, "deactivated", &is_boolean/1, version, "deactivated must be a boolean"),
         :ok <- check(raw, "ttl", &ttl?/1, version, "ttl must be an integer between 0 and 2^31"),
         :ok <- check_prerotation(raw, previous, version) do
      {:ok, merge(raw, previous, witness)}
    end
  end

  defp merge(raw, nil, witness) do
    %__MODULE__{
      log_version: raw["logVersion"],
      scid: raw["scid"],
      update_keys: raw["updateKeys"],
      next_key_hashes: Map.get(raw, "nextKeyHashes", []),
      witness: witness,
      watchers: Map.get(raw, "watchers", []),
      deactivated: Map.get(raw, "deactivated", false),
      ttl: Map.get(raw, "ttl", 3600)
    }
  end

  defp merge(raw, %__MODULE__{} = prev, witness) do
    %__MODULE__{
      log_version: Map.get(raw, "logVersion", prev.log_version),
      scid: prev.scid,
      update_keys: Map.get(raw, "updateKeys", prev.update_keys),
      next_key_hashes: Map.get(raw, "nextKeyHashes", prev.next_key_hashes),
      witness: witness,
      watchers: Map.get(raw, "watchers", prev.watchers),
      deactivated: Map.get(raw, "deactivated", false),
      ttl: Map.get(raw, "ttl", prev.ttl)
    }
  end

  defp invalid(message, version), do: {:error, Error.new(:invalid_parameter, message, version)}

  defp check_no_nulls(raw, version) do
    case Enum.find(raw, fn {_k, v} -> v == nil end) do
      nil -> :ok
      {key, _} -> invalid("#{key} must not be null", version)
    end
  end

  defp check_log_version(raw, previous, version) do
    case {raw, previous} do
      {%{"logVersion" => lv}, _} when lv in @supported_log_versions ->
        # With a single supported version, it can never be lowered.
        :ok

      {%{"logVersion" => lv}, _} ->
        {:error,
         Error.new(:unsupported_log_version, "unsupported logVersion #{inspect(lv)}", version)}

      {_, nil} ->
        {:error, Error.new(:unsupported_log_version, "logVersion missing from first entry", 1)}

      _ ->
        :ok
    end
  end

  defp check_scid_and_required(raw, nil, version) do
    cond do
      not is_binary(raw["scid"]) ->
        invalid("scid missing from first entry", version)

      not Map.has_key?(raw, "updateKeys") ->
        invalid("updateKeys missing from first entry", version)

      true ->
        :ok
    end
  end

  defp check_scid_and_required(raw, _previous, version) do
    if Map.has_key?(raw, "scid"),
      do: invalid("scid may only appear in the first entry", version),
      else: :ok
  end

  defp check(raw, key, valid?, version, message) do
    case raw do
      %{^key => value} -> if valid?.(value), do: :ok, else: invalid(message, version)
      _ -> :ok
    end
  end

  defp multikeys?(v), do: is_list(v) and Enum.all?(v, &Multikey.valid?/1)
  defp key_hashes?(v), do: is_list(v) and Enum.all?(v, &(Hash.check_sha256(&1) == :ok))
  defp urls?(v), do: is_list(v) and Enum.all?(v, &URL.valid?/1)
  defp ttl?(v), do: is_integer(v) and v >= 0 and v <= @max_ttl

  defp witness(%{"witness" => value}, _previous, version), do: validate_witness(value, version)
  defp witness(_raw, nil, _version), do: {:ok, nil}
  defp witness(_raw, %__MODULE__{witness: w}, _version), do: {:ok, w}

  @doc """
  Validates a `witness` parameter value. `{}` means no witnesses (`{:ok, nil}`).
  """
  @spec validate_witness(term(), pos_integer()) ::
          {:ok, witness_config() | nil} | {:error, Error.t()}
  def validate_witness(value, _version) when value == %{}, do: {:ok, nil}

  def validate_witness(%{} = value, version) do
    fail = fn why -> invalid("witness: " <> why, version) end

    with {:ok, witnesses} <- witness_list(value["witnesses"], fail),
         {:ok, ids} <- witness_ids(witnesses, fail) do
      threshold = value["threshold"]

      if is_integer(threshold) and threshold >= 1 and threshold <= MapSet.size(ids) do
        {:ok, %{"threshold" => threshold, "witnesses" => witnesses}}
      else
        fail.("threshold must be an integer between 1 and the number of witnesses")
      end
    end
  end

  def validate_witness(_value, version), do: invalid("witness: must be an object", version)

  defp witness_list([_ | _] = list, _fail), do: {:ok, list}
  defp witness_list(_, fail), do: fail.("witnesses must be a non-empty array")

  defp witness_ids(witnesses, fail) do
    Enum.reduce_while(witnesses, {:ok, MapSet.new()}, fn
      %{"id" => "did:key:" <> mk = id}, {:ok, ids} when is_binary(id) ->
        nfc = :unicode.characters_to_nfc_binary(id)

        cond do
          not Multikey.valid?(mk) -> {:halt, fail.("witness id #{id} is not an Ed25519 did:key")}
          MapSet.member?(ids, nfc) -> {:halt, fail.("duplicate witness id #{id}")}
          true -> {:cont, {:ok, MapSet.put(ids, nfc)}}
        end

      %{"id" => id}, _acc when is_binary(id) ->
        {:halt, fail.("witness id #{id} is not an Ed25519 did:key")}

      _, _acc ->
        {:halt, fail.("each witness needs a string id")}
    end)
  end

  # Pre-rotation (Read step 7): while the previous entry committed to key
  # hashes, updateKeys and nextKeyHashes must be explicit and every new key
  # must have been committed.
  defp check_prerotation(_raw, nil, _version), do: :ok
  defp check_prerotation(_raw, %__MODULE__{next_key_hashes: []}, _version), do: :ok

  defp check_prerotation(raw, %__MODULE__{next_key_hashes: committed}, version) do
    violation = &{:error, Error.new(:prerotation_violation, &1, version)}

    cond do
      not Map.has_key?(raw, "updateKeys") ->
        violation.("updateKeys must be explicit while pre-rotation is active")

      not Map.has_key?(raw, "nextKeyHashes") ->
        violation.("nextKeyHashes must be explicit while pre-rotation is active")

      key = Enum.find(raw["updateKeys"], &(Hash.key_hash(&1) not in committed)) ->
        violation.("key #{key} was not committed")

      true ->
        :ok
    end
  end
end
