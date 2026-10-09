defmodule VHLog.Log do
  @moduledoc """
  The Log Controller side: hashing, sealing and serialising entries
  (profile §5).

  Generators deliberately don't validate semantics beyond what they need to
  produce a well-formed entry, so the same code can build invalid test logs.
  """

  alias VHLog.{Hash, JCS, JSON, Proof}

  @scid_placeholder "{SCID}"
  @log_version "vh-log:1.0"
  @field_order ~w(versionId versionTime parameters state proof)

  @typedoc "A log entry (or entry body) as a decoded JSON object."
  @type entry :: %{String.t() => term()}

  @doc "The SCID placeholder, `{SCID}`."
  @spec scid_placeholder() :: String.t()
  def scid_placeholder, do: @scid_placeholder

  @doc "The only supported `logVersion`, `vh-log:1.0`."
  @spec log_version() :: String.t()
  def log_version, do: @log_version

  @doc "SCID of a preliminary entry (placeholders in place, proof ignored)."
  @spec scid(entry()) :: String.t()
  def scid(preliminary),
    do: preliminary |> Map.delete("proof") |> JCS.canonicalize() |> Hash.b58()

  @doc """
  Entry hash: the entry without `proof`, with `versionId` set to the
  predecessor's `versionId` (the SCID for entry 1).
  """
  @spec entry_hash(entry(), String.t()) :: String.t()
  def entry_hash(entry, previous_version_id) do
    entry
    |> Map.delete("proof")
    |> Map.put("versionId", previous_version_id)
    |> JCS.canonicalize()
    |> Hash.b58()
  end

  @doc """
  Replaces every occurrence of `from` with `to` in the serialised entry and
  parses the result (the spec's textual SCID substitution).
  """
  @spec replace_text(entry(), String.t(), String.t()) :: entry()
  def replace_text(entry, from, to) do
    entry |> JCS.canonicalize() |> String.replace(from, to) |> JSON.decode!()
  end

  @doc """
  Serialises an entry as one compact JSON line (with the trailing `\\n`), with
  the fields in the profile's order.
  """
  @spec serialize_entry(entry()) :: String.t()
  def serialize_entry(entry) do
    {known, extra} = Enum.split_with(entry, fn {k, _} -> k in @field_order end)
    known = Enum.sort_by(known, fn {k, _} -> Enum.find_index(@field_order, &(&1 == k)) end)

    members =
      Enum.map(known ++ extra, fn {k, v} -> [JSON.encode!(k), ?:, JSON.encode!(v)] end)

    IO.iodata_to_binary([?{, Enum.intersperse(members, ?,), "}\n"])
  end

  @doc "Splits log text into lines (a final empty line is dropped)."
  @spec lines(String.t()) :: [String.t()]
  def lines(log) do
    parts = String.split(log, "\n")
    if List.last(parts) == "", do: List.delete_at(parts, -1), else: parts
  end

  @doc """
  Turns a genesis body into a signed first entry: computes the SCID, replaces
  the placeholder, computes the entry hash and signs once per seed.
  """
  @spec seal_genesis(entry(), [String.t()]) :: {entry(), String.t()}
  def seal_genesis(body, signers) do
    preliminary = Map.put(body, "versionId", @scid_placeholder)
    scid = scid(preliminary)
    replaced = replace_text(preliminary, @scid_placeholder, scid)
    document = Map.put(replaced, "versionId", "1-" <> entry_hash(replaced, scid))
    {sign(document, signers), scid}
  end

  @doc "Signs a later entry whose predecessor has `previous_version_id`."
  @spec seal_entry(entry(), String.t(), [String.t()]) :: entry()
  def seal_entry(body, previous_version_id, signers) do
    number =
      case Integer.parse(previous_version_id) do
        {n, _} -> Integer.to_string(n + 1)
        _ -> "NaN"
      end

    hash = entry_hash(body, previous_version_id)
    body |> Map.put("versionId", "#{number}-#{hash}") |> sign(signers)
  end

  defp sign(document, signers) do
    created = document["versionTime"]
    proofs = Enum.map(signers, &Proof.create(document, &1, created: created))
    Map.put(document, "proof", proofs)
  end

  @doc """
  Creates a log. `parameters` gets `logVersion` and `scid: "{SCID}"` if they
  are absent.
  """
  @spec create(entry(), entry(), String.t(), [String.t()]) ::
          %{log: String.t(), scid: String.t(), version_id: String.t()}
  def create(state, parameters, version_time, signers) do
    parameters =
      parameters
      |> Map.put_new("logVersion", @log_version)
      |> Map.put_new("scid", @scid_placeholder)

    body = %{"versionTime" => version_time, "parameters" => parameters, "state" => state}
    {entry, scid} = seal_genesis(body, signers)
    %{log: serialize_entry(entry), scid: scid, version_id: entry["versionId"]}
  end

  @doc """
  Appends an entry to `log`, chaining from its last line.
  """
  @spec update(String.t(), entry(), entry(), String.t(), [String.t()]) ::
          %{log: String.t(), version_id: String.t()}
  def update(log, state, parameters, version_time, signers) do
    previous =
      case lines(log) do
        [] -> raise ArgumentError, "cannot update an empty log"
        lines -> lines |> List.last() |> JSON.decode!()
      end

    previous_id = previous["versionId"]

    body = %{
      "versionId" => previous_id,
      "versionTime" => version_time,
      "parameters" => parameters,
      "state" => state
    }

    entry = seal_entry(body, previous_id, signers)
    prefix = if log == "" or String.ends_with?(log, "\n"), do: log, else: log <> "\n"
    %{log: prefix <> serialize_entry(entry), version_id: entry["versionId"]}
  end

  @doc ~S"""
  A witness proof: `eddsa-jcs-2022` over `{"versionId": version_id}` (profile §3).
  """
  @spec witness_proof(String.t(), String.t(), String.t() | nil) :: Proof.t()
  def witness_proof(version_id, seed, created \\ nil) do
    Proof.create(
      %{"versionId" => version_id},
      seed,
      if(created, do: [created: created], else: [])
    )
  end
end
