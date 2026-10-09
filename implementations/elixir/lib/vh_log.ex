defmodule VHLog do
  @moduledoc """
  Verifiable History Log (VH-Log), following the `vh-log-interop-0` profile.

  A VH-Log is a JSON Lines file of entries, each committing to its
  predecessor through a hash chain and signed by the log's update keys. This
  module is the Log Controller (`create/1`, `update/2`, `witness_proof/2`)
  and the resolver (`verify/2`, `resolve/2`).

  Resolution is a pure fold over the log's immutable entries: each entry runs
  the profile's checks in order (`VHLog.Verifier`) and the first failure
  becomes a `VHLog.Error`.

  ## Example

      iex> seed = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
      iex> key = VHLog.Multikey.from_seed(seed).multikey
      iex> {:ok, %{log: log, scid: scid}} =
      ...>   VHLog.create(
      ...>     state: %{"id" => "example:{SCID}"},
      ...>     parameters: %{"updateKeys" => [key]},
      ...>     version_time: "2026-01-01T00:00:00Z",
      ...>     signers: [seed]
      ...>   )
      iex> {:ok, %{log: log}} =
      ...>   VHLog.update(log,
      ...>     state: %{"id" => "example:" <> scid, "name" => "renamed"},
      ...>     version_time: "2026-01-02T00:00:00Z",
      ...>     signers: [seed]
      ...>   )
      iex> {:ok, resolution} = VHLog.resolve(log, now: "2026-06-01T00:00:00Z")
      iex> resolution.state["name"]
      "renamed"
      iex> resolution.metadata["versionNumber"]
      2
  """

  alias VHLog.{Error, Log, Resolution, Resolver, Verifier, VersionTime}

  @typedoc "Log text: JSON Lines, one entry per line."
  @type log :: String.t()

  @typedoc "A hex-encoded 32-byte Ed25519 seed."
  @type seed :: String.t()

  @doc """
  Creates a log with one (genesis) entry.

  Options: `:state` and `:parameters` (maps with string keys; `{SCID}` is
  replaced by the SCID), `:version_time` and `:signers` (seeds; one proof
  each). `logVersion` defaults to `"vh-log:1.0"` and `scid` to `"{SCID}"`.
  """
  @spec create(keyword()) :: {:ok, %{log: log(), scid: String.t(), version_id: String.t()}}
  def create(opts) do
    {:ok,
     Log.create(
       Keyword.fetch!(opts, :state),
       Keyword.get(opts, :parameters, %{}),
       Keyword.fetch!(opts, :version_time),
       Keyword.fetch!(opts, :signers)
     )}
  end

  @doc """
  Appends an entry to `log`. Options: `:state`, `:parameters` (default
  `%{}`), `:version_time`, `:signers`. To deactivate, pass
  `parameters: %{"deactivated" => true}`.
  """
  @spec update(log(), keyword()) ::
          {:ok, %{log: log(), version_id: String.t()}} | {:error, Error.t()}
  def update(log, opts) do
    case Log.lines(log) do
      [] ->
        {:error, Error.new(:invalid_log, "cannot update an empty log")}

      _ ->
        {:ok,
         Log.update(
           log,
           Keyword.fetch!(opts, :state),
           Keyword.get(opts, :parameters, %{}),
           Keyword.fetch!(opts, :version_time),
           Keyword.fetch!(opts, :signers)
         )}
    end
  end

  @doc """
  A witness's proof for `version_id` (profile §3). Pass `created:` to set
  the proof's `created` time.
  """
  @spec witness_proof(String.t(), seed(), keyword()) :: VHLog.Proof.t()
  def witness_proof(version_id, seed, opts \\ []),
    do: Log.witness_proof(version_id, seed, opts[:created])

  @doc """
  Verifies every entry of a log and its witness proofs.

  Options: `:now` (a `versionTime` string or `DateTime`, default the current
  time) and `:witness` (the decoded witness file). Returns the verified
  entries if the whole log is valid, otherwise the first failure.
  """
  @spec verify(log(), keyword()) :: {:ok, [Verifier.Entry.t()]} | {:error, Error.t()}
  def verify(log, opts \\ []) do
    with {:ok, string} <- now(opts[:now]) do
      {:ok, now} = VersionTime.parse(string)

      case Verifier.verify_log(log, Keyword.get(opts, :witness, :absent), now) do
        %{failure: nil, entries: entries} -> {:ok, entries}
        %{failure: error} -> {:error, error}
      end
    end
  end

  @doc """
  Resolves a log.

  Options:

    * `:now` — the resolver's clock (`versionTime` string or `DateTime`;
      default the current time)
    * `:witness` — the decoded witness file
    * `:version_id`, `:version_time`, `:version_number` — at most one version
      selector
    * `:min_copies` — copies that must be `current` or `behind`
    * `:copies` — watcher copies: maps with `"source"` and either `"log"`
      (and optionally `"witness"`) or `"unavailable"`
    * `:retained_version_id` — a `versionId` retained from an earlier
      resolution

  Returns `{:ok, %VHLog.Resolution{}}` — which may still report a later
  invalid entry in `first_invalid_version`/`error` — or `{:error, error}`.
  """
  @spec resolve(log(), keyword()) :: {:ok, Resolution.t()} | {:error, Error.t()}
  def resolve(log, opts \\ []) do
    selectors = [
      version_id: "versionId",
      version_time: "versionTime",
      version_number: "versionNumber",
      min_copies: "minCopies"
    ]

    with {:ok, now} <- now(opts[:now]),
         [] <-
           Keyword.keys(opts) --
             [:now, :witness, :copies, :retained_version_id | Keyword.keys(selectors)] do
      options =
        for {k, wire} <- selectors, Keyword.has_key?(opts, k), into: %{}, do: {wire, opts[k]}

      %{"log" => log, "now" => now, "options" => options}
      |> put_opt(opts, :witness, "witness")
      |> put_opt(opts, :copies, "copies")
      |> put_opt(opts, :retained_version_id, "retainedVersionId")
      |> Resolver.resolve()
    else
      [unknown | _] -> {:error, Error.new(:invalid_option, "unsupported option #{unknown}")}
      {:error, _} = error -> error
    end
  end

  defp put_opt(map, opts, key, wire) do
    if Keyword.has_key?(opts, key), do: Map.put(map, wire, opts[key]), else: map
  end

  # Normalises `now` to the wire's string form, validating it.
  defp now(nil), do: now(DateTime.utc_now())

  defp now(%DateTime{} = dt),
    do:
      dt
      |> DateTime.shift_zone!("Etc/UTC")
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()
      |> now()

  defp now(string) do
    if VersionTime.valid?(string),
      do: {:ok, string},
      else: {:error, Error.new(:invalid_option, "now must be a whole-second UTC ISO 8601 time")}
  end
end
