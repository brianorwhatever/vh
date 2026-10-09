defmodule VHLog.Error do
  @moduledoc """
  A VH-Log verification or resolution failure (profile §6).

  `code` is one of the profile's error codes as an atom, with `-` written as
  `_` (`:entry_hash_mismatch` is reported on the wire as
  `"entry-hash-mismatch"`). `version` is the version number of the entry that
  failed, where there is one. `fork` is set for `:fork_detected`.
  """

  @codes [
    :invalid_log,
    :invalid_entry,
    :invalid_parameter,
    :unsupported_log_version,
    :prerotation_violation,
    :invalid_proof,
    :unauthorized_key,
    :invalid_version_id,
    :invalid_hash_algorithm,
    :entry_hash_mismatch,
    :invalid_version_time,
    :future_version_time,
    :scid_mismatch,
    :entry_after_deactivation,
    :witness_threshold_not_met,
    :invalid_witness_file,
    :fork_detected,
    :min_copies_not_met,
    :not_found,
    :invalid_option
  ]

  @typedoc "A profile error code."
  @type code ::
          :invalid_log
          | :invalid_entry
          | :invalid_parameter
          | :unsupported_log_version
          | :prerotation_violation
          | :invalid_proof
          | :unauthorized_key
          | :invalid_version_id
          | :invalid_hash_algorithm
          | :entry_hash_mismatch
          | :invalid_version_time
          | :future_version_time
          | :scid_mismatch
          | :entry_after_deactivation
          | :witness_threshold_not_met
          | :invalid_witness_file
          | :fork_detected
          | :min_copies_not_met
          | :not_found
          | :invalid_option

  @typedoc "Where two copies (or a retained versionId and a copy) diverge."
  @type fork :: %{version: pos_integer(), copies: [%{source: String.t(), version_id: String.t()}]}

  @type t :: %__MODULE__{
          code: code(),
          version: pos_integer() | nil,
          message: String.t(),
          fork: fork() | nil
        }

  defexception [:code, :version, :fork, message: ""]

  @doc "All profile error codes."
  @spec codes() :: [code()]
  def codes, do: @codes

  @doc "Builds an error."
  @spec new(code(), String.t(), pos_integer() | nil, fork() | nil) :: t()
  def new(code, message, version \\ nil, fork \\ nil) when code in @codes do
    %__MODULE__{code: code, message: message, version: version, fork: fork}
  end

  @doc ~S"""
  The wire form of a code.

      iex> VHLog.Error.code_string(:entry_hash_mismatch)
      "entry-hash-mismatch"
  """
  @spec code_string(code()) :: String.t()
  def code_string(code) when code in @codes,
    do: code |> Atom.to_string() |> String.replace("_", "-")

  @doc "The error report of the interop protocol (`{code, version, message, fork?}`)."
  @spec to_json(t()) :: map()
  def to_json(%__MODULE__{} = e) do
    report = %{"code" => code_string(e.code), "version" => e.version, "message" => e.message}

    case e.fork do
      nil ->
        report

      %{version: v, copies: copies} ->
        copies = Enum.map(copies, &%{"source" => &1.source, "versionId" => &1.version_id})
        Map.put(report, "fork", %{"version" => v, "copies" => copies})
    end
  end
end
