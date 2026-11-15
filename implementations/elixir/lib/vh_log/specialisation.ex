defmodule VHLog.Specialisation do
  @moduledoc """
  What a specialisation of VH-Log (such as did:vh, see `VHLog.DidVh`) changes
  in verification. Everything else (hashing, proofs, witnesses, pre-rotation)
  is shared.

    * `version_parameter` — the parameter carrying the log version
      (`logVersion` in plain VH-Log)
    * `versions` — its accepted values, oldest first
    * `version_syntax` — a regex for well-formed values. When set, a missing
      or malformed value fails with `invalid-parameter`, and only a
      well-formed value that is not accepted fails with
      `unsupported-log-version`. When `nil`, every unaccepted value is
      `unsupported-log-version` (plain VH-Log).
    * `extra_parameters` — parameters added to the VH-Log set. `nil` means
      unknown parameters are ignored (plain VH-Log); a list closes the set,
      and an unknown parameter fails with `invalid-parameter`.
    * `check_state` — `fn state, scid, version -> :ok | {:error, error}`,
      run on every entry after the SCID check, or `nil`
  """

  alias VHLog.Log

  @type t :: %__MODULE__{
          version_parameter: String.t(),
          versions: [String.t()],
          version_syntax: Regex.t() | nil,
          extra_parameters: [String.t()] | nil,
          check_state: (map(), String.t(), pos_integer() -> :ok | {:error, VHLog.Error.t()}) | nil
        }

  @enforce_keys [:version_parameter, :versions]
  defstruct [
    :version_parameter,
    :versions,
    version_syntax: nil,
    extra_parameters: nil,
    check_state: nil
  ]

  @doc "Plain VH-Log (`vh-log:1.0`), as specified by profile vh-log-interop-0."
  @spec vh_log() :: t()
  def vh_log, do: %__MODULE__{version_parameter: "logVersion", versions: [Log.log_version()]}

  @doc "The VH-Log parameters, excluding the version parameter."
  @spec vh_log_parameters() :: [String.t()]
  def vh_log_parameters, do: ~w(scid updateKeys nextKeyHashes witness watchers deactivated ttl)
end
