defmodule VHLog.Resolution do
  @moduledoc """
  A successful resolution.

  `metadata` uses the interop protocol's camelCase keys (`"versionId"`,
  `"versionNumber"`, `"warnings"`, …). `first_invalid_version` and `error`
  describe partial validity: when a later entry fails, the valid prefix still
  resolves and they report where and why the log stops being valid.
  """

  alias VHLog.Error

  @type t :: %__MODULE__{
          state: map(),
          metadata: %{String.t() => term()},
          first_invalid_version: pos_integer() | nil,
          error: Error.t() | nil
        }

  @enforce_keys [:state, :metadata]
  defstruct [:state, :metadata, first_invalid_version: nil, error: nil]

  @doc "The interop protocol's result object for a resolution outcome."
  @spec to_json({:ok, t()} | {:error, Error.t()}) :: map()
  def to_json({:ok, %__MODULE__{} = r}) do
    %{
      "valid" => true,
      "state" => r.state,
      "metadata" => r.metadata,
      "firstInvalidVersion" => r.first_invalid_version,
      "error" => r.error && Error.to_json(r.error)
    }
  end

  def to_json({:error, %Error{} = e}), do: %{"valid" => false, "error" => Error.to_json(e)}
end
