ExUnit.start()

defmodule VHLog.TestVectors do
  @moduledoc false
  @dir Path.expand("../../../vectors", __DIR__)

  def dir, do: @dir

  def load(name), do: @dir |> Path.join(name) |> File.read!() |> VHLog.JSON.decode!()

  # Order-insensitive comparison of decoded JSON values, as the harness does.
  def same?(a, b), do: VHLog.JCS.canonicalize(a) == VHLog.JCS.canonicalize(b)
end
