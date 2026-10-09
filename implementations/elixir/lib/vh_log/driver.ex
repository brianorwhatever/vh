defmodule VHLog.Driver do
  @moduledoc """
  Interop driver (`docs/interop-protocol.md`): JSON Lines requests on stdin,
  one JSON response line per request on stdout, logs on stderr, exit on EOF.

  stdin and stdout are switched to raw bytes so UTF-8 passes through
  untouched; lines are split on `\\n` only, since JSON strings may contain raw
  U+2028/U+2029.

      mix run --no-compile -e "VHLog.Driver.main()"
  """

  alias VHLog.{Hash, JCS, JSON, Log, Multikey, Proof, Resolution, Resolver}

  @doc "Runs the driver until EOF on stdin."
  @spec main() :: :ok
  def main do
    :ok = :io.setopts(:standard_io, binary: true, encoding: :latin1)
    loop()
  end

  defp loop do
    case IO.binread(:stdio, :line) do
      line when is_binary(line) ->
        line = String.trim_trailing(line, "\n")

        unless String.trim(line) == "" do
          IO.binwrite(:stdio, [handle_line(line), ?\n])
        end

        loop()

      _eof_or_error ->
        :ok
    end
  end

  @doc """
  Handles one request line and returns the response line (without `\\n`).
  """
  @spec handle_line(String.t()) :: String.t()
  def handle_line(line) do
    response =
      case JSON.decode(line) do
        {:ok, %{} = request} ->
          id = request["id"]

          try do
            %{
              "id" => id,
              "ok" => true,
              "result" => handle(request["op"], request["input"] || %{})
            }
          rescue
            e ->
              IO.puts(:stderr, Exception.format(:error, e, __STACKTRACE__))
              %{"id" => id, "ok" => false, "error" => Exception.message(e)}
          end

        _ ->
          %{"id" => nil, "ok" => false, "error" => "malformed request"}
      end

    JSON.encode!(response)
  end

  @doc "Runs one protocol operation on its decoded `input`."
  @spec handle(String.t(), map()) :: map()
  def handle("jcs", %{"text" => text}) do
    case JCS.canonicalize_text(text) do
      {:ok, output} -> %{"output" => output}
      {:error, reason} -> raise ArgumentError, "invalid JSON text: #{inspect(reason)}"
    end
  end

  def handle("hash", %{"data" => data}), do: %{"output" => Hash.b58(data)}

  def handle("multikey", %{"seed" => seed}),
    do: %{"multikey" => Multikey.from_seed(seed).multikey}

  def handle("key-hash", %{"multikey" => mk}), do: %{"output" => Hash.key_hash(mk)}
  def handle("scid", %{"entry" => entry}), do: %{"scid" => Log.scid(entry)}

  def handle("entry-hash", %{"entry" => entry, "previousVersionId" => previous}),
    do: %{"hash" => Log.entry_hash(entry, previous)}

  def handle("sign", %{"document" => document, "seed" => seed} = input) do
    opts =
      for {key, wire} <- [verification_method: "verificationMethod", created: "created"],
          input[wire] != nil,
          do: {key, input[wire]}

    %{"proof" => Proof.create(document, seed, opts)}
  end

  def handle("verify", %{"document" => document, "proof" => proof}),
    do: %{"valid" => Proof.verify(document, proof)}

  def handle("create", input) do
    result =
      Log.create(
        input["state"],
        input["parameters"] || %{},
        input["versionTime"],
        input["signers"]
      )

    %{"log" => result.log, "scid" => result.scid, "versionId" => result.version_id}
  end

  def handle("update", input) do
    result =
      Log.update(
        input["log"],
        input["state"],
        input["parameters"] || %{},
        input["versionTime"],
        input["signers"]
      )

    %{"log" => result.log, "versionId" => result.version_id}
  end

  def handle("witness", %{"versionId" => version_id, "seed" => seed} = input),
    do: %{"proof" => Log.witness_proof(version_id, seed, input["created"])}

  def handle("resolve", input), do: input |> Resolver.resolve() |> Resolution.to_json()

  def handle(op, _input) when is_binary(op),
    do: raise(ArgumentError, "unknown op #{op} or missing input")

  def handle(op, _input), do: raise(ArgumentError, "unknown op #{inspect(op)}")
end
