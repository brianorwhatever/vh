defmodule VHLog.Resolver do
  @moduledoc """
  Resolution (spec *Read*, *Selecting a Version*, *Comparing Copies of a
  Log*) with the partial-validity, deactivation and multi-copy rules of
  profile §4.

  `resolve/1` takes the wire-format request of the interop protocol (a map
  with camelCase string keys) — see `VHLog.resolve/2` for the Elixir-facing
  API.
  """

  alias VHLog.{Error, JSON, Resolution, VersionTime}
  alias VHLog.Verifier
  alias VHLog.Verifier.Result

  @option_keys ~w(versionId versionTime versionNumber minCopies)
  @selectors ~w(versionId versionTime versionNumber)
  @primary "primary"

  @doc """
  Resolves a log. `input` has `"log"`, `"now"`, and optionally `"witness"`,
  `"options"`, `"copies"` and `"retainedVersionId"`.
  """
  @spec resolve(map()) :: {:ok, Resolution.t()} | {:error, Error.t()}
  def resolve(input) do
    options = input["options"] || %{}

    with {:ok, now} <- parse_now(input["now"]),
         :ok <- validate_options(options) do
      if Map.has_key?(input, "copies") or Map.get(options, "minCopies", 1) > 1 do
        resolve_copies(input, now, options)
      else
        resolve_single(input, now, options)
      end
    end
  end

  defp resolve_single(input, now, options) do
    verified = Verifier.verify_log(input["log"], Map.get(input, "witness", :absent), now)

    with [_ | _] <- verified.entries,
         {:ok, warnings} <- check_retained(input, verified, @primary, []) do
      build(verified, options, warnings, nil)
    else
      [] -> {:error, verified.failure}
      {:error, _} = error -> error
    end
  end

  defp parse_now(now) do
    case VersionTime.parse(now) do
      {:ok, t} -> {:ok, t}
      :error -> option_error("now must be a whole-second UTC ISO 8601 time")
    end
  end

  defp option_error(message), do: {:error, Error.new(:invalid_option, message)}

  defp validate_options(options) when is_map(options) do
    cond do
      key = Enum.find(Map.keys(options), &(&1 not in @option_keys)) ->
        option_error("unsupported option #{key}")

      Enum.count(@selectors, &Map.has_key?(options, &1)) > 1 ->
        option_error("at most one version selector may be given")

      Map.has_key?(options, "versionId") and not is_binary(options["versionId"]) ->
        option_error("versionId must be a string")

      Map.has_key?(options, "versionTime") and not VersionTime.valid?(options["versionTime"]) ->
        option_error("versionTime must be a whole-second UTC ISO 8601 time")

      key =
          Enum.find(
            ~w(versionNumber minCopies),
            &(Map.has_key?(options, &1) and not positive_integer?(options[&1]))
          ) ->
        option_error("#{key} must be a positive integer")

      true ->
        :ok
    end
  end

  defp validate_options(_), do: option_error("options must be an object")

  defp positive_integer?(n), do: (is_integer(n) or (is_float(n) and trunc(n) == n)) and n >= 1

  @doc false
  # The versionId of raw line `index` (0-based), or nil.
  @spec line_version_id([String.t()], integer()) :: String.t() | nil
  def line_version_id(lines, index) when index >= 0 do
    with line when is_binary(line) <- Enum.at(lines, index),
         {:ok, %{"versionId" => id}} when is_binary(id) <- JSON.decode(line) do
      id
    else
      _ -> nil
    end
  end

  def line_version_id(_lines, _index), do: nil

  # ------------------------------------------------------------ selection

  # Selecting a Version. A target at or after the first invalid entry fails
  # with that entry's error (profile §4).
  defp select(%Result{entries: entries, lines: lines, failure: failure}, options) do
    invalid = fn ->
      {:error, %{failure | message: "requested version is invalid: #{failure.message}"}}
    end

    valid_count = length(entries)

    cond do
      Map.has_key?(options, "versionId") ->
        id = options["versionId"]

        cond do
          found = Enum.find(entries, &(&1.entry["versionId"] == id)) ->
            {:ok, found}

          Enum.any?(valid_count..(length(lines) - 1)//1, &(line_version_id(lines, &1) == id)) ->
            invalid.()

          true ->
            {:error, Error.new(:not_found, "no entry with versionId #{id}")}
        end

      Map.has_key?(options, "versionNumber") ->
        n = options["versionNumber"]

        cond do
          n <= valid_count -> {:ok, Enum.at(entries, trunc(n) - 1)}
          n <= length(lines) -> invalid.()
          true -> {:error, Error.new(:not_found, "no entry with version number #{n}")}
        end

      Map.has_key?(options, "versionTime") ->
        {:ok, time} = VersionTime.parse(options["versionTime"])

        if failure != nil and valid_count < length(lines) and
             first_invalid_time(lines, valid_count) <= time do
          invalid.()
        else
          case entries |> Enum.filter(&(&1.time <= time)) |> List.last() do
            nil -> {:error, Error.new(:not_found, "no entry active at #{options["versionTime"]}")}
            found -> {:ok, found}
          end
        end

      true ->
        {:ok, List.last(entries)}
    end
  end

  # The parsed versionTime of the first invalid line, or :infinity.
  defp first_invalid_time(lines, index) do
    with {:ok, %{"versionTime" => vt}} <- JSON.decode(Enum.at(lines, index)),
         {:ok, t} <- VersionTime.parse(vt) do
      t
    else
      _ -> :infinity
    end
  end

  defp build(%Result{} = verified, options, warnings, copies) do
    with {:ok, target} <- select(verified, options) do
      first = hd(verified.entries)
      last = List.last(verified.entries)
      failure = verified.failure

      warnings =
        if failure do
          message =
            "entries from version #{failure.version} fail verification: #{failure.message}"

          warnings ++ [%{"code" => "invalid-entries", "message" => message}]
        else
          warnings
        end

      metadata =
        %{
          "versionId" => target.entry["versionId"],
          "versionTime" => target.entry["versionTime"],
          "versionNumber" => target.version_number,
          "created" => first.entry["versionTime"],
          "updated" => last.entry["versionTime"],
          "scid" => first.parameters.scid,
          "deactivated" => last.parameters.deactivated,
          "ttl" => last.parameters.ttl,
          "witness" => last.parameters.witness,
          "watchers" => last.parameters.watchers,
          "updateKeys" => target.parameters.update_keys,
          "nextKeyHashes" => target.parameters.next_key_hashes,
          "warnings" => warnings
        }
        |> then(fn m -> if copies, do: Map.put(m, "copies", copies), else: m end)

      {:ok,
       %Resolution{
         state: target.entry["state"],
         metadata: metadata,
         first_invalid_version: if(failure, do: length(verified.entries) + 1),
         error: failure
       }}
    end
  end

  # ------------------------------------------------------------ retained versionId

  defp check_retained(%{"retainedVersionId" => retained}, %Result{} = reference, source, warnings) do
    with true <- is_binary(retained),
         [_, digits] <- Regex.run(~r/\A([1-9][0-9]*)-/, retained) do
      n = String.to_integer(digits)
      valid = length(reference.entries)

      cond do
        valid < n ->
          message = "the log has #{valid} valid entries, fewer than retained version #{n}"
          {:ok, warnings ++ [%{"code" => "retained-version-not-found", "message" => message}]}

        (version_id = Enum.at(reference.entries, n - 1).entry["versionId"]) != retained ->
          fork = %{
            version: n,
            copies: [
              %{source: "retained", version_id: retained},
              %{source: source, version_id: version_id}
            ]
          }

          {:error,
           Error.new(:fork_detected, "retained versionId differs at version #{n}", n, fork)}

        true ->
          {:ok, warnings}
      end
    else
      _ -> option_error("retainedVersionId is not a versionId")
    end
  end

  defp check_retained(_input, _reference, _source, warnings), do: {:ok, warnings}

  # ------------------------------------------------------------ copies

  # Comparing Copies of a Log, with the copies supplied in the request. The
  # primary copy is tried first as the reference; a copy that extends the
  # reference and verifies becomes the new reference.
  defp resolve_copies(input, now, options) do
    primary = %{"source" => @primary, "log" => input["log"]}

    primary =
      if Map.has_key?(input, "witness"),
        do: Map.put(primary, "witness", input["witness"]),
        else: primary

    all =
      [primary | input["copies"] || []] |> Enum.with_index() |> Map.new(fn {c, i} -> {i, c} end)

    count = map_size(all)

    verified =
      Map.new(
        for {i, c} <- all, not Map.has_key?(c, "unavailable") do
          {i, Verifier.verify_log(c["log"], Map.get(c, "witness", :absent), now)}
        end
      )

    state = %{status: %{}, warnings: [], verified: verified, all: all}

    state =
      Enum.reduce(0..(count - 1), state, fn i, st ->
        case all[i] do
          %{"unavailable" => reason} -> mark(st, i, "unavailable", reason)
          _ -> st
        end
      end)

    {ref, state} =
      Enum.reduce_while(0..(count - 1), {nil, state}, fn i, {nil, st} ->
        cond do
          Map.has_key?(st.status, i) -> {:cont, {nil, st}}
          Result.fully_valid?(verified[i]) -> {:halt, {i, st}}
          true -> {:cont, {nil, mark_invalid(st, i)}}
        end
      end)

    case ref do
      nil ->
        {:error, verified[0].failure || Error.new(:invalid_log, "no copy verifies")}

      ref ->
        with {:ok, ref, state} <- compare_copies(ref, state, count),
             reference = verified[ref],
             {:ok, warnings} <-
               check_retained(input, reference, all[ref]["source"], state.warnings) do
          finish(%{state | warnings: warnings}, reference, options, count)
        end
    end
  end

  defp compare_copies(ref, state, count) do
    Enum.reduce_while(0..(count - 1), {:ok, ref, MapSet.new([ref]), state}, fn i,
                                                                               {:ok, ref, matched,
                                                                                st} ->
      if Map.has_key?(st.status, i) or MapSet.member?(matched, i) do
        {:cont, {:ok, ref, matched, st}}
      else
        case compare(st.verified[ref], st.verified[i]) do
          :same ->
            {:cont, {:ok, ref, MapSet.put(matched, i), st}}

          :extends ->
            if Result.fully_valid?(st.verified[i]),
              do: {:cont, {:ok, i, MapSet.put(matched, i), st}},
              else: {:cont, {:ok, ref, matched, mark_invalid(st, i)}}

          :diverges ->
            if Result.fully_valid?(st.verified[i]),
              do: {:halt, fork(st, ref, i)},
              else: {:cont, {:ok, ref, matched, mark_invalid(st, i)}}

          :empty ->
            {:cont, {:ok, ref, matched, mark_invalid(st, i)}}
        end
      end
    end)
    |> case do
      {:ok, ref, _matched, st} -> {:ok, ref, st}
      {:error, _} = error -> error
    end
  end

  # How a copy relates to the (fully valid) reference copy.
  defp compare(%Result{} = reference, %Result{lines: copy_lines}) do
    ref_lines = reference.lines
    n = length(copy_lines)

    cond do
      n == 0 ->
        :empty

      n <= length(ref_lines) ->
        if line_version_id(copy_lines, n - 1) ==
             Enum.at(reference.entries, n - 1).entry["versionId"],
           do: :same,
           else: :diverges

      line_version_id(copy_lines, length(ref_lines) - 1) ==
          List.last(reference.entries).entry["versionId"] ->
        :extends

      true ->
        :diverges
    end
  end

  defp fork(st, ref, i) do
    ref_lines = st.verified[ref].lines
    copy_lines = st.verified[i].lines
    version = divergence(ref_lines, copy_lines)

    copies =
      for {k, lines} <- [{ref, ref_lines}, {i, copy_lines}] do
        %{source: st.all[k]["source"], version_id: line_version_id(lines, version - 1) || ""}
      end

    {:error,
     Error.new(:fork_detected, "copies diverge at version #{version}", version, %{
       version: version,
       copies: copies
     })}
  end

  # First version number at which two logs' versionIds differ.
  defp divergence(a, b) do
    n = min(length(a), length(b))
    Enum.find(1..n//1, n + 1, &(line_version_id(a, &1 - 1) != line_version_id(b, &1 - 1)))
  end

  defp mark(st, i, "unavailable", reason) do
    warning = %{
      "code" => "copy-unavailable",
      "source" => st.all[i]["source"],
      "message" => to_string(reason)
    }

    %{st | status: Map.put(st.status, i, "unavailable"), warnings: st.warnings ++ [warning]}
  end

  defp mark_invalid(st, i) do
    failure = st.verified[i].failure
    version = if failure && failure.version, do: failure.version, else: "?"
    detail = if failure, do: failure.message, else: ""

    warning = %{
      "code" => "copy-invalid",
      "source" => st.all[i]["source"],
      "message" => "copy fails verification at version #{version}: #{detail}"
    }

    %{st | status: Map.put(st.status, i, "invalid"), warnings: st.warnings ++ [warning]}
  end

  defp finish(st, %Result{} = reference, options, count) do
    {copies, warnings} =
      Enum.map_reduce(0..(count - 1), st.warnings, fn i, warnings ->
        source = st.all[i]["source"]

        case st.status[i] do
          "unavailable" ->
            {%{"source" => source, "status" => "unavailable"}, warnings}

          "invalid" ->
            lines = st.verified[i].lines

            copy =
              %{"source" => source, "status" => "invalid"}
              |> put_some("versionId", line_version_id(lines, length(lines) - 1))

            {copy, warnings}

          nil ->
            lines = st.verified[i].lines
            behind = length(reference.lines) - length(lines)
            version_id = line_version_id(lines, length(lines) - 1)

            if behind > 0 do
              warning = %{
                "code" => "copy-behind",
                "source" => source,
                "message" => "copy is #{behind} entries behind"
              }

              {%{"source" => source, "versionId" => version_id, "status" => "behind"},
               warnings ++ [warning]}
            else
              {%{"source" => source, "versionId" => version_id, "status" => "current"}, warnings}
            end
        end
      end)

    usable = Enum.count(copies, &(&1["status"] in ["current", "behind"]))
    required = Map.get(options, "minCopies", 1)

    if usable < required do
      {:error, Error.new(:min_copies_not_met, "#{usable} matching copies, #{required} required")}
    else
      build(reference, options, warnings, copies)
    end
  end

  defp put_some(map, _key, nil), do: map
  defp put_some(map, key, value), do: Map.put(map, key, value)
end
