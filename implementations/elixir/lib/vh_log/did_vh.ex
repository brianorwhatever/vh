defmodule VHLog.DidVh do
  @moduledoc """
  did:vh (`docs/didvh-profile.md`). A did:vh DID log has the same format and
  verification as a VH-Log log (did:vh and VH-Log are both derived from
  did:webvh), so the log is verified by the VH-Log code with the did:vh
  `VHLog.Specialisation`. This module adds the DID syntax, the `srcLog` /
  `srcWitness` and DID URL rules, the resolution options, and DID Resolution
  metadata and errors.

  Functions that validate return `{:ok, value}` or `{:error, code, message}`,
  where `code` is a did:vh error code string such as `"invalidOptions"`.
  """

  alias VHLog.{Error, Log, Resolver, Specialisation, URL, VersionTime}

  @method "did:vh:1.0"
  @prefix "did:vh:"

  @typedoc "A did:vh error code (DID Resolution, plus the did:vh-specific ones)."
  @type error_code :: String.t()

  @typedoc "A validation failure."
  @type failure :: {:error, error_code(), String.t()}

  @doc "The supported `method` value, `did:vh:1.0`."
  @spec method() :: String.t()
  def method, do: @method

  # ---------------------------------------------------------------- the DID

  @doc """
  The SCID of a did:vh DID, or `nil` if `did` does not match the ABNF.

      iex> VHLog.DidVh.parse_did("did:vh:QmeezVX1uU8kMyM9TEQuvz9hBYgKAt44ThjHvbkopuZMM4")
      "QmeezVX1uU8kMyM9TEQuvz9hBYgKAt44ThjHvbkopuZMM4"
      iex> VHLog.DidVh.parse_did("did:VH:QmeezVX1uU8kMyM9TEQuvz9hBYgKAt44ThjHvbkopuZMM4")
      nil
  """
  @spec parse_did(term()) :: String.t() | nil
  def parse_did(@prefix <> scid) do
    if Regex.match?(~r/\A[1-9A-HJ-NP-Za-km-z]{46}\z/, scid), do: scid
  end

  def parse_did(_), do: nil

  @doc """
  The did:vh specialisation of VH-Log: `method` instead of `logVersion`, a
  closed parameter set, and `state.id` = `did:vh:<SCID>` in every entry. With
  `expected_scid`, the log's SCID must also be that of the DID being resolved.
  """
  @spec specialisation(String.t() | nil) :: Specialisation.t()
  def specialisation(expected_scid \\ nil) do
    %Specialisation{
      version_parameter: "method",
      versions: [@method],
      version_syntax: ~r/\Adid:vh:(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/,
      extra_parameters: [],
      check_state: fn state, scid, version ->
        cond do
          expected_scid != nil and scid != expected_scid ->
            {:error,
             Error.new(
               :invalid_state,
               "the log is for did:vh:#{scid}, not did:vh:#{expected_scid}",
               version
             )}

          state["id"] != @prefix <> scid ->
            {:error, Error.new(:invalid_state, "state.id must be #{@prefix}#{scid}", version)}

          true ->
            :ok
        end
      end
    }
  end

  # ---------------------------------------------------------------- create / update

  @doc """
  Creates a did:vh DID log. `document` uses `did:vh:{SCID}` wherever it refers
  to the DID; `method` and `scid` are added to `parameters` if absent. Like
  VH-Log generation, it does not validate its input.
  """
  @spec create(map(), map(), String.t(), [String.t()]) ::
          %{log: String.t(), did: String.t(), scid: String.t(), version_id: String.t()}
  def create(document, parameters, version_time, signers) do
    result = Log.create(document, parameters, version_time, signers, "method", @method)
    Map.put(result, :did, @prefix <> result.scid)
  end

  @doc """
  Appends an entry to a did:vh DID log. Deactivate with
  `parameters: %{"deactivated" => true}`.
  """
  @spec update(String.t(), map(), map(), String.t(), [String.t()]) ::
          %{log: String.t(), version_id: String.t()}
  def update(log, document, parameters, version_time, signers),
    do: Log.update(log, document, parameters, version_time, signers)

  # ---------------------------------------------------------------- shared URL checks

  @whitespace [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680] ++
                Enum.to_list(0x2000..0x200A) ++ [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]

  @hex ~c"0123456789abcdefABCDEF"

  @doc """
  Percent-decodes `s` to a UTF-8 string, or `nil` if an escape or the UTF-8
  is malformed.

      iex> VHLog.DidVh.percent_decode("a%2Fb%C3%A9")
      "a/bé"
      iex> VHLog.DidVh.percent_decode("%FF")
      nil
  """
  @spec percent_decode(String.t()) :: String.t() | nil
  def percent_decode(s) do
    with {:ok, bytes} <- decode_bytes(s, []),
         true <- String.valid?(bytes) do
      bytes
    else
      _ -> nil
    end
  end

  defp decode_bytes(<<>>, acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp decode_bytes(<<?%, a, b, rest::binary>>, acc) when a in @hex and b in @hex,
    do: decode_bytes(rest, [String.to_integer(<<a, b>>, 16) | acc])

  defp decode_bytes(<<?%, _::binary>>, _acc), do: :error
  defp decode_bytes(<<c, rest::binary>>, acc), do: decode_bytes(rest, [c | acc])

  defp octet?(s), do: Regex.match?(~r/\A(0|[1-9][0-9]{0,2})\z/, s) and String.to_integer(s) <= 255

  defp loopback_host?("localhost"), do: true
  defp loopback_host?("[::1]"), do: true

  defp loopback_host?(host) do
    case String.split(host, ".") do
      ["127" | _] = parts when length(parts) == 4 -> Enum.all?(parts, &octet?/1)
      _ -> false
    end
  end

  defp domain_name?(host) do
    name =
      if String.ends_with?(host, "."), do: binary_part(host, 0, byte_size(host) - 1), else: host

    labels = String.split(name, ".")

    byte_size(name) in 1..253 and not Regex.match?(~r/\A[0-9]+\z/, List.last(labels)) and
      Enum.all?(labels, &Regex.match?(~r/\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/, &1))
  end

  # Splits `scheme:rest` (profile §3 steps 1–2); nil if `value` is not
  # printable ASCII with a scheme. The scheme is lowercased.
  defp split_scheme(value) when is_binary(value) do
    with true <- Regex.match?(~r/\A[\x21-\x7e]+\z/, value),
         [_, scheme, rest] <- Regex.run(~r/\A([A-Za-z][A-Za-z0-9+.-]*):(.*)\z/s, value) do
      {String.downcase(scheme), rest}
    else
      _ -> nil
    end
  end

  defp split_scheme(_), do: nil

  # Checks an http(s) authority (profile §3); true if valid for `scheme`.
  defp authority?(authority, scheme) do
    with false <- String.contains?(authority, "@"),
         {:ok, host, port} <- split_host_port(authority),
         true <- port == nil or Regex.match?(~r/\A[0-9]{1,5}\z/, port),
         true <- port == nil or String.to_integer(port) <= 65_535 do
      host = String.downcase(host)

      if scheme == "http",
        do: loopback_host?(host),
        else: not String.starts_with?(host, "[") and domain_name?(host)
    else
      _ -> false
    end
  end

  defp split_host_port("[" <> _ = authority) do
    case :binary.match(authority, "]") do
      :nomatch ->
        :error

      {close, 1} ->
        host = binary_part(authority, 0, close + 1)

        case binary_part(authority, close + 1, byte_size(authority) - close - 1) do
          "" -> {:ok, host, nil}
          ":" <> port -> {:ok, host, port}
          _ -> :error
        end
    end
  end

  defp split_host_port(authority) do
    case String.split(authority, ":", parts: 2) do
      [host] -> {:ok, host, nil}
      [host, port] -> {:ok, host, port}
    end
  end

  # Checks the segments of a path that starts with `/` (profile §3). Each is
  # percent-decoded and must not be `.` or `..` or contain `/`, `\` or NUL.
  # With `strict` (the `src` DID URL parameter), it must also be non-empty and
  # not start or end with whitespace.
  defp segments?("/" <> path, strict) do
    path
    |> String.split("/")
    |> Enum.all?(fn raw ->
      segment = percent_decode(raw)

      segment != nil and segment not in [".", ".."] and
        not String.contains?(segment, ["/", "\\", <<0>>]) and
        (not strict or (segment != "" and not edge_whitespace?(segment)))
    end)
  end

  defp edge_whitespace?(segment) do
    chars = String.to_charlist(segment)
    hd(chars) in @whitespace or List.last(chars) in @whitespace
  end

  # ---------------------------------------------------------------- srcLog / srcWitness references

  @doc """
  Validates a `srcLog` or `srcWitness` reference, which names a file
  (profile §3.1), and returns its kind: `"web"`, `"loopback"`, `"file"` or
  `"other"`. Fails with `invalidOptions`.

      iex> VHLog.DidVh.check_ref("https://example.com/dids/issuer/did.jsonl")
      {:ok, "web"}
      iex> VHLog.DidVh.check_ref("http://example.com/did.jsonl") |> elem(1)
      "invalidOptions"
  """
  @spec check_ref(term()) :: {:ok, String.t()} | failure()
  def check_ref(ref) do
    invalid = fn why -> {:error, "invalidOptions", "reference #{inspect(ref)}: #{why}"} end

    case split_scheme(ref) do
      nil ->
        invalid.("not a printable-ASCII absolute URL")

      {scheme, rest} ->
        cond do
          String.contains?(rest, "#") -> invalid.("must not have a fragment")
          scheme in ["https", "http"] -> check_web_ref(scheme, rest, invalid)
          scheme == "file" -> check_file_ref(rest, invalid)
          rest == "" -> invalid.("empty URL")
          true -> {:ok, "other"}
        end
    end
  end

  defp check_web_ref(scheme, "//" <> after_slashes, invalid) do
    {authority, after_authority} =
      case :binary.match(after_slashes, ["/", "?"]) do
        :nomatch ->
          {after_slashes, ""}

        {i, _} ->
          {binary_part(after_slashes, 0, i),
           binary_part(after_slashes, i, byte_size(after_slashes) - i)}
      end

    [path | _] = String.split(after_authority, "?", parts: 2)

    cond do
      not authority?(authority, scheme) ->
        invalid.(
          if scheme == "http",
            do: "http is only allowed with a loopback host",
            else: "invalid https host"
        )

      path == "" ->
        invalid.("must have a path")

      not segments?(path, false) ->
        invalid.("invalid path segment")

      true ->
        {:ok, if(scheme == "http", do: "loopback", else: "web")}
    end
  end

  defp check_web_ref(_scheme, _rest, invalid), do: invalid.("missing authority")

  defp check_file_ref(rest, invalid) do
    path =
      case rest do
        "//" <> after_slashes ->
          case String.split(after_slashes, "/", parts: 2) do
            [host, path] ->
              if String.downcase(host) in ["", "localhost"],
                do: {:ok, "/" <> path},
                else: invalid.("file URL host must be empty or localhost")

            [_] ->
              invalid.("file URL needs an absolute path")
          end

        "/" <> _ ->
          {:ok, rest}

        _ ->
          invalid.("file URL needs an absolute path")
      end

    cond do
      String.contains?(rest, "?") -> invalid.("must not have a query")
      match?({:error, _, _}, path) -> path
      not segments?(elem(path, 1), false) -> invalid.("invalid path segment")
      true -> {:ok, "file"}
    end
  end

  # ---------------------------------------------------------------- the src DID URL parameter

  @doc """
  Validates a (percent-decoded) `src` DID URL parameter and derives the
  `srcLog` and `srcWitness` references from it (profile §3.2). Fails with
  `invalidDidUrl`.

      iex> VHLog.DidVh.src_references("https://example.com/dids/issuer/")
      {:ok, %{"srcLog" => "https://example.com/dids/issuer/did.jsonl",
              "srcWitness" => "https://example.com/dids/issuer/did-witness.json"}}
  """
  @spec src_references(term()) :: {:ok, %{String.t() => String.t()}} | failure()
  def src_references(src) do
    invalid = fn why -> {:error, "invalidDidUrl", "src #{inspect(src)}: #{why}"} end

    with {:parts, {scheme, rest}} <- {:parts, split_scheme(src)},
         {:query, false} <- {:query, String.contains?(rest, ["?", "#"])},
         {:scheme, _, false} <- {:scheme, scheme, scheme in ["http", "file"]},
         {:authority, "//" <> <<c, _::binary>>} when c != ?/ <- {:authority, rest},
         base = String.replace_suffix(rest, "/", ""),
         :ok <- check_src_https(scheme, base, invalid) do
      location = "#{scheme}:#{base}"

      {:ok,
       %{"srcLog" => location <> "/did.jsonl", "srcWitness" => location <> "/did-witness.json"}}
    else
      {:parts, nil} -> invalid.("not a printable-ASCII absolute URL")
      {:query, true} -> invalid.("must not have a query or fragment")
      {:scheme, scheme, true} -> invalid.("#{scheme} is not allowed in a DID URL")
      {:authority, _} -> invalid.("not a hierarchical URL with an authority")
      {:error, _, _} = error -> error
    end
  end

  defp check_src_https("https", "//" <> base, invalid) do
    {authority, path} =
      case String.split(base, "/", parts: 2) do
        [authority] -> {authority, ""}
        [authority, path] -> {authority, "/" <> path}
      end

    cond do
      not authority?(authority, "https") -> invalid.("invalid https host")
      path != "" and not segments?(path, true) -> invalid.("invalid path segment")
      true -> :ok
    end
  end

  defp check_src_https(_scheme, _base, _invalid), do: :ok

  # ---------------------------------------------------------------- DID URLs

  @url_parameters ~w(src versionId versionTime versionNumber)
  @option_only ~w(didLog didWitness srcLog srcWitness checkWatchers extraWatchers minCopies includeDidLog)

  @doc """
  Parses a did:vh DID URL as a dereferencer does (profile §4): `src` becomes
  the `srcLog` and `srcWitness` options, and the version parameters become
  the options of the same name. Returns `{:ok, %{did, options, fragment}}`
  (`fragment` is `nil` without a `#`). Fails with `invalidDidUrl`.
  """
  @spec parse_did_url(term()) ::
          {:ok, %{did: String.t(), options: map(), fragment: String.t() | nil}} | failure()
  def parse_did_url(did_url) when is_binary(did_url) do
    invalid = fn why -> {:error, "invalidDidUrl", "#{inspect(did_url)}: #{why}"} end

    {before_fragment, fragment} =
      case String.split(did_url, "#", parts: 2) do
        [before] -> {before, nil}
        [before, fragment] -> {before, fragment}
      end

    {did, query} =
      case String.split(before_fragment, "?", parts: 2) do
        [did] -> {did, nil}
        [did, query] -> {did, query}
      end

    cond do
      parse_did(did) == nil ->
        invalid.("not a did:vh DID")

      query == nil ->
        {:ok, %{did: did, options: %{}, fragment: fragment}}

      true ->
        query
        |> String.split("&")
        |> Enum.reduce_while({:ok, %{}, MapSet.new()}, fn pair, {:ok, options, seen} ->
          case url_parameter(pair, options, seen, invalid) do
            {:ok, _, _} = acc -> {:cont, acc}
            error -> {:halt, error}
          end
        end)
        |> case do
          {:ok, options, _seen} -> {:ok, %{did: did, options: options, fragment: fragment}}
          error -> error
        end
    end
  end

  def parse_did_url(_), do: {:error, "invalidDidUrl", "not a string"}

  defp url_parameter(pair, options, seen, invalid) do
    with {:pair, [raw_key, raw_value]} <- {:pair, String.split(pair, "=", parts: 2)},
         {:decode, key, value} when is_binary(key) and is_binary(value) <-
           {:decode, percent_decode(raw_key), percent_decode(raw_value)},
         {:option, false} <- {:option, key in @option_only},
         {:known, true} <- {:known, key in @url_parameters},
         {:seen, false} <- {:seen, MapSet.member?(seen, key)},
         {:ok, options} <- url_option(key, value, options, invalid) do
      {:ok, options, MapSet.put(seen, key)}
    else
      {:pair, _} -> invalid.("query parameter #{inspect(pair)} has no value")
      {:decode, _, _} -> invalid.("malformed percent-encoding")
      {:option, true} -> invalid.("a resolution option is not a DID URL parameter")
      {:known, false} -> {:ok, options, seen}
      {:seen, true} -> invalid.("a parameter is given more than once")
      {:error, _, _} = error -> error
    end
  end

  defp url_option("src", value, options, _invalid) do
    with {:ok, refs} <- src_references(value), do: {:ok, Map.merge(options, refs)}
  end

  defp url_option("versionNumber", value, options, invalid) do
    if Regex.match?(~r/\A[1-9][0-9]{0,15}\z/, value),
      do: {:ok, Map.put(options, "versionNumber", String.to_integer(value))},
      else: invalid.("versionNumber must be a positive integer")
  end

  defp url_option(key, value, options, _invalid), do: {:ok, Map.put(options, key, value)}

  # ---------------------------------------------------------------- resolve

  @selectors ~w(versionId versionTime versionNumber)

  @error_map %{
    not_found: "notFound",
    invalid_option: "invalidOptions",
    fork_detected: "logForked",
    min_copies_not_met: "insufficientCopies",
    unsupported_log_version: "featureNotSupported"
  }

  defp integral?(n), do: is_integer(n) or (is_float(n) and trunc(n) == n)
  defp positive_integer?(n), do: integral?(n) and n >= 1

  # did:vh Resolution Options validation (profile §5, step 2).
  defp validate_options(o, remote) when is_map(o) do
    has = &Map.has_key?(o, &1)
    invalid = fn why -> {:error, "invalidOptions", why} end

    refs = check_src_refs(o, remote)

    cond do
      has.("didLog") == has.("srcLog") ->
        invalid.("exactly one of didLog and srcLog must be given")

      has.("didWitness") and has.("srcWitness") ->
        invalid.("at most one of didWitness and srcWitness may be given")

      has.("didLog") and not is_binary(o["didLog"]) ->
        invalid.("didLog must be a string")

      has.("didWitness") and not is_list(o["didWitness"]) ->
        invalid.("didWitness must be an array")

      refs != :ok ->
        refs

      Enum.count(@selectors, has) > 1 ->
        invalid.("at most one of versionId, versionTime and versionNumber may be given")

      has.("versionId") and not is_binary(o["versionId"]) ->
        invalid.("versionId must be a string")

      has.("versionTime") and not VersionTime.valid?(o["versionTime"]) ->
        invalid.("versionTime must be a whole-second UTC ISO 8601 time")

      has.("versionNumber") and not positive_integer?(o["versionNumber"]) ->
        invalid.("versionNumber must be a positive integer")

      has.("checkWatchers") and
          not (o["checkWatchers"] == "all" or
                   (integral?(o["checkWatchers"]) and o["checkWatchers"] >= 0)) ->
        invalid.(~s(checkWatchers must be a non-negative integer or "all"))

      has.("extraWatchers") and not extra_watchers?(o["extraWatchers"]) ->
        invalid.("extraWatchers must be an array of https URLs")

      has.("minCopies") and not positive_integer?(o["minCopies"]) ->
        invalid.("minCopies must be a positive integer")

      has.("includeDidLog") and not is_boolean(o["includeDidLog"]) ->
        invalid.("includeDidLog must be a boolean")

      true ->
        {:ok, o}
    end
  end

  defp validate_options(_o, _remote),
    do: {:error, "invalidOptions", "resolution options must be an object"}

  # srcLog and srcWitness are valid references, and not local when `remote`.
  defp check_src_refs(o, remote) do
    Enum.reduce_while(~w(srcLog srcWitness), :ok, fn key, :ok ->
      with true <- Map.has_key?(o, key),
           {:ok, kind} <- check_ref(o[key]) do
        if remote and kind in ["file", "loopback"],
          do:
            {:halt,
             {:error, "invalidOptions",
              "#{key}: a resolver that serves other systems must not use local file or loopback references"}},
          else: {:cont, :ok}
      else
        false -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp extra_watchers?(w) when is_list(w),
    do: Enum.all?(w, &(is_binary(&1) and String.starts_with?(&1, "https://") and URL.valid?(&1)))

  defp extra_watchers?(_), do: false

  defp failure(code, message, vh_log) do
    problem = %{"title" => code, "detail" => message}
    problem = if vh_log, do: Map.put(problem, "vhLog", Error.to_json(vh_log)), else: problem

    %{
      "didResolutionMetadata" => %{"error" => code, "problemDetails" => problem},
      "didDocument" => nil,
      "didDocumentMetadata" => %{}
    }
  end

  defp current_time,
    do: DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

  @doc """
  did:vh `resolve(did, resolutionOptions)` (profile §5), returning the DID
  Resolution result as a JSON-ready map with `"didResolutionMetadata"`,
  `"didDocument"` and `"didDocumentMetadata"`.

  This resolver is offline: it verifies a log passed in `"didLog"` (and
  `"didWitness"`), and returns `featureNotSupported` when it would have to
  retrieve anything. Context options: `:now` (a `versionTime` string; default
  the current time) and `:remote` (true for a resolver that serves other
  systems).
  """
  @spec resolve(term(), term(), keyword()) :: map()
  def resolve(did, options \\ %{}, context \\ []) do
    case do_resolve(
           did,
           options,
           Keyword.get(context, :now),
           Keyword.get(context, :remote, false)
         ) do
      {:error, code, message} -> failure(code, message, nil)
      {:error, code, message, vh_log} -> failure(code, message, vh_log)
      result -> result
    end
  end

  defp do_resolve(did, options, now, remote) do
    with {:did, scid} when scid != nil <- {:did, parse_did(did)},
         {:ok, options} <- validate_options(options, remote),
         :ok <- check_retrieval(options) do
      spec = specialisation(scid)
      now = now || current_time()
      log = options["didLog"]

      clock =
        case VersionTime.parse(now) do
          {:ok, t} -> t
          :error -> System.os_time(:second)
        end

      # Whether the log needs witnessing does not depend on the witness file.
      # Without one, the first entry that needs it fails, which cuts it from
      # the entries.
      unwitnessed = VHLog.Verifier.verify_log(log, :absent, clock, spec)

      witnessed =
        (unwitnessed.failure != nil and unwitnessed.failure.code == :witness_threshold_not_met) or
          Enum.any?(unwitnessed.entries, &(&1.witness_rule != nil))

      if witnessed and Map.has_key?(options, "srcWitness") do
        {:error, "featureNotSupported", "this resolver does not retrieve srcWitness references"}
      else
        resolve_log(log, options, now, spec, witnessed)
      end
    else
      {:did, nil} -> {:error, "invalidDid", "#{inspect(did)} is not a did:vh DID"}
      error -> error
    end
  end

  defp check_retrieval(options) do
    cond do
      Map.has_key?(options, "srcLog") ->
        {:error, "featureNotSupported", "this resolver does not retrieve srcLog references"}

      Map.get(options, "checkWatchers", 0) != 0 or Map.get(options, "extraWatchers", []) != [] ->
        {:error, "featureNotSupported", "this resolver does not retrieve copies from watchers"}

      true ->
        :ok
    end
  end

  defp resolve_log(log, options, now, spec, witnessed) do
    input =
      %{"log" => log, "now" => now, "options" => Map.take(options, @selectors ++ ["minCopies"])}

    input =
      if Map.has_key?(options, "didWitness"),
        do: Map.put(input, "witness", options["didWitness"]),
        else: input

    selected = Enum.any?(@selectors, &Map.has_key?(options, &1))

    case Resolver.resolve(input, spec) do
      {:error, %Error{} = e} ->
        {:error, Map.get(@error_map, e.code, "invalidDid"), e.message, e}

      {:ok, %{error: %Error{code: :unsupported_log_version} = e}} when not selected ->
        # Entries after the last valid one may change the document or its keys (profile §5).
        {:error, "featureNotSupported", e.message, e}

      {:ok, resolution} ->
        success(resolution, log, options, witnessed)
    end
  end

  defp success(resolution, log, options, witnessed) do
    m = resolution.metadata
    # A deactivated DID's document is not returned; earlier versions still are (profile §5).
    last? = m["versionTime"] == m["updated"]

    document_metadata =
      m
      |> Map.take(~w(versionId versionTime created updated scid deactivated ttl watchers))
      |> then(&if(m["witness"], do: Map.put(&1, "witness", m["witness"]), else: &1))

    meta = %{"contentType" => "application/did+json"}
    meta = if m["warnings"] != [], do: Map.put(meta, "warnings", m["warnings"]), else: meta

    meta =
      if options["includeDidLog"] == true do
        lines = Log.lines(log)

        valid =
          if resolution.first_invalid_version,
            do: resolution.first_invalid_version - 1,
            else: length(lines)

        did_log = lines |> Enum.take(valid) |> Enum.map_join(&(&1 <> "\n"))
        meta = Map.put(meta, "didLog", did_log)

        if witnessed do
          witness = if is_list(options["didWitness"]), do: options["didWitness"], else: []
          Map.put(meta, "didWitness", witness)
        else
          meta
        end
      else
        meta
      end

    %{
      "didResolutionMetadata" => meta,
      "didDocument" => if(m["deactivated"] and last?, do: nil, else: resolution.state),
      "didDocumentMetadata" => document_metadata
    }
  end
end
