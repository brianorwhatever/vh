import gleam/list
import gleam/result
import gleam/string
import json_value.{type Json, Arr, Boolean, Null, Num, Str} as j
import primitives as p

fn object(pairs: List(#(String, Json))) -> Json {
  j.object(pairs)
}

fn error(code: String, n: Int) -> Json {
  object([
    #("code", Str(code)),
    #("version", case n {
      0 -> Null
      _ -> j.int(n)
    }),
    #("message", Str(code)),
  ])
}

fn ensure(condition: Bool, code: String, n: Int) -> Result(Nil, Json) {
  case condition {
    True -> Ok(Nil)
    False -> Error(error(code, n))
  }
}

fn strings(v: Json) -> Bool {
  j.is_array(v) && list.all(j.items(v), j.is_string)
}

fn present(v: Json, k: String) -> Bool {
  j.has(v, k)
}

fn empty(v: Json) -> Bool {
  j.items(v) == []
}

fn at(a: List(a), n: Int) -> Result(a, Nil) {
  list.first(list.drop(a, n))
}

fn last(a: List(a)) -> Result(a, Nil) {
  list.first(list.reverse(a))
}

pub fn signing_input(document: Json, config: Json) -> BitArray {
  <<p.sha(j.jcs(config)):bits, p.sha(j.jcs(document)):bits>>
}

pub fn sign(document: Json, seed: String, options: Json) -> Json {
  let mk = p.multikey(seed)
  let config =
    object([
      #("type", Str("DataIntegrityProof")),
      #("cryptosuite", Str("eddsa-jcs-2022")),
      #(
        "verificationMethod",
        j.default(
          options,
          "verificationMethod",
          Str("did:key:" <> mk <> "#" <> mk),
        ),
      ),
      #("proofPurpose", Str("assertionMethod")),
    ])
  let config = case present(options, "created") {
    True -> j.set(config, "created", j.get(options, "created"))
    False -> config
  }
  j.set(
    config,
    "proofValue",
    Str(p.sign(seed, signing_input(document, config))),
  )
}

pub fn verify(document: Json, proof: Json) -> Bool {
  case
    j.get(proof, "type") == Str("DataIntegrityProof")
    && j.get(proof, "cryptosuite") == Str("eddsa-jcs-2022")
    && j.get(proof, "proofPurpose") == Str("assertionMethod")
  {
    False -> False
    True ->
      case p.method_key(j.get(proof, "verificationMethod")) {
        Error(_) -> False
        Ok(key) ->
          p.verify(
            key,
            j.get(proof, "proofValue"),
            signing_input(document, j.remove(proof, "proofValue")),
          )
      }
  }
}

pub fn scid(e: Json) -> String {
  p.hash(j.jcs(j.remove(e, "proof")))
}

pub fn entry_hash(e: Json, previous: String) -> String {
  e |> j.remove("proof") |> j.set("versionId", Str(previous)) |> j.jcs |> p.hash
}

fn lines(log: String) -> List(String) {
  let parts = string.split(log, "\n")
  case string.ends_with(log, "\n") {
    True -> list.take(parts, list.length(parts) - 1)
    False ->
      case log {
        "" -> []
        _ -> parts
      }
  }
}

pub fn create(input: Json) -> Json {
  let params =
    list.fold(
      j.fields(j.get(input, "parameters")),
      object([#("logVersion", Str("vh-log:1.0")), #("scid", Str("{SCID}"))]),
      fn(a, pair) { j.set(a, pair.0, pair.1) },
    )
  let preliminary =
    object([
      #("versionId", Str("{SCID}")),
      #("versionTime", j.get(input, "versionTime")),
      #("parameters", params),
      #("state", j.get(input, "state")),
    ])
  let id = scid(preliminary)
  let assert Ok(e) = j.parse(string.replace(j.jcs(preliminary), "{SCID}", id))
  let e = j.set(e, "versionId", Str("1-" <> entry_hash(e, id)))
  let proofs =
    list.map(j.items(j.get(input, "signers")), fn(s) {
      sign(e, j.text(s), object([#("created", j.get(input, "versionTime"))]))
    })
  let signed = j.set(e, "proof", Arr(proofs))
  object([
    #("log", Str(j.jcs(signed) <> "\n")),
    #("scid", Str(id)),
    #("versionId", j.get(e, "versionId")),
  ])
}

pub fn update(input: Json) -> Json {
  let log = j.text(j.get(input, "log"))
  let assert Ok(line) = last(lines(log))
  let assert Ok(old) = j.parse(line)
  let previous = j.get(old, "versionId")
  let assert Ok(#(n, _)) = p.version(previous)
  let e =
    object([
      #("versionId", previous),
      #("versionTime", j.get(input, "versionTime")),
      #("parameters", j.default(input, "parameters", object([]))),
      #("state", j.get(input, "state")),
    ])
  let e =
    j.set(
      e,
      "versionId",
      Str(j.jcs(j.int(n + 1)) <> "-" <> entry_hash(e, j.text(previous))),
    )
  let proofs =
    list.map(j.items(j.get(input, "signers")), fn(s) {
      sign(e, j.text(s), object([#("created", j.get(input, "versionTime"))]))
    })
  let separator = case string.ends_with(log, "\n") {
    True -> ""
    False -> "\n"
  }
  object([
    #(
      "log",
      Str(log <> separator <> j.jcs(j.set(e, "proof", Arr(proofs))) <> "\n"),
    ),
    #("versionId", j.get(e, "versionId")),
  ])
}

fn valid_witness(v: Json) -> Bool {
  let id = j.text(j.get(v, "id"))
  string.starts_with(id, "did:key:")
  && p.valid_key(Str(string.drop_start(id, 8)))
}

fn parameters(raw: Json, previous: Json, n: Int) -> Result(Json, Json) {
  use _ <- result.try(ensure(
    list.all(j.fields(raw), fn(pair) { pair.1 != Null }),
    "invalid-parameter",
    n,
  ))
  use _ <- result.try(ensure(
    { previous != Null || present(raw, "logVersion") }
      && {
      !present(raw, "logVersion")
      || j.get(raw, "logVersion") == Str("vh-log:1.0")
    },
    "unsupported-log-version",
    n,
  ))
  use _ <- result.try(ensure(
    case previous {
      Null -> j.is_string(j.get(raw, "scid")) && present(raw, "updateKeys")
      _ -> !present(raw, "scid")
    },
    "invalid-parameter",
    n,
  ))
  use _ <- result.try(ensure(
    !present(raw, "updateKeys")
      || {
      strings(j.get(raw, "updateKeys"))
      && list.all(j.items(j.get(raw, "updateKeys")), p.valid_key)
    },
    "invalid-parameter",
    n,
  ))
  use _ <- result.try(ensure(
    !present(raw, "nextKeyHashes")
      || {
      strings(j.get(raw, "nextKeyHashes"))
      && list.all(j.items(j.get(raw, "nextKeyHashes")), fn(h) {
        p.check_hash(h) == "ok"
      })
    },
    "invalid-parameter",
    n,
  ))
  let initial = case previous {
    Null ->
      object([
        #("nextKeyHashes", Arr([])),
        #("witness", Null),
        #("watchers", Arr([])),
        #("ttl", Num(3600.0)),
      ])
    _ -> previous
  }
  let params =
    list.fold(
      [
        "logVersion",
        "scid",
        "updateKeys",
        "nextKeyHashes",
        "witness",
        "watchers",
        "ttl",
      ],
      initial,
      fn(a, k) {
        case present(raw, k) {
          True -> j.set(a, k, j.get(raw, k))
          False -> a
        }
      },
    )
  let params =
    j.set(params, "deactivated", j.default(raw, "deactivated", Boolean(False)))
  use params <- result.try(witness_parameter(raw, params, n))
  use _ <- result.try(ensure(
    !present(raw, "watchers")
      || {
      strings(j.get(raw, "watchers"))
      && list.all(j.items(j.get(raw, "watchers")), p.url)
    },
    "invalid-parameter",
    n,
  ))
  use _ <- result.try(ensure(
    list.contains([Boolean(True), Boolean(False)], j.get(params, "deactivated"))
      && j.integer(j.get(params, "ttl"))
      && j.number(j.get(params, "ttl")) >=. 0.0
      && j.number(j.get(params, "ttl")) <=. 2_147_483_648.0,
    "invalid-parameter",
    n,
  ))
  use _ <- result.try(prerotation(raw, previous, n))
  Ok(params)
}

fn witness_parameter(raw: Json, params: Json, n: Int) -> Result(Json, Json) {
  case present(raw, "witness") {
    False -> Ok(params)
    True -> {
      let w = j.get(raw, "witness")
      use _ <- result.try(ensure(j.is_object(w), "invalid-parameter", n))
      case j.fields(w) {
        [] -> Ok(j.set(params, "witness", Null))
        _ -> {
          let ws = j.get(w, "witnesses")
          use _ <- result.try(ensure(
            j.is_array(ws) && !empty(ws) && list.all(j.items(ws), valid_witness),
            "invalid-parameter",
            n,
          ))
          let ids = list.map(j.items(ws), fn(x) { j.get(x, "id") })
          let t = j.get(w, "threshold")
          use _ <- result.try(ensure(
            list.length(list.unique(ids)) == list.length(ids)
              && j.integer(t)
              && j.number(t) >=. 1.0
              && j.to_int(t) <= list.length(ids),
            "invalid-parameter",
            n,
          ))
          Ok(j.set(
            params,
            "witness",
            object([#("threshold", t), #("witnesses", ws)]),
          ))
        }
      }
    }
  }
}

fn prerotation(raw: Json, previous: Json, n: Int) -> Result(Nil, Json) {
  case previous != Null && !empty(j.get(previous, "nextKeyHashes")) {
    False -> Ok(Nil)
    True -> {
      use _ <- result.try(ensure(
        present(raw, "updateKeys") && present(raw, "nextKeyHashes"),
        "prerotation-violation",
        n,
      ))
      ensure(
        list.all(j.items(j.get(raw, "updateKeys")), fn(k) {
          list.contains(
            j.items(j.get(previous, "nextKeyHashes")),
            Str(p.hash(j.text(k))),
          )
        }),
        "prerotation-violation",
        n,
      )
    }
  }
}

pub type Entry {
  Entry(e: Json, params: Json, n: Int, time: Int, rule: Json)
}

pub type Verified {
  Verified(entries: List(Entry), lines: List(String), failure: Json)
}

fn verify_entry(
  e: Json,
  previous: Result(Entry, Nil),
  now: Int,
) -> Result(Entry, Json) {
  let n = case previous {
    Ok(x) -> x.n + 1
    Error(_) -> 1
  }
  let old = case previous {
    Ok(x) -> x.params
    Error(_) -> Null
  }
  use _ <- result.try(ensure(
    j.get(old, "deactivated") != Boolean(True),
    "entry-after-deactivation",
    n,
  ))
  use _ <- result.try(ensure(
    list.length(j.fields(e)) == 5
      && j.is_string(j.get(e, "versionId"))
      && j.is_string(j.get(e, "versionTime"))
      && j.is_object(j.get(e, "parameters"))
      && j.is_object(j.get(e, "state"))
      && j.is_array(j.get(e, "proof")),
    "invalid-entry",
    n,
  ))
  use params <- result.try(parameters(j.get(e, "parameters"), old, n))
  let keys = case old == Null || !empty(j.get(old, "nextKeyHashes")) {
    True -> j.get(params, "updateKeys")
    False -> j.get(old, "updateKeys")
  }
  let rule = case
    old == Null
    || {
      present(j.get(e, "parameters"), "witness")
      && j.get(old, "witness") == Null
    }
  {
    True -> j.get(params, "witness")
    False -> j.get(old, "witness")
  }
  use _ <- result.try(ensure(!empty(j.get(e, "proof")), "invalid-proof", n))
  use _ <- result.try(
    list.try_fold(j.items(j.get(e, "proof")), Nil, fn(_, proof) {
      use mk <- result.try(
        result.map_error(
          p.method_key(j.get(proof, "verificationMethod")),
          fn(_) { error("invalid-proof", n) },
        ),
      )
      use _ <- result.try(ensure(
        list.contains(j.items(keys), Str(mk)),
        "unauthorized-key",
        n,
      ))
      ensure(verify(j.remove(e, "proof"), proof), "invalid-proof", n)
    }),
  )
  use parts <- result.try(
    result.map_error(p.version(j.get(e, "versionId")), fn(_) {
      error("invalid-version-id", n)
    }),
  )
  use _ <- result.try(ensure(parts.0 == n, "invalid-version-id", n))
  let status = p.check_hash(Str(parts.1))
  use _ <- result.try(ensure(status != "not-base58", "invalid-version-id", n))
  use _ <- result.try(ensure(status == "ok", "invalid-hash-algorithm", n))
  let previous_id = case previous {
    Ok(x) -> j.get(x.e, "versionId")
    Error(_) -> j.get(params, "scid")
  }
  use _ <- result.try(ensure(
    entry_hash(e, j.text(previous_id)) == parts.1,
    "entry-hash-mismatch",
    n,
  ))
  use t <- result.try(
    result.map_error(p.time(j.get(e, "versionTime")), fn(_) {
      error("invalid-version-time", n)
    }),
  )
  use _ <- result.try(ensure(
    case previous {
      Ok(x) -> t > x.time
      Error(_) -> True
    },
    "invalid-version-time",
    n,
  ))
  use _ <- result.try(ensure(t <= now + 300, "future-version-time", n))
  use _ <- result.try(case previous {
    Ok(_) -> Ok(Nil)
    Error(_) -> verify_scid(e, params, n)
  })
  Ok(Entry(e, params, n, t, rule))
}

fn verify_scid(e: Json, params: Json, n: Int) -> Result(Nil, Json) {
  let id = j.get(params, "scid")
  let status = p.check_hash(id)
  use _ <- result.try(ensure(
    status != "unsupported-algorithm",
    "invalid-hash-algorithm",
    n,
  ))
  use _ <- result.try(ensure(status == "ok", "scid-mismatch", n))
  let preliminary = e |> j.remove("proof") |> j.set("versionId", Str("{SCID}"))
  let assert Ok(restored) =
    j.parse(string.replace(j.jcs(preliminary), j.text(id), "{SCID}"))
  ensure(scid(restored) == j.text(id), "scid-mismatch", n)
}

fn verify_lines(
  remaining: List(String),
  entries: List(Entry),
  now: Int,
) -> #(List(Entry), Json) {
  case remaining {
    [] -> #(entries, Null)
    [line, ..rest] -> {
      let checked = {
        use e <- result.try(
          result.map_error(j.parse(line), fn(_) {
            error("invalid-log", list.length(entries) + 1)
          }),
        )
        use _ <- result.try(ensure(
          j.is_object(e),
          "invalid-log",
          list.length(entries) + 1,
        ))
        verify_entry(e, last(entries), now)
      }
      case checked {
        Error(e) -> #(entries, e)
        Ok(e) -> verify_lines(rest, list.append(entries, [e]), now)
      }
    }
  }
}

fn witness_error(
  entries: List(Entry),
  e: Entry,
  i: Int,
  file: Json,
) -> Result(Nil, Json) {
  case e.rule {
    Null -> Ok(Nil)
    _ -> {
      use _ <- result.try(ensure(
        j.is_array(file)
          && list.all(j.items(file), fn(r) {
          j.is_object(r)
          && j.is_string(j.get(r, "versionId"))
          && j.is_array(j.get(r, "proof"))
        }),
        "invalid-witness-file",
        i + 1,
      ))
      let allowed =
        list.map(j.items(j.get(e.rule, "witnesses")), fn(w) { j.get(w, "id") })
      let later =
        list.map(list.drop(entries, i), fn(x) { j.get(x.e, "versionId") })
      let ids =
        list.flat_map(j.items(file), fn(r) {
          case list.contains(later, j.get(r, "versionId")) {
            False -> []
            True ->
              list.filter_map(j.items(j.get(r, "proof")), fn(proof) {
                use mk <- result.try(
                  p.method_key(j.get(proof, "verificationMethod")),
                )
                let id = Str("did:key:" <> mk)
                case
                  list.contains(allowed, id)
                  && verify(
                    object([#("versionId", j.get(r, "versionId"))]),
                    proof,
                  )
                {
                  True -> Ok(id)
                  False -> Error(Nil)
                }
              })
          }
        })
      ensure(
        list.length(list.unique(ids)) >= j.to_int(j.get(e.rule, "threshold")),
        "witness-threshold-not-met",
        i + 1,
      )
    }
  }
}

fn verify_log(log: String, witness: Json, now: Int) -> Verified {
  let ls = lines(log)
  case ls {
    [] -> Verified([], ls, error("invalid-log", 0))
    _ -> {
      let #(entries, failure) = verify_lines(ls, [], now)
      let issues =
        list.index_map(entries, fn(e, i) {
          #(i, witness_error(entries, e, i, witness))
        })
      case list.find(issues, fn(x) { result.is_error(x.1) }) {
        Ok(#(i, Error(e))) -> Verified(list.take(entries, i), ls, e)
        _ -> Verified(entries, ls, failure)
      }
    }
  }
}

fn line_value(line: String) -> Json {
  j.parse(line) |> result.unwrap(Null)
}

fn line_id(line: String) -> Json {
  let v = j.get(line_value(line), "versionId")
  case j.is_string(v) {
    True -> v
    False -> Null
  }
}

fn id_at(ls: List(String), n: Int) -> Json {
  case at(ls, n) {
    Ok(line) -> line_id(line)
    Error(_) -> Str("")
  }
}

fn fork(n: Int, copies: List(#(String, Json))) -> Json {
  j.set(
    error("fork-detected", n),
    "fork",
    object([
      #("version", j.int(n)),
      #(
        "copies",
        Arr(
          list.map(copies, fn(c) {
            object([#("source", Str(c.0)), #("versionId", c.1)])
          }),
        ),
      ),
    ]),
  )
}

fn retained(v: Verified, source: String, id: Json) -> Result(List(Json), Json) {
  use n <- result.try(
    result.map_error(p.retained_version(id), fn(_) {
      error("invalid-option", 0)
    }),
  )
  case at(v.entries, n - 1) {
    Error(_) ->
      Ok([
        object([
          #("code", Str("retained-version-not-found")),
          #("message", Str("retained version not found")),
        ]),
      ])
    Ok(e) ->
      case j.get(e.e, "versionId") == id {
        True -> Ok([])
        False ->
          Error(
            fork(n, [#("retained", id), #(source, j.get(e.e, "versionId"))]),
          )
      }
  }
}

fn select(v: Verified, options: Json) -> Result(Entry, Json) {
  let target = case
    present(options, "versionId"),
    present(options, "versionNumber"),
    present(options, "versionTime")
  {
    True, _, _ -> {
      let found =
        list.find(v.entries, fn(e) {
          j.get(e.e, "versionId") == j.get(options, "versionId")
        })
      case
        result.is_error(found)
        && list.any(list.drop(v.lines, list.length(v.entries)), fn(l) {
          line_id(l) == j.get(options, "versionId")
        })
      {
        True -> Error(v.failure)
        False -> Ok(found)
      }
    }
    _, True, _ -> {
      let n = j.to_int(j.get(options, "versionNumber"))
      let found = at(v.entries, n - 1)
      case result.is_error(found) && n <= list.length(v.lines) {
        True -> Error(v.failure)
        False -> Ok(found)
      }
    }
    _, _, True -> {
      let assert Ok(t) = p.time(j.get(options, "versionTime"))
      let bad = case at(v.lines, list.length(v.entries)) {
        Ok(l) ->
          case p.time(j.get(line_value(l), "versionTime")) {
            Ok(it) -> it <= t
            Error(_) -> False
          }
        Error(_) -> False
      }
      case v.failure != Null && bad {
        True -> Error(v.failure)
        False -> Ok(list.find(list.reverse(v.entries), fn(e) { e.time <= t }))
      }
    }
    _, _, _ -> Ok(last(v.entries))
  }
  use chosen <- result.try(target)
  result.map_error(chosen, fn(_) { error("not-found", 0) })
}

fn output(
  v: Verified,
  options: Json,
  warnings: List(Json),
  copies: Json,
) -> Result(Json, Json) {
  use target <- result.try(select(v, options))
  let assert Ok(first) = list.first(v.entries)
  let assert Ok(final) = last(v.entries)
  let warnings = case v.failure {
    Null -> warnings
    _ ->
      list.append(warnings, [
        object([
          #("code", Str("invalid-entries")),
          #("message", j.get(v.failure, "message")),
        ]),
      ])
  }
  let meta =
    object([
      #("versionId", j.get(target.e, "versionId")),
      #("versionTime", j.get(target.e, "versionTime")),
      #("versionNumber", j.int(target.n)),
      #("created", j.get(first.e, "versionTime")),
      #("updated", j.get(final.e, "versionTime")),
      #("scid", j.get(first.params, "scid")),
      #("deactivated", j.get(final.params, "deactivated")),
      #("ttl", j.get(final.params, "ttl")),
      #("witness", j.get(final.params, "witness")),
      #("watchers", j.get(final.params, "watchers")),
      #("updateKeys", j.get(target.params, "updateKeys")),
      #("nextKeyHashes", j.get(target.params, "nextKeyHashes")),
      #("warnings", Arr(warnings)),
    ])
  let meta = case copies {
    Null -> meta
    _ -> j.set(meta, "copies", copies)
  }
  Ok(
    object([
      #("valid", Boolean(True)),
      #("state", j.get(target.e, "state")),
      #("metadata", meta),
      #("firstInvalidVersion", case v.failure {
        Null -> Null
        _ -> j.int(list.length(v.entries) + 1)
      }),
      #("error", v.failure),
    ]),
  )
}

fn warning(code: String, source: Json, message: Json) -> Json {
  object([#("code", Str(code)), #("source", source), #("message", message)])
}

type Copy {
  Copy(index: Int, raw: Json, log: Verified, status: String)
}

fn copy_id(c: Copy) -> Json {
  last(c.log.lines) |> result.map(line_id) |> result.unwrap(Null)
}

fn invalid(c: Copy) -> Copy {
  Copy(..c, status: "invalid")
}

fn invalid_warning(c: Copy) -> Json {
  warning(
    "copy-invalid",
    j.get(c.raw, "source"),
    Str("copy fails verification"),
  )
}

fn find_reference(
  copies: List(Copy),
  before: List(Copy),
  warnings: List(Json),
) -> Result(#(Copy, List(Copy), List(Json)), Json) {
  case copies {
    [] ->
      Error(case list.first(before) {
        Ok(c) -> c.log.failure
        Error(_) -> error("invalid-log", 0)
      })
    [c, ..rest] ->
      case c.status {
        "unavailable" ->
          find_reference(rest, list.append(before, [c]), warnings)
        _ ->
          case c.log.failure {
            Null -> Ok(#(c, list.append(before, [c, ..rest]), warnings))
            _ ->
              find_reference(
                rest,
                list.append(before, [invalid(c)]),
                list.append(warnings, [invalid_warning(c)]),
              )
          }
      }
  }
}

fn divergence(a: List(String), b: List(String), n: Int) -> Int {
  case a, b {
    [x, ..xs], [y, ..ys] ->
      case line_id(x) == line_id(y) {
        True -> divergence(xs, ys, n + 1)
        False -> n
      }
    _, _ -> n
  }
}

fn compare_copies(
  remaining: List(Copy),
  ref: Copy,
  done: List(Copy),
  warnings: List(Json),
) -> Result(#(Copy, List(Copy), List(Json)), Json) {
  case remaining {
    [] -> Ok(#(ref, done, warnings))
    [c, ..rest] -> {
      case c.status != "" || c.index == ref.index {
        True -> compare_copies(rest, ref, list.append(done, [c]), warnings)
        False -> {
          let rl = ref.log.lines
          let cl = c.log.lines
          let same =
            cl != []
            && list.length(cl) <= list.length(rl)
            && copy_id(c) == id_at(rl, list.length(cl) - 1)
          let extends_log =
            list.length(cl) > list.length(rl)
            && id_at(cl, list.length(rl) - 1) == copy_id(ref)
          case same, extends_log, c.log.failure {
            True, _, _ ->
              compare_copies(rest, ref, list.append(done, [c]), warnings)
            _, True, Null ->
              compare_copies(rest, c, list.append(done, [c]), warnings)
            _, _, Null -> {
              let k = divergence(rl, cl, 0)
              Error(
                fork(k + 1, [
                  #(j.text(j.get(ref.raw, "source")), id_at(rl, k)),
                  #(j.text(j.get(c.raw, "source")), id_at(cl, k)),
                ]),
              )
            }
            _, _, _ ->
              compare_copies(
                rest,
                ref,
                list.append(done, [invalid(c)]),
                list.append(warnings, [invalid_warning(c)]),
              )
          }
        }
      }
    }
  }
}

fn resolve_copies(input: Json, now: Int, options: Json) -> Result(Json, Json) {
  let primary =
    object([
      #("source", Str("primary")),
      #("log", j.get(input, "log")),
      #("witness", j.default(input, "witness", Arr([]))),
    ])
  let all =
    list.index_map([primary, ..j.items(j.get(input, "copies"))], fn(c, i) {
      Copy(
        i,
        c,
        verify_log(
          j.text(j.get(c, "log")),
          j.default(c, "witness", Arr([])),
          now,
        ),
        case present(c, "unavailable") {
          True -> "unavailable"
          False -> ""
        },
      )
    })
  let warnings =
    list.filter_map(all, fn(c) {
      case c.status {
        "unavailable" ->
          Ok(warning(
            "copy-unavailable",
            j.get(c.raw, "source"),
            j.get(c.raw, "unavailable"),
          ))
        _ -> Error(Nil)
      }
    })
  use found <- result.try(find_reference(all, [], warnings))
  use compared <- result.try(compare_copies(found.1, found.0, [], found.2))
  let #(ref, copies, warnings) = compared
  use retained_warnings <- result.try(case present(input, "retainedVersionId") {
    True ->
      retained(
        ref.log,
        j.text(j.get(ref.raw, "source")),
        j.get(input, "retainedVersionId"),
      )
    False -> Ok([])
  })
  let reports =
    list.map(copies, fn(c) {
      let status = case c.status {
        "" ->
          case list.length(c.log.lines) < list.length(ref.log.lines) {
            True -> "behind"
            False -> "current"
          }
        s -> s
      }
      let report =
        object([#("source", j.get(c.raw, "source")), #("status", Str(status))])
      case status != "unavailable" && copy_id(c) != Null {
        True -> j.set(report, "versionId", copy_id(c))
        False -> report
      }
    })
  let behind =
    list.filter_map(reports, fn(c) {
      case j.get(c, "status") {
        Str("behind") ->
          Ok(warning("copy-behind", j.get(c, "source"), Str("copy is behind")))
        _ -> Error(Nil)
      }
    })
  let count =
    list.length(
      list.filter(reports, fn(c) {
        list.contains([Str("current"), Str("behind")], j.get(c, "status"))
      }),
    )
  use _ <- result.try(ensure(
    count >= j.to_int(j.default(options, "minCopies", Num(1.0))),
    "min-copies-not-met",
    0,
  ))
  output(
    ref.log,
    options,
    list.flatten([warnings, retained_warnings, behind]),
    Arr(reports),
  )
}

pub fn resolve(input: Json) -> Json {
  let resolved = {
    use now <- result.try(
      result.map_error(p.time(j.get(input, "now")), fn(_) {
        error("invalid-option", 0)
      }),
    )
    let options = case j.get(input, "options") {
      Null -> object([])
      v -> v
    }
    use _ <- result.try(ensure(
      j.is_object(options)
        && list.all(j.fields(options), fn(pair) {
        list.contains(
          ["versionId", "versionTime", "versionNumber", "minCopies"],
          pair.0,
        )
      }),
      "invalid-option",
      0,
    ))
    use _ <- result.try(ensure(
      list.length(
        list.filter(["versionId", "versionTime", "versionNumber"], fn(k) {
          present(options, k)
        }),
      )
        <= 1,
      "invalid-option",
      0,
    ))
    use _ <- result.try(ensure(
      !present(options, "versionId") || j.is_string(j.get(options, "versionId")),
      "invalid-option",
      0,
    ))
    use _ <- result.try(ensure(
      !present(options, "versionTime")
        || result.is_ok(p.time(j.get(options, "versionTime"))),
      "invalid-option",
      0,
    ))
    use _ <- result.try(ensure(
      list.all(["versionNumber", "minCopies"], fn(k) {
        !present(options, k)
        || {
          j.integer(j.get(options, k)) && j.number(j.get(options, k)) >=. 1.0
        }
      }),
      "invalid-option",
      0,
    ))
    case
      present(input, "copies")
      || j.number(j.default(options, "minCopies", Num(1.0))) >. 1.0
    {
      True -> resolve_copies(input, now, options)
      False -> {
        let v =
          verify_log(
            j.text(j.get(input, "log")),
            j.default(input, "witness", Arr([])),
            now,
          )
        case v.entries {
          [] -> Error(v.failure)
          _ -> {
            use warnings <- result.try(
              case present(input, "retainedVersionId") {
                True ->
                  retained(v, "primary", j.get(input, "retainedVersionId"))
                False -> Ok([])
              },
            )
            output(v, options, warnings, Null)
          }
        }
      }
    }
  }
  case resolved {
    Ok(v) -> v
    Error(e) -> object([#("valid", Boolean(False)), #("error", e)])
  }
}

pub fn dispatch(op: String, input: Json) -> Result(Json, String) {
  case op {
    "jcs" -> {
      use value <- result.try(j.parse(j.text(j.get(input, "text"))))
      Ok(object([#("output", Str(j.jcs(value)))]))
    }
    "hash" ->
      Ok(object([#("output", Str(p.hash(j.text(j.get(input, "data")))))]))
    "key-hash" ->
      Ok(object([#("output", Str(p.hash(j.text(j.get(input, "multikey")))))]))
    "multikey" ->
      Ok(object([#("multikey", Str(p.multikey(j.text(j.get(input, "seed")))))]))
    "scid" -> Ok(object([#("scid", Str(scid(j.get(input, "entry"))))]))
    "entry-hash" ->
      Ok(
        object([
          #(
            "hash",
            Str(entry_hash(
              j.get(input, "entry"),
              j.text(j.get(input, "previousVersionId")),
            )),
          ),
        ]),
      )
    "sign" ->
      Ok(
        object([
          #(
            "proof",
            sign(j.get(input, "document"), j.text(j.get(input, "seed")), input),
          ),
        ]),
      )
    "verify" ->
      Ok(
        object([
          #(
            "valid",
            Boolean(verify(j.get(input, "document"), j.get(input, "proof"))),
          ),
        ]),
      )
    "witness" ->
      Ok(
        object([
          #(
            "proof",
            sign(
              object([#("versionId", j.get(input, "versionId"))]),
              j.text(j.get(input, "seed")),
              input,
            ),
          ),
        ]),
      )
    "create" -> Ok(create(input))
    "update" -> Ok(update(input))
    "resolve" -> Ok(resolve(input))
    _ -> Error("unknown operation " <> op)
  }
}

pub fn main() {
  p.run()
}
