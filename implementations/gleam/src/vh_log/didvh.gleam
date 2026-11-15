//// did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
//// verification as a VH-Log log (both are derived from did:webvh), so the log
//// is verified by `vh_log` with the did:vh `Spec`. This module adds the DID
//// syntax, the srcLog/srcWitness and DID URL rules, the resolution options,
//// and DID Resolution metadata and errors.
////
//// Checks return `Error(#(code, message))` with a did:vh error code such as
//// `invalidOptions`.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import json_value.{type Json, Arr, Boolean, Null, Str} as j
import primitives as p
import vh_log

pub const method = "did:vh:1.0"

const prefix = "did:vh:"

const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

pub type Failure =
  #(String, String)

@external(erlang, "binary", "split")
fn split_once(subject: String, pattern: String) -> List(String)

@external(erlang, "vh_native", "split_all")
fn split_all(subject: String, pattern: String) -> List(String)

@external(erlang, "vh_native", "contains")
fn contains(subject: String, pattern: String) -> Bool

@external(erlang, "vh_native", "now")
fn current_time() -> String

// ---------------------------------------------------------------- bytes

fn bytes(s: String) -> List(Int) {
  to_bytes(<<s:utf8>>, [])
}

fn to_bytes(b: BitArray, acc: List(Int)) -> List(Int) {
  case b {
    <<c, rest:bytes>> -> to_bytes(rest, [c, ..acc])
    _ -> list.reverse(acc)
  }
}

fn from_bytes(b: List(Int)) -> Result(String, Nil) {
  list.fold(b, <<>>, fn(acc, c) { <<acc:bits, c>> }) |> bit_array.to_string
}

fn digit(c: Int) -> Bool {
  c >= 0x30 && c <= 0x39
}

fn alpha(c: Int) -> Bool {
  { c >= 0x41 && c <= 0x5a } || { c >= 0x61 && c <= 0x7a }
}

fn digits(s: String) -> Bool {
  s != "" && list.all(bytes(s), digit)
}

/// `0` or a decimal integer without leading zeros, of at most `max` digits.
fn plain_integer(s: String, max: Int) -> Bool {
  case bytes(s) {
    [0x30] -> True
    [first, ..] as b -> first != 0x30 && list.length(b) <= max && digits(s)
    [] -> False
  }
}

fn natural(s: String) -> Bool {
  plain_integer(s, string.byte_size(s))
}

fn strip_prefix(s: String, start: String) -> Result(String, Nil) {
  case split_once(s, start) {
    ["", rest] -> Ok(rest)
    _ -> Error(Nil)
  }
}

fn strip_suffix(s: String, end: Int) -> String {
  case list.last(bytes(s)) {
    Ok(c) if c == end -> {
      let b = <<s:utf8>>
      let assert Ok(head) = bit_array.slice(b, 0, bit_array.byte_size(b) - 1)
      let assert Ok(head) = bit_array.to_string(head)
      head
    }
    _ -> s
  }
}

/// Splits `s` at the first byte in `stops` (an ASCII character).
fn break_at(s: String, stops: List(Int)) -> #(String, String) {
  let b = <<s:utf8>>
  let i =
    bytes(s)
    |> list.take_while(fn(c) { !list.contains(stops, c) })
    |> list.length
  let assert Ok(head) = bit_array.slice(b, 0, i)
  let assert Ok(tail) = bit_array.slice(b, i, bit_array.byte_size(b) - i)
  let assert Ok(head) = bit_array.to_string(head)
  let assert Ok(tail) = bit_array.to_string(tail)
  #(head, tail)
}

// ---------------------------------------------------------------- the DID

/// The SCID of a did:vh DID, or `Error(Nil)` if it does not match the ABNF.
pub fn parse_did(did: Json) -> Result(String, Nil) {
  use scid <- result.try(strip_prefix(j.text(did), prefix))
  let alphabet = bytes(base58)
  case
    list.length(bytes(scid)) == 46
    && list.all(bytes(scid), list.contains(alphabet, _))
  {
    True -> Ok(scid)
    False -> Error(Nil)
  }
}

fn method_syntax(value: String) -> Bool {
  case strip_prefix(value, prefix) {
    Ok(version) ->
      case split_all(version, ".") {
        [major, minor] -> natural(major) && natural(minor)
        _ -> False
      }
    Error(_) -> False
  }
}

/// The did:vh specialisation of VH-Log: `method` instead of `logVersion`, a
/// closed parameter set, and `state.id` = `did:vh:<SCID>` in every entry. With
/// `expected_scid`, the log's SCID must also be that of the DID being resolved.
pub fn spec(expected_scid: Option(String)) -> vh_log.Spec {
  vh_log.Spec(
    version_parameter: "method",
    versions: [method],
    version_syntax: Some(method_syntax),
    closed: True,
    check_state: fn(state, scid, n) {
      let other = case expected_scid {
        Some(expected) -> expected != scid
        None -> False
      }
      case other || j.get(state, "id") != Str(prefix <> scid) {
        True -> Error(vh_log.error("invalid-state", n))
        False -> Ok(Nil)
      }
    },
  )
}

// ---------------------------------------------------------------- create / update

/// Creates a did:vh DID log from `{document, parameters, versionTime,
/// signers}`; `method` and `scid` are added to the parameters if absent.
pub fn create(input: Json) -> Json {
  let created =
    input
    |> j.set("state", j.get(input, "document"))
    |> vh_log.create_with("method", method)
  j.set(created, "did", Str(prefix <> j.text(j.get(created, "scid"))))
}

/// Appends an entry to a did:vh DID log from `{log, document, parameters,
/// versionTime, signers}`. Deactivate with parameters `{"deactivated": true}`.
pub fn update(input: Json) -> Json {
  input |> j.set("state", j.get(input, "document")) |> vh_log.update
}

// ---------------------------------------------------------------- shared URL checks

const whitespace = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002,
  0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029,
  0x202f, 0x205f, 0x3000,
]

fn hex(c: Int) -> Result(Int, Nil) {
  case c {
    _ if c >= 0x30 && c <= 0x39 -> Ok(c - 0x30)
    _ if c >= 0x41 && c <= 0x46 -> Ok(c - 0x37)
    _ if c >= 0x61 && c <= 0x66 -> Ok(c - 0x57)
    _ -> Error(Nil)
  }
}

fn unescape(b: List(Int), acc: List(Int)) -> Result(List(Int), Nil) {
  case b {
    [] -> Ok(list.reverse(acc))
    [0x25, h, l, ..rest] -> {
      use x <- result.try(hex(h))
      use y <- result.try(hex(l))
      unescape(rest, [x * 16 + y, ..acc])
    }
    [0x25, ..] -> Error(Nil)
    [c, ..rest] -> unescape(rest, [c, ..acc])
  }
}

/// Percent-decodes `s` as UTF-8; `Error(Nil)` if an escape or the UTF-8 is
/// malformed.
pub fn percent_decode(s: String) -> Result(String, Nil) {
  unescape(bytes(s), []) |> result.try(from_bytes)
}

fn octet(s: String) -> Bool {
  plain_integer(s, 3) && result.unwrap(int.parse(s), 256) <= 255
}

fn loopback_host(host: String) -> Bool {
  case host, split_all(host, ".") {
    "localhost", _ | "[::1]", _ -> True
    _, ["127", _, _, _] as parts -> list.all(parts, octet)
    _, _ -> False
  }
}

fn label(l: String) -> Bool {
  let b = bytes(l)
  let size = list.length(b)
  size >= 1
  && size <= 63
  && list.all(b, fn(c) { digit(c) || { c >= 0x61 && c <= 0x7a } || c == 0x2d })
  && list.first(b) != Ok(0x2d)
  && list.last(b) != Ok(0x2d)
}

fn domain_name(host: String) -> Bool {
  let name = strip_suffix(host, 0x2e)
  let size = string.byte_size(name)
  let labels = split_all(name, ".")
  size >= 1
  && size <= 253
  && !digits(result.unwrap(list.last(labels), ""))
  && list.all(labels, label)
}

/// `#(scheme, rest)` of a printable-ASCII absolute URL (profile §3 steps 1–2),
/// with the scheme in lowercase.
fn split_scheme(value: Json) -> Result(#(String, String), Nil) {
  let s = j.text(value)
  let printable = list.all(bytes(s), fn(c) { c >= 0x21 && c <= 0x7e })
  case j.is_string(value) && s != "" && printable, split_once(s, ":") {
    True, [scheme, rest] ->
      case bytes(scheme) {
        [first, ..others] ->
          case
            alpha(first)
            && list.all(others, fn(c) {
              alpha(c) || digit(c) || c == 0x2b || c == 0x2e || c == 0x2d
            })
          {
            True -> Ok(#(string.lowercase(scheme), rest))
            False -> Error(Nil)
          }
        [] -> Error(Nil)
      }
    _, _ -> Error(Nil)
  }
}

fn host_and_port(authority: String) -> Result(#(String, Option(String)), Nil) {
  case string.starts_with(authority, "[") {
    True ->
      case split_once(authority, "]") {
        [inside, after] ->
          case after, strip_prefix(after, ":") {
            "", _ -> Ok(#(inside <> "]", None))
            _, Ok(port) -> Ok(#(inside <> "]", Some(port)))
            _, _ -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    False ->
      case split_once(authority, ":") {
        [host, port] -> Ok(#(host, Some(port)))
        _ -> Ok(#(authority, None))
      }
  }
}

/// Checks an `http(s)` authority (profile §3).
fn authority(value: String, scheme: String) -> Bool {
  case contains(value, "@"), host_and_port(value) {
    False, Ok(#(host, port)) -> {
      let port_ok = case port {
        None -> True
        Some(port) ->
          digits(port)
          && string.byte_size(port) <= 5
          && result.unwrap(int.parse(port), 65_536) <= 65_535
      }
      let host = string.lowercase(host)
      port_ok
      && case scheme {
        "http" -> loopback_host(host)
        _ -> !string.starts_with(host, "[") && domain_name(host)
      }
    }
    _, _ -> False
  }
}

fn edge_whitespace(segment: String) -> Bool {
  let points =
    list.map(string.to_utf_codepoints(segment), string.utf_codepoint_to_int)
  let edge = fn(c) { list.contains(whitespace, result.unwrap(c, -1)) }
  edge(list.first(points)) || edge(list.last(points))
}

/// Checks the segments of a path that starts with `/` (profile §3). With
/// `strict` (the `src` DID URL parameter) they must also be non-empty and not
/// start or end with whitespace.
fn segments(path: String, strict: Bool) -> Bool {
  let rest = result.unwrap(strip_prefix(path, "/"), "")
  path != ""
  && list.all(split_all(rest, "/"), fn(raw) {
    case percent_decode(raw) {
      Error(_) -> False
      Ok(segment) ->
        segment != "."
        && segment != ".."
        && !contains(segment, "/")
        && !contains(segment, "\\")
        && !contains(segment, "\u{0000}")
        && { !strict || { segment != "" && !edge_whitespace(segment) } }
    }
  })
}

// ---------------------------------------------------------------- srcLog / srcWitness references

/// Validates a `srcLog` or `srcWitness` reference, which names a file
/// (profile §3.1), and returns its kind: `web`, `loopback`, `file` or `other`.
/// Fails with `invalidOptions`.
pub fn check_ref(ref: Json) -> Result(String, Failure) {
  let invalid = fn(why) {
    Error(#("invalidOptions", "reference " <> j.jcs(ref) <> ": " <> why))
  }
  case split_scheme(ref) {
    Error(_) -> invalid("not a printable-ASCII absolute URL")
    Ok(#(scheme, rest)) ->
      case contains(rest, "#"), scheme {
        True, _ -> invalid("must not have a fragment")
        _, "https" | _, "http" ->
          case strip_prefix(rest, "//") {
            Error(_) -> invalid("missing authority")
            Ok(after) -> {
              let #(auth, after_authority) = break_at(after, [0x2f, 0x3f])
              let #(path, _) = break_at(after_authority, [0x3f])
              case authority(auth, scheme), path, segments(path, False) {
                False, _, _ if scheme == "http" ->
                  invalid("http is only allowed with a loopback host")
                False, _, _ -> invalid("invalid https host")
                _, "", _ -> invalid("must have a path")
                _, _, False -> invalid("invalid path segment")
                _, _, True if scheme == "http" -> Ok("loopback")
                _, _, True -> Ok("web")
              }
            }
          }
        _, "file" -> {
          let path = case strip_prefix(rest, "//") {
            Ok(after) ->
              case split_once(after, "/") {
                [host, path] ->
                  case string.lowercase(host) {
                    "" | "localhost" -> Ok("/" <> path)
                    _ -> invalid("file URL host must be empty or localhost")
                  }
                _ -> invalid("file URL needs an absolute path")
              }
            Error(_) ->
              case string.starts_with(rest, "/") {
                True -> Ok(rest)
                False -> invalid("file URL needs an absolute path")
              }
          }
          case contains(rest, "?"), path {
            True, _ -> invalid("must not have a query")
            _, Error(e) -> Error(e)
            _, Ok(path) ->
              case segments(path, False) {
                True -> Ok("file")
                False -> invalid("invalid path segment")
              }
          }
        }
        _, _ if rest == "" -> invalid("empty URL")
        _, _ -> Ok("other")
      }
  }
}

// ---------------------------------------------------------------- the src DID URL parameter

/// Validates a (percent-decoded) `src` DID URL parameter and derives
/// `#(srcLog, srcWitness)` from it (profile §3.2). Fails with `invalidDidUrl`.
pub fn src_references(src: Json) -> Result(#(String, String), Failure) {
  let invalid = fn(why) {
    Error(#("invalidDidUrl", "src " <> j.jcs(src) <> ": " <> why))
  }
  case split_scheme(src) {
    Error(_) -> invalid("not a printable-ASCII absolute URL")
    Ok(#(scheme, rest)) -> {
      let after = strip_prefix(rest, "//")
      case contains(rest, "?") || contains(rest, "#"), scheme, after {
        True, _, _ -> invalid("must not have a query or fragment")
        _, "http", _ | _, "file", _ ->
          invalid(scheme <> " is not allowed in a DID URL")
        _, _, Error(_) | _, _, Ok("") ->
          invalid("not a hierarchical URL with an authority")
        _, _, Ok(after) -> {
          case string.starts_with(after, "/") {
            True -> invalid("not a hierarchical URL with an authority")
            False -> {
              let base = strip_suffix(after, 0x2f)
              let #(auth, path) = case split_once(base, "/") {
                [auth, path] -> #(auth, "/" <> path)
                _ -> #(base, "")
              }
              let https_ok = scheme != "https" || authority(auth, "https")
              let path_ok =
                scheme != "https" || path == "" || segments(path, True)
              case https_ok, path_ok {
                False, _ -> invalid("invalid https host")
                _, False -> invalid("invalid path segment")
                True, True -> {
                  let location = scheme <> "://" <> base
                  Ok(#(
                    location <> "/did.jsonl",
                    location <> "/did-witness.json",
                  ))
                }
              }
            }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------- DID URLs

pub type DidUrl {
  DidUrl(did: String, options: Json, fragment: Option(String))
}

const url_parameters = ["src", "versionId", "versionTime", "versionNumber"]

const option_only = [
  "didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers",
  "extraWatchers", "minCopies", "includeDidLog",
]

/// Parses a did:vh DID URL as a dereferencer does (profile §4): `src`
/// becomes the `srcLog` and `srcWitness` options, and the version parameters
/// become the options of the same name. Fails with `invalidDidUrl`.
pub fn parse_did_url(did_url: Json) -> Result(DidUrl, Failure) {
  let invalid = fn(why) { #("invalidDidUrl", j.jcs(did_url) <> ": " <> why) }
  let s = j.text(did_url)
  let #(before, fragment) = case split_once(s, "#") {
    [before, fragment] -> #(before, Some(fragment))
    _ -> #(s, None)
  }
  let #(did, query) = case split_once(before, "?") {
    [did, query] -> #(did, Some(query))
    _ -> #(before, None)
  }
  case j.is_string(did_url), parse_did(Str(did)), query {
    False, _, _ -> Error(invalid("not a string"))
    _, Error(_), _ -> Error(invalid("not a did:vh DID"))
    _, _, None -> Ok(DidUrl(did, j.object([]), fragment))
    _, _, Some(query) -> {
      let parsed =
        list.try_fold(split_all(query, "&"), #(j.object([]), []), fn(acc, pair) {
          let #(options, seen) = acc
          case split_once(pair, "=") {
            [raw_key, raw_value] ->
              case percent_decode(raw_key), percent_decode(raw_value) {
                Ok(key), Ok(value) ->
                  case
                    list.contains(option_only, key),
                    list.contains(url_parameters, key),
                    list.contains(seen, key)
                  {
                    True, _, _ ->
                      Error(invalid(
                        key
                        <> " is a resolution option, not a DID URL parameter",
                      ))
                    _, False, _ -> Ok(acc)
                    _, _, True -> Error(invalid(key <> " given more than once"))
                    _, _, _ -> {
                      use options <- result.map(url_option(
                        key,
                        value,
                        options,
                        invalid,
                      ))
                      #(options, [key, ..seen])
                    }
                  }
                _, _ -> Error(invalid("malformed percent-encoding"))
              }
            _ -> Error(invalid("query parameter " <> pair <> " has no value"))
          }
        })
      use #(options, _) <- result.map(parsed)
      DidUrl(did, options, fragment)
    }
  }
}

fn url_option(
  key: String,
  value: String,
  options: Json,
  invalid: fn(String) -> Failure,
) -> Result(Json, Failure) {
  case key {
    "src" -> {
      use #(log, witness) <- result.map(src_references(Str(value)))
      options |> j.set("srcLog", Str(log)) |> j.set("srcWitness", Str(witness))
    }
    "versionNumber" ->
      case plain_integer(value, 16) && value != "0" {
        True -> {
          let assert Ok(n) = int.parse(value)
          Ok(j.set(options, key, j.int(n)))
        }
        False -> Error(invalid("versionNumber must be a positive integer"))
      }
    _ -> Ok(j.set(options, key, Str(value)))
  }
}

// ---------------------------------------------------------------- resolve

const selectors = ["versionId", "versionTime", "versionNumber"]

fn positive_integer(v: Json) -> Bool {
  j.integer(v) && j.number(v) >=. 1.0
}

fn check(condition: Bool, why: String) -> Result(Nil, Failure) {
  case condition {
    True -> Ok(Nil)
    False -> Error(#("invalidOptions", why))
  }
}

fn local_ref(o: Json, key: String, remote: Bool) -> Result(Nil, Failure) {
  case j.has(o, key) {
    False -> Ok(Nil)
    True -> {
      use kind <- result.try(check_ref(j.get(o, key)))
      check(
        !remote || { kind != "file" && kind != "loopback" },
        key
          <> ": a resolver that serves other systems must not use local file or loopback references",
      )
    }
  }
}

/// did:vh Resolution Options validation (profile §5, step 2).
fn validate_options(o: Json, remote: Bool) -> Result(Nil, Failure) {
  let has = j.has(o, _)
  use _ <- result.try(check(
    j.is_object(o),
    "resolution options must be an object",
  ))
  use _ <- result.try(check(
    has("didLog") != has("srcLog"),
    "exactly one of didLog and srcLog must be given",
  ))
  use _ <- result.try(check(
    !{ has("didWitness") && has("srcWitness") },
    "at most one of didWitness and srcWitness may be given",
  ))
  use _ <- result.try(check(
    !has("didLog") || j.is_string(j.get(o, "didLog")),
    "didLog must be a string",
  ))
  use _ <- result.try(check(
    !has("didWitness") || j.is_array(j.get(o, "didWitness")),
    "didWitness must be an array",
  ))
  use _ <- result.try(local_ref(o, "srcLog", remote))
  use _ <- result.try(local_ref(o, "srcWitness", remote))
  use _ <- result.try(check(
    list.count(selectors, has) <= 1,
    "at most one of versionId, versionTime and versionNumber may be given",
  ))
  use _ <- result.try(check(
    !has("versionId") || j.is_string(j.get(o, "versionId")),
    "versionId must be a string",
  ))
  use _ <- result.try(check(
    !has("versionTime") || result.is_ok(p.time(j.get(o, "versionTime"))),
    "versionTime must be a whole-second UTC ISO 8601 time",
  ))
  use _ <- result.try(check(
    !has("versionNumber") || positive_integer(j.get(o, "versionNumber")),
    "versionNumber must be a positive integer",
  ))
  let watchers = j.get(o, "checkWatchers")
  use _ <- result.try(check(
    !has("checkWatchers")
      || watchers == Str("all")
      || { j.integer(watchers) && j.number(watchers) >=. 0.0 },
    "checkWatchers must be a non-negative integer or \"all\"",
  ))
  let extra = j.get(o, "extraWatchers")
  use _ <- result.try(check(
    !has("extraWatchers")
      || {
      j.is_array(extra)
      && list.all(j.items(extra), fn(u) {
        string.starts_with(j.text(u), "https://") && p.url(u)
      })
    },
    "extraWatchers must be an array of https URLs",
  ))
  use _ <- result.try(check(
    !has("minCopies") || positive_integer(j.get(o, "minCopies")),
    "minCopies must be a positive integer",
  ))
  check(
    !has("includeDidLog")
      || list.contains(
      [Boolean(True), Boolean(False)],
      j.get(o, "includeDidLog"),
    ),
    "includeDidLog must be a boolean",
  )
}

fn did_error(code: String) -> String {
  case code {
    "not-found" -> "notFound"
    "invalid-option" -> "invalidOptions"
    "fork-detected" -> "logForked"
    "min-copies-not-met" -> "insufficientCopies"
    "unsupported-log-version" -> "featureNotSupported"
    _ -> "invalidDid"
  }
}

fn failure(code: String, detail: String, vh_log_error: Json) -> Json {
  let problem = j.object([#("title", Str(code)), #("detail", Str(detail))])
  let problem = case vh_log_error {
    Null -> problem
    e -> j.set(problem, "vhLog", e)
  }
  j.object([
    #(
      "didResolutionMetadata",
      j.object([#("error", Str(code)), #("problemDetails", problem)]),
    ),
    #("didDocument", Null),
    #("didDocumentMetadata", j.object([])),
  ])
}

/// did:vh `resolve(did, resolutionOptions)` (profile §5), returning
/// `{didResolutionMetadata, didDocument, didDocumentMetadata}`. This resolver
/// is offline: it verifies a log passed in `didLog` (and `didWitness`), and
/// returns `featureNotSupported` when it would have to retrieve anything.
/// `now` is the resolver's clock (default the current time); `remote` is true
/// for a resolver that serves other systems.
pub fn resolve(
  did: Json,
  options: Json,
  now: Option(String),
  remote: Bool,
) -> Json {
  let outcome = {
    use scid <- result.try(
      parse_did(did)
      |> result.replace_error(#(
        #("invalidDid", j.jcs(did) <> " is not a did:vh DID"),
        Null,
      )),
    )
    let plain = fn(r: Result(a, Failure)) {
      result.map_error(r, fn(f) { #(f, Null) })
    }
    use _ <- result.try(plain(validate_options(options, remote)))
    use _ <- result.try(case j.has(options, "srcLog") {
      True ->
        Error(#(
          #(
            "featureNotSupported",
            "this resolver does not retrieve srcLog references",
          ),
          Null,
        ))
      False -> Ok(Nil)
    })
    let watchers = j.number(j.get(options, "checkWatchers"))
    use _ <- result.try(
      case
        j.get(options, "checkWatchers") == Str("all")
        || watchers >. 0.0
        || j.items(j.get(options, "extraWatchers")) != []
      {
        True ->
          Error(#(
            #(
              "featureNotSupported",
              "this resolver does not retrieve copies from watchers",
            ),
            Null,
          ))
        False -> Ok(Nil)
      },
    )
    let spec = spec(Some(scid))
    let now = option.unwrap(now, current_time())
    let clock =
      result.lazy_unwrap(p.time(Str(now)), fn() {
        result.unwrap(p.time(Str(current_time())), 0)
      })
    let log = j.text(j.get(options, "didLog"))
    // Whether the log needs witnessing does not depend on the witness file.
    // Without one, the first entry that needs it fails, which cuts it from
    // the entries.
    let unwitnessed = vh_log.verify_log(log, Arr([]), clock, spec)
    let witnessed =
      j.get(unwitnessed.failure, "code") == Str("witness-threshold-not-met")
      || list.any(unwitnessed.entries, fn(e) { e.rule != Null })
    use _ <- result.try(case witnessed && j.has(options, "srcWitness") {
      True ->
        Error(#(
          #(
            "featureNotSupported",
            "this resolver does not retrieve srcWitness references",
          ),
          Null,
        ))
      False -> Ok(Nil)
    })
    let vh_options =
      list.fold(["minCopies", ..selectors], j.object([]), fn(acc, k) {
        case j.has(options, k) {
          True -> j.set(acc, k, j.get(options, k))
          False -> acc
        }
      })
    let request =
      j.object([
        #("log", Str(log)),
        #("now", Str(now)),
        #("options", vh_options),
      ])
    let request = case j.has(options, "didWitness") {
      True -> j.set(request, "witness", j.get(options, "didWitness"))
      False -> request
    }
    let result = vh_log.resolve_with(request, spec)
    let error = j.get(result, "error")
    let selected = list.any(selectors, j.has(options, _))
    case j.get(result, "valid"), j.get(error, "code") {
      Boolean(False), Str(code) ->
        Error(#(#(did_error(code), j.text(j.get(error, "message"))), error))
      _, Str("unsupported-log-version") if !selected ->
        // Entries after the last valid one may change the document or its keys (profile §5).
        Error(#(
          #("featureNotSupported", j.text(j.get(error, "message"))),
          error,
        ))
      _, _ -> Ok(success(result, log, options, witnessed))
    }
  }
  case outcome {
    Ok(v) -> v
    Error(#(#(code, detail), vh_log_error)) ->
      failure(code, detail, vh_log_error)
  }
}

fn success(result: Json, log: String, options: Json, witnessed: Bool) -> Json {
  let m = j.get(result, "metadata")
  let copy = fn(acc, k) { j.set(acc, k, j.get(m, k)) }
  let metadata =
    list.fold(
      [
        "versionId", "versionTime", "created", "updated", "scid", "deactivated",
        "ttl", "watchers",
      ],
      j.object([]),
      copy,
    )
  let metadata = case j.get(m, "witness") {
    Null -> metadata
    w -> j.set(metadata, "witness", w)
  }
  let meta = j.object([#("contentType", Str("application/did+json"))])
  let meta = case j.get(m, "warnings") {
    Arr([]) -> meta
    w -> j.set(meta, "warnings", w)
  }
  let meta = case j.get(options, "includeDidLog") {
    Boolean(True) -> {
      let lines = vh_log.lines(log)
      let valid = case j.get(result, "firstInvalidVersion") {
        Null -> list.length(lines)
        n -> j.to_int(n) - 1
      }
      let did_log =
        list.take(lines, valid)
        |> list.map(fn(l) { l <> "\n" })
        |> string.concat
      let meta = j.set(meta, "didLog", Str(did_log))
      case witnessed, j.get(options, "didWitness") {
        False, _ -> meta
        True, Arr(_) as w -> j.set(meta, "didWitness", w)
        True, _ -> j.set(meta, "didWitness", Arr([]))
      }
    }
    _ -> meta
  }
  // A deactivated DID's document is returned only for an explicit version selector (profile §5).
  let selected = list.any(selectors, j.has(options, _))
  let document = case j.get(m, "deactivated") == Boolean(True) && !selected {
    True -> Null
    False -> j.get(result, "state")
  }
  j.object([
    #("didResolutionMetadata", meta),
    #("didDocument", document),
    #("didDocumentMetadata", metadata),
  ])
}

// ---------------------------------------------------------------- driver results

fn rejected(r: Result(Json, Failure)) -> Json {
  case r {
    Ok(v) -> j.set(v, "valid", Boolean(True))
    Error(#(code, _)) ->
      j.object([#("valid", Boolean(False)), #("error", Str(code))])
  }
}

/// `didvh-resolve`: `{did, options, now?, remote?}`.
pub fn resolve_request(input: Json) -> Json {
  let now = case j.get(input, "now") {
    Str(s) -> Some(s)
    _ -> None
  }
  resolve(
    j.get(input, "did"),
    j.get(input, "options"),
    now,
    j.get(input, "remote") == Boolean(True),
  )
}

/// `didvh-ref`: `{ref}` → `{valid, kind}` or `{valid: false, error}`.
pub fn ref_result(input: Json) -> Json {
  check_ref(j.get(input, "ref"))
  |> result.map(fn(kind) { j.object([#("kind", Str(kind))]) })
  |> rejected
}

/// `didvh-src`: `{src}` → `{valid, srcLog, srcWitness}`.
pub fn src_result(input: Json) -> Json {
  src_references(j.get(input, "src"))
  |> result.map(fn(refs) {
    j.object([#("srcLog", Str(refs.0)), #("srcWitness", Str(refs.1))])
  })
  |> rejected
}

/// `didvh-did-url`: `{didUrl}` → `{valid, did, options, fragment?}`.
pub fn did_url_result(input: Json) -> Json {
  parse_did_url(j.get(input, "didUrl"))
  |> result.map(fn(url) {
    let v = j.object([#("did", Str(url.did)), #("options", url.options)])
    case url.fragment {
      Some(f) -> j.set(v, "fragment", Str(f))
      None -> v
    }
  })
  |> rejected
}
