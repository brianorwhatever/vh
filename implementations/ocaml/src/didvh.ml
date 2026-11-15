(* did:vh (didvh-interop-0) on top of the VH-Log verifier. *)
open Json

exception Bad

let base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

(* ---------------------------------------------------------------- DIDs *)

let did_scid did =
  if
    String.length did = 53
    && String.sub did 0 7 = "did:vh:"
    && String.for_all (String.contains base58) (String.sub did 7 46)
  then Some (String.sub did 7 46)
  else None

let version_syntax v =
  let number x =
    x <> ""
    && String.for_all (fun c -> c >= '0' && c <= '9') x
    && (x = "0" || x.[0] <> '0')
  in
  String.starts_with ~prefix:"did:vh:" v
  &&
  match String.split_on_char '.' (String.sub v 7 (String.length v - 7)) with
  | [ major; minor ] -> number major && number minor
  | _ -> false

let parameter_names =
  [ "method"; "scid"; "updateKeys"; "nextKeyHashes"; "witness"; "watchers"; "deactivated"; "ttl" ]

(* The specialisation for resolving [scid]'s DID: closed parameters, [method]
   and the state check. *)
let spec ~scid : Vh_log.spec =
  {
    version_param = "method";
    accepted = [ "did:vh:1.0" ];
    version_syntax = Some version_syntax;
    closed = Some parameter_names;
    state_check =
      Some (fun log_scid state -> log_scid = scid && get "id" state = String ("did:vh:" ^ log_scid));
  }

(* ---------------------------------------------------------------- text helpers *)

let printable s = s <> "" && String.for_all (fun c -> c >= '!' && c <= '~') s
let drop n s = String.sub s n (String.length s - n)
let take n s = String.sub s 0 n
let is_digit c = c >= '0' && c <= '9'

let index_any s chars =
  let rec go i =
    if i >= String.length s then String.length s
    else if List.mem s.[i] chars then i
    else go (i + 1)
  in
  go 0

(* Percent-decodes once; the result must be UTF-8. *)
let percent_decode s =
  let hex c =
    match c with
    | '0' .. '9' -> Char.code c - 48
    | 'a' .. 'f' -> Char.code c - 87
    | 'A' .. 'F' -> Char.code c - 55
    | _ -> raise Bad
  in
  let b = Buffer.create (String.length s) in
  let n = String.length s in
  let rec go i =
    if i < n then
      if s.[i] = '%' then (
        if i + 2 >= n then raise Bad;
        Buffer.add_char b (Char.chr ((hex s.[i + 1] * 16) + hex s.[i + 2]));
        go (i + 3))
      else (
        Buffer.add_char b s.[i];
        go (i + 1))
  in
  go 0;
  let d = Buffer.contents b in
  if not (String.is_valid_utf_8 d) then raise Bad;
  d

let white_space u =
  (u >= 0x09 && u <= 0x0d)
  || u = 0x20 || u = 0x85 || u = 0xa0 || u = 0x1680
  || (u >= 0x2000 && u <= 0x200a)
  || u = 0x2028 || u = 0x2029 || u = 0x202f || u = 0x205f || u = 0x3000

let first_char d = Uchar.to_int (Uchar.utf_decode_uchar (String.get_utf_8_uchar d 0))

let last_char d =
  let rec start i = if Char.code d.[i] land 0xc0 = 0x80 then start (i - 1) else i in
  first_char (drop (start (String.length d - 1)) d)

(* A path segment of a reference; [strict] adds the src rules. *)
let segment ?(strict = false) seg =
  let d = percent_decode seg in
  if d = "." || d = ".." || String.contains d '/' || String.contains d '\\' || String.contains d '\000'
  then raise Bad;
  if strict && (d = "" || white_space (first_char d) || white_space (last_char d)) then raise Bad

let scheme s =
  match String.index_opt s ':' with
  | Some i
    when i > 0
         && (match s.[0] with 'a' .. 'z' | 'A' .. 'Z' -> true | _ -> false)
         && String.for_all
              (function
                | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '.' | '-' -> true | _ -> false)
              (take i s) ->
      (String.lowercase_ascii (take i s), drop (i + 1) s)
  | _ -> raise Bad

(* Host (lowercase) and whether it is an IP literal; checks the port. *)
let host_port authority =
  if String.contains authority '@' then raise Bad;
  let host, port =
    if authority <> "" && authority.[0] = '[' then
      match String.index_opt authority ']' with
      | None -> raise Bad
      | Some j ->
          let rest = drop (j + 1) authority in
          ( take (j + 1) authority,
            if rest = "" then None else if rest.[0] = ':' then Some (drop 1 rest) else raise Bad )
    else
      match String.index_opt authority ':' with
      | None -> (authority, None)
      | Some j -> (take j authority, Some (drop (j + 1) authority))
  in
  (match port with
  | Some p ->
      let l = String.length p in
      if l < 1 || l > 5 || (not (String.for_all is_digit p)) || int_of_string p > 65535 then raise Bad
  | None -> ());
  (String.lowercase_ascii host, host <> "" && host.[0] = '[')

let domain host =
  let h =
    if host <> "" && host.[String.length host - 1] = '.' then take (String.length host - 1) host
    else host
  in
  let labels = String.split_on_char '.' h in
  String.length h >= 1
  && String.length h <= 253
  && List.for_all
       (fun l ->
         let n = String.length l in
         n >= 1 && n <= 63
         && String.for_all (function 'a' .. 'z' | '0' .. '9' | '-' -> true | _ -> false) l
         && l.[0] <> '-'
         && l.[n - 1] <> '-')
       labels
  && not (String.for_all is_digit (List.nth labels (List.length labels - 1)))

let octet x =
  x <> ""
  && String.length x <= 3
  && String.for_all is_digit x
  && (x = "0" || x.[0] <> '0')
  && int_of_string x <= 255

let loopback host =
  host = "localhost" || host = "[::1]"
  ||
  match String.split_on_char '.' host with
  | [ a; b; c; d ] -> a = "127" && List.for_all octet [ b; c; d ]
  | _ -> false

let path_segments path = List.iter segment (String.split_on_char '/' (drop 1 path))

(* ---------------------------------------------------------------- references *)

(* §3.1: the kind of a srcLog/srcWitness reference, or None (invalidOptions). *)
let reference_kind = function
  | String r -> (
      try
        if (not (printable r)) || String.contains r '#' then raise Bad;
        let scheme, rest = scheme r in
        match scheme with
        | "https" | "http" ->
            if not (String.starts_with ~prefix:"//" rest) then raise Bad;
            let rest = drop 2 rest in
            let a = index_any rest [ '/'; '?' ] in
            let after = drop a rest in
            let path = take (index_any after [ '?' ]) after in
            let host, literal = host_port (take a rest) in
            if scheme = "https" then (if literal || not (domain host) then raise Bad)
            else if not (loopback host) then raise Bad;
            if path = "" then raise Bad;
            path_segments path;
            Some (if scheme = "https" then "web" else "loopback")
        | "file" ->
            if String.contains rest '?' then raise Bad;
            let path =
              if String.starts_with ~prefix:"//" rest then (
                let r = drop 2 rest in
                let j = index_any r [ '/' ] in
                let host = String.lowercase_ascii (take j r) in
                if host <> "" && host <> "localhost" then raise Bad;
                drop j r)
              else rest
            in
            if path = "" || path.[0] <> '/' then raise Bad;
            path_segments path;
            Some "file"
        | _ ->
            if rest = "" then raise Bad;
            Some "other"
      with Bad | Invalid_argument _ | Failure _ -> None)
  | _ -> None

(* §3.2: srcLog and srcWitness from a decoded src value, or None (invalidDidUrl). *)
let src_locations src =
  try
    if (not (printable src)) || String.contains src '?' || String.contains src '#' then raise Bad;
    let scheme, rest = scheme src in
    if scheme = "http" || scheme = "file" || not (String.starts_with ~prefix:"//" rest) then
      raise Bad;
    let rest = if String.ends_with ~suffix:"/" rest then take (String.length rest - 1) rest else rest in
    let r = drop 2 rest in
    let j = index_any r [ '/' ] in
    let authority = take j r and path = drop j r in
    if authority = "" then raise Bad;
    if scheme = "https" then (
      let host, literal = host_port authority in
      if literal || not (domain host) then raise Bad;
      if path <> "" then List.iter (segment ~strict:true) (String.split_on_char '/' (drop 1 path)));
    let base = scheme ^ ":" ^ rest in
    Some (base ^ "/did.jsonl", base ^ "/did-witness.json")
  with Bad | Invalid_argument _ | Failure _ -> None

(* ---------------------------------------------------------------- DID URLs *)

let resolution_options =
  [ "didLog"; "didWitness"; "srcLog"; "srcWitness"; "checkWatchers"; "extraWatchers"; "minCopies"; "includeDidLog" ]

let version_number v =
  let n = String.length v in
  n >= 1 && n <= 16 && v.[0] >= '1' && v.[0] <= '9' && String.for_all is_digit v

(* §4: Some (did, options, fragment) or None (invalidDidUrl). *)
let parse_did_url = function
  | String url -> (
      try
        let before, fragment =
          match String.index_opt url '#' with
          | Some i -> (take i url, Some (drop (i + 1) url))
          | None -> (url, None)
        in
        let did, query =
          match String.index_opt before '?' with
          | Some i -> (take i before, Some (drop (i + 1) before))
          | None -> (before, None)
        in
        if did_scid did = None then raise Bad;
        let options = ref [] and seen = ref [] in
        let add k v = options := !options @ [ (k, v) ] in
        Option.iter
          (fun q ->
            List.iter
              (fun part ->
                let i = match String.index_opt part '=' with Some i -> i | None -> raise Bad in
                let name = percent_decode (take i part) and value = percent_decode (drop (i + 1) part) in
                if List.mem name resolution_options then raise Bad;
                if List.mem name [ "src"; "versionId"; "versionTime"; "versionNumber" ] then (
                  if List.mem name !seen then raise Bad;
                  seen := name :: !seen;
                  match name with
                  | "src" -> (
                      match src_locations value with
                      | Some (log, witness) ->
                          add "srcLog" (String log);
                          add "srcWitness" (String witness)
                      | None -> raise Bad)
                  | "versionNumber" ->
                      if not (version_number value) then raise Bad;
                      add "versionNumber" (Number (float_of_string value))
                  | _ -> add name (String value)))
              (String.split_on_char '&' q))
          query;
        Some (did, !options, fragment)
      with Bad | Invalid_argument _ | Failure _ -> None)
  | _ -> None

(* ---------------------------------------------------------------- generation *)

let controller input =
  Object
    [
      ("state", get "document" input);
      ("parameters", if has "parameters" input then get "parameters" input else Object []);
      ("versionTime", get "versionTime" input);
      ("signers", get "signers" input);
    ]

let create input =
  let out =
    Vh_log.create_json
      ~defaults:[ ("method", "did:vh:1.0"); ("scid", "{SCID}") ]
      (controller input)
  in
  set "did" (String ("did:vh:" ^ str (get "scid" out))) out

let update input = Vh_log.update_json (set "log" (get "log" input) (controller input))

(* ---------------------------------------------------------------- resolution *)

exception Did_error of string * string * t option

let error_code = function
  | "not-found" -> "notFound"
  | "invalid-option" -> "invalidOptions"
  | "unsupported-log-version" -> "featureNotSupported"
  | "fork-detected" -> "logForked"
  | "min-copies-not-met" -> "insufficientCopies"
  | _ -> "invalidDid"

let integer_at_least m = function Number f -> Float.is_integer f && f >= m | _ -> false

(* The log lines a VH-Log verifier sees: split on LF, final terminator dropped. *)
let log_lines log =
  let xs = String.split_on_char '\n' log in
  if String.ends_with ~suffix:"\n" log then List.filteri (fun i _ -> i < List.length xs - 1) xs
  else xs

(* Whether some entry sets a non-empty witness list, so some entry has an
   active one. *)
let needs_witnessing lines =
  List.exists
    (fun line ->
      try match get "witness" (get "parameters" (parse line)) with Object (_ :: _) -> true | _ -> false
      with _ -> false)
    lines

let resolve_exn ~did ~options ~now ~remote =
  let scid =
    match did with
    | String d -> ( match did_scid d with Some s -> s | None -> raise (Did_error ("invalidDid", "not a did:vh DID", None)))
    | _ -> raise (Did_error ("invalidDid", "not a did:vh DID", None))
  in
  let bad m = raise (Did_error ("invalidOptions", m, None)) in
  let unsupported m = raise (Did_error ("featureNotSupported", m, None)) in
  (match options with Object _ -> () | _ -> bad "options must be an object");
  let has k = has k options and get k = get k options in
  if has "didLog" = has "srcLog" then bad "exactly one of didLog and srcLog is required";
  if has "didWitness" && has "srcWitness" then bad "didWitness and srcWitness are exclusive";
  if has "didLog" && (match get "didLog" with String _ -> false | _ -> true) then bad "didLog must be a string";
  if has "didWitness" && (match get "didWitness" with Array _ -> false | _ -> true) then
    bad "didWitness must be an array";
  List.iter
    (fun k ->
      if has k then
        match reference_kind (get k) with
        | None -> bad (k ^ " is not a valid reference")
        | Some ("file" | "loopback") when remote -> bad (k ^ " is local")
        | Some _ -> ())
    [ "srcLog"; "srcWitness" ];
  let selectors = List.filter has [ "versionId"; "versionTime"; "versionNumber" ] in
  if List.length selectors > 1 then bad "more than one version selector";
  if has "versionId" && (match get "versionId" with String _ -> false | _ -> true) then bad "versionId";
  if has "versionTime" && (match get "versionTime" with String t -> not (Vh_log.valid_time t) | _ -> true) then
    bad "versionTime";
  if has "versionNumber" && not (integer_at_least 1. (get "versionNumber")) then bad "versionNumber";
  if has "checkWatchers" && not (integer_at_least 0. (get "checkWatchers") || get "checkWatchers" = String "all")
  then bad "checkWatchers";
  if
    has "extraWatchers"
    &&
    match get "extraWatchers" with
    | Array xs ->
        not
          (List.for_all
             (function
               | String u -> String.starts_with ~prefix:"https://" u && Vh_log.valid_watcher_url u
               | _ -> false)
             xs)
    | _ -> true
  then bad "extraWatchers";
  if has "minCopies" && not (integer_at_least 1. (get "minCopies")) then bad "minCopies";
  if has "includeDidLog" && (match get "includeDidLog" with Bool _ -> false | _ -> true) then
    bad "includeDidLog";
  if has "srcLog" then unsupported "retrieving srcLog is not supported";
  if has "checkWatchers" && get "checkWatchers" <> Number 0. then unsupported "checkWatchers";
  if has "extraWatchers" && get "extraWatchers" <> Array [] then unsupported "extraWatchers";
  let log = str (get "didLog") in
  let lines = log_lines log in
  if has "srcWitness" && needs_witnessing lines then unsupported "retrieving srcWitness is not supported";
  let input =
    Object
      ([ ("log", String log); ("now", now) ]
      @ (if has "didWitness" then [ ("witness", get "didWitness") ] else [])
      @ [
          ( "options",
            Object
              (List.filter_map
                 (fun k -> if has k then Some (k, get k) else None)
                 [ "versionId"; "versionTime"; "versionNumber"; "minCopies" ]) );
        ])
  in
  let result = Vh_log.resolve_json ~spec:(spec ~scid) input in
  let vh_error e = raise (Did_error (error_code (str (Json.get "code" e)), str (Json.get "message" e), Some e)) in
  if Json.get "valid" result <> Bool true then vh_error (Json.get "error" result);
  let error = Json.get "error" result in
  if selectors = [] && error <> Null && Json.get "code" error = String "unsupported-log-version" then
    vh_error error;
  let md = Json.get "metadata" result in
  let valid_count =
    match Json.get "firstInvalidVersion" result with
    | Number f -> int_of_float f - 1
    | _ -> List.length lines
  in
  let valid_lines = List.filteri (fun i _ -> i < valid_count) lines in
  let deactivated = Json.get "deactivated" md = Bool true in
  let latest = Json.get "versionNumber" md = Number (float_of_int valid_count) in
  let field k = (k, Json.get k md) in
  let document_metadata =
    List.map field [ "versionId"; "versionTime"; "created"; "updated"; "scid"; "deactivated"; "ttl" ]
    @ (if Json.get "witness" md = Null then [] else [ field "witness" ])
    @ [ field "watchers" ]
  in
  let warnings = Json.get "warnings" md in
  let resolution_metadata =
    [ ("contentType", String "application/did+json") ]
    @ (match warnings with Array (_ :: _) -> [ ("warnings", warnings) ] | _ -> [])
    @
    if get "includeDidLog" = Bool true then
      [ ("didLog", String (String.concat "" (List.map (fun l -> l ^ "\n") valid_lines))) ]
      @
      if needs_witnessing valid_lines then
        [ ("didWitness", if has "didWitness" then get "didWitness" else Array []) ]
      else []
    else []
  in
  Object
    [
      ("didResolutionMetadata", Object resolution_metadata);
      ("didDocument", if deactivated && latest then Null else Json.get "state" result);
      ("didDocumentMetadata", Object document_metadata);
    ]

let resolve ?(remote = false) ~now did options =
  try resolve_exn ~did ~options ~now ~remote
  with Did_error (code, detail, vh_log) ->
    Object
      [
        ( "didResolutionMetadata",
          Object
            [
              ("error", String code);
              ( "problemDetails",
                Object
                  ([ ("title", String code); ("detail", String detail) ]
                  @ match vh_log with Some e -> [ ("vhLog", e) ] | None -> []) );
            ] );
        ("didDocument", Null);
        ("didDocumentMetadata", Object []);
      ]

(* ---------------------------------------------------------------- driver ops *)

let invalid_result code = Object [ ("valid", Bool false); ("error", String code) ]

let dispatch op input =
  match op with
  | "didvh-create" -> create input
  | "didvh-update" -> update input
  | "didvh-resolve" ->
      resolve
        ~remote:(Json.get "remote" input = Bool true)
        ~now:(Json.get "now" input) (Json.get "did" input)
        (if has "options" input then Json.get "options" input else Object [])
  | "didvh-ref" -> (
      match reference_kind (Json.get "ref" input) with
      | Some kind -> Object [ ("valid", Bool true); ("kind", String kind) ]
      | None -> invalid_result "invalidOptions")
  | "didvh-src" -> (
      match Json.get "src" input with
      | String src -> (
          match src_locations src with
          | Some (log, witness) ->
              Object [ ("valid", Bool true); ("srcLog", String log); ("srcWitness", String witness) ]
          | None -> invalid_result "invalidDidUrl")
      | _ -> invalid_result "invalidDidUrl")
  | "didvh-did-url" -> (
      match parse_did_url (Json.get "didUrl" input) with
      | Some (did, options, fragment) ->
          Object
            ([ ("valid", Bool true); ("did", String did); ("options", Object options) ]
            @ match fragment with Some f -> [ ("fragment", String f) ] | None -> [])
      | None -> invalid_result "invalidDidUrl")
  | _ -> raise Not_found

(* VH-Log operations plus the did:vh ones. *)
let perform op input =
  if String.starts_with ~prefix:"didvh-" op then
    try Ok (dispatch op input) with
    | Json.Invalid e | Invalid_argument e | Stdlib.Failure e -> Error e
    | Not_found -> Error "unknown operation"
    | e -> Error (Printexc.to_string e)
  else Vh_log.perform op input
