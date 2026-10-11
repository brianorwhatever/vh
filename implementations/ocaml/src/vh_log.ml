open Json

let s x = String x
let n x = Number (float_of_int x)
let o xs = Object xs
let a xs = Array xs
let gs k j = str (get k j)

let replace text old repl =
  if old = "" then text
  else
    let b = Buffer.create (String.length text) in
    let rec loop i =
      if i >= String.length text then ()
      else if
        i + String.length old <= String.length text
        && String.sub text i (String.length old) = old
      then (
        Buffer.add_string b repl;
        loop (i + String.length old))
      else (
        Buffer.add_char b text.[i];
        loop (i + 1))
    in
    loop 0;
    Buffer.contents b

let scid entry = Crypto.hash (canonicalize (remove "proof" entry))

let entry_hash entry previous =
  Crypto.hash (canonicalize (set "versionId" (s previous) (remove "proof" entry)))

let lines log =
  String.split_on_char '\n' log |> List.filter (fun x -> String.trim x <> "")

let parse_log log =
  let xs = List.map parse (lines log) in
  if xs = [] || List.exists (function Object _ -> false | _ -> true) xs then
    invalid "empty or nonobject log";
  xs

let sign_entry doc signers =
  set "proof"
    (a
       (List.map
          (fun seed -> Crypto.sign ~created:(gs "versionTime" doc) doc (str seed))
          (arr signers)))
    doc

let create input =
  let p = get "parameters" input in
  let p = if has "scid" p then p else set "scid" (s "{SCID}") p in
  let p = if has "logVersion" p then p else set "logVersion" (s "vh-log:1.0") p in
  let preliminary =
    o
      [
        ("versionId", s "{SCID}");
        ("versionTime", get "versionTime" input);
        ("parameters", p);
        ("state", get "state" input);
      ]
  in
  let id = scid preliminary in
  let doc = parse (replace (serialize preliminary) "{SCID}" id) in
  let vid = "1-" ^ entry_hash doc id in
  let doc = set "versionId" (s vid) doc in
  let entry = sign_entry doc (get "signers" input) in
  o [ ("log", s (serialize entry ^ "\n")); ("scid", s id); ("versionId", s vid) ]

let update input =
  let log = gs "log" input in
  let entries = parse_log log in
  let last = List.hd (List.rev entries) in
  let previous = gs "versionId" last in
  let number = int_of_string (List.hd (String.split_on_char '-' previous)) + 1 in
  let doc =
    o
      [
        ("versionId", s previous);
        ("versionTime", get "versionTime" input);
        ("parameters", if has "parameters" input then get "parameters" input else o []);
        ("state", get "state" input);
      ]
  in
  let vid = string_of_int number ^ "-" ^ entry_hash doc previous in
  let entry = sign_entry (set "versionId" (s vid) doc) (get "signers" input) in
  o
    [
      ( "log",
        s
          (log
          ^ (if String.ends_with ~suffix:"\n" log then "" else "\n")
          ^ serialize entry ^ "\n") );
      ("versionId", s vid);
    ]

type error = { code : string; version : int option; fork : t option }

exception Failure of error

let fail ?version ?fork code = raise (Failure { code; version; fork })

let error_json e =
  o
    ([
       ("code", s e.code);
       ("version", match e.version with None -> Null | Some v -> n v);
       ("message", s e.code);
     ]
    @ match e.fork with None -> [] | Some f -> [ ("fork", f) ])

let timestamp text =
  let len = String.length text in
  if
    not
      ((len = 20 && String.sub text 19 1 = "Z")
      || (len = 25 && String.sub text 19 6 = "+00:00"))
  then invalid "time";
  List.iter
    (fun (i, c) -> if text.[i] <> c then invalid "time")
    [ (4, '-'); (7, '-'); (10, 'T'); (13, ':'); (16, ':') ];
  let num i l =
    let t = String.sub text i l in
    if not (String.for_all (fun c -> c >= '0' && c <= '9') t) then invalid "time";
    int_of_string t
  in
  let y = num 0 4
  and m = num 5 2
  and d = num 8 2
  and h = num 11 2
  and mi = num 14 2
  and sec = num 17 2 in
  let leap = y mod 4 = 0 && (y mod 100 <> 0 || y mod 400 = 0) in
  let days =
    [| 31; (if leap then 29 else 28); 31; 30; 31; 30; 31; 31; 30; 31; 30; 31 |]
  in
  if m < 1 || m > 12 || d < 1 || d > days.(m - 1) || h > 23 || mi > 59 || sec > 59 then
    invalid "time";
  let before_y =
    let y = y - 1 in
    (* floor division also covers year zero *)
    let div a b = if a < 0 then (a - b + 1) / b else a / b in
    (365 * (y + 1)) + div y 4 - div y 100 + div y 400
  in
  let before_m = ref 0 in
  for i = 0 to m - 2 do
    before_m := !before_m + days.(i)
  done;
  float_of_int (((before_y + !before_m + d - 1) * 86400) + (h * 3600) + (mi * 60) + sec)

let integer = function Number f -> Float.is_integer f | _ -> false
let positive = function Number f -> Float.is_integer f && f > 0. | _ -> false

let string_list validate j =
  match j with
  | Array xs -> List.for_all (function String s -> validate s | _ -> false) xs
  | _ -> false

let valid_url u =
  let len = String.length u in
  let start =
    if String.starts_with ~prefix:"https://" u then 8
    else if String.starts_with ~prefix:"http://" u then 7
    else len
  in
  start < len
  && (not (List.mem u.[start] [ '/'; '?'; '#' ]))
  && String.for_all (fun c -> c >= '!' && c <= '~') u

let valid_witness = function
  | Object [] -> true
  | Object xs as j -> (
      try
        let ws = arr (get "witnesses" j) in
        let ids =
          List.map
            (fun w ->
              let id = gs "id" w in
              if
                (not (String.starts_with ~prefix:"did:key:" id))
                || not (Crypto.valid_key (String.sub id 8 (String.length id - 8)))
              then invalid "id";
              id)
            ws
        in
        positive (get "threshold" j)
        && (match get "threshold" j with
          | Number f -> f <= float_of_int (List.length ids)
          | _ -> false)
        && ids <> []
        && List.length (List.sort_uniq compare ids) = List.length ids
        && List.length xs = 2
      with _ -> false)
  | _ -> false

let defaults =
  o
    [
      ("nextKeyHashes", a []);
      ("witness", o []);
      ("watchers", a []);
      ("deactivated", Bool false);
      ("ttl", n 3600);
    ]

let parameters version before p =
  let bad () = fail ~version "invalid-parameter" in
  List.iter
    (fun (k, v) ->
      let valid =
        match k with
        | "logVersion" -> ( match v with String _ -> true | _ -> false)
        | "scid" -> ( match v with String _ -> version = 1 | _ -> false)
        | "updateKeys" -> string_list Crypto.valid_key v
        | "nextKeyHashes" -> string_list Crypto.multihash v
        | "witness" -> valid_witness v
        | "watchers" -> string_list valid_url v
        | "deactivated" -> ( match v with Bool _ -> true | _ -> false)
        | "ttl" -> (
            match v with
            | Number f -> Float.is_integer f && f >= 0. && f <= 2147483648.
            | _ -> false)
        | _ -> true
      in
      if not valid then bad ())
    (obj p);
  if version = 1 && ((not (has "scid" p)) || not (has "updateKeys" p)) then bad ();
  if
    (version = 1 && not (has "logVersion" p))
    || (has "logVersion" p && get "logVersion" p <> s "vh-log:1.0")
  then fail ~version "unsupported-log-version";
  let pre = get "nextKeyHashes" before <> a [] in
  if version > 1 && pre then (
    if (not (has "updateKeys" p && has "nextKeyHashes" p)) || get "updateKeys" p = a []
    then fail ~version "prerotation-violation";
    let hashes = arr (get "nextKeyHashes" before) in
    List.iter
      (fun k ->
        if not (List.mem (s (Crypto.hash (str k))) hashes) then
          fail ~version "prerotation-violation")
      (arr (get "updateKeys" p)));
  let active = List.fold_left (fun j (k, v) -> set k v j) before (obj p) in
  let keys =
    if version = 1 || pre then get "updateKeys" active else get "updateKeys" before
  in
  let witness =
    if get "witness" before = o [] then get "witness" active else get "witness" before
  in
  (active, keys, witness)

type snapshot = { entry : t; params : t; witness : t }
type checked = { all : t list; valid : snapshot list; error : error option }

let check ?(prefix = []) log witness now =
  let raw_lines = String.split_on_char '\n' log in
  let raw_lines =
    if String.ends_with ~suffix:"\n" log then List.rev (List.tl (List.rev raw_lines))
    else raw_lines
  in
  if log = "" then fail "invalid-log";
  let entries =
    List.map
      (fun line ->
        try match parse line with Object _ as j -> j | _ -> Null with _ -> Null)
      raw_lines
  in
  let prefix_length = List.length prefix in
  let valid = ref prefix and error = ref None in
  let active =
    ref (if prefix = [] then defaults else (List.hd (List.rev prefix)).params)
  in
  let prev =
    ref (if prefix = [] then "" else gs "versionId" (List.hd (List.rev prefix)).entry)
  in
  let time =
    ref
      (if prefix = [] then neg_infinity
       else timestamp (gs "versionTime" (List.hd (List.rev prefix)).entry))
  in
  List.iteri
    (fun i entry ->
      if !error = None && i >= prefix_length then
        let v = i + 1 in
        try
          if get "deactivated" !active = Bool true then
            fail ~version:v "entry-after-deactivation";
          if entry = Null then fail ~version:v "invalid-log";
          let fields = obj entry in
          if
            List.length fields <> 5
            || (not
                  (List.for_all
                     (fun k -> has k entry)
                     [ "versionId"; "versionTime"; "parameters"; "state"; "proof" ]))
            || not
                 (match
                    ( get "versionId" entry,
                      get "versionTime" entry,
                      get "parameters" entry,
                      get "state" entry,
                      get "proof" entry )
                  with
                 | String _, String _, Object _, Object _, Array _ -> true
                 | _ -> false)
          then fail ~version:v "invalid-entry";
          let params, keys, w = parameters v !active (get "parameters" entry) in
          let proofs = arr (get "proof" entry) in
          if proofs = [] then fail ~version:v "invalid-proof";
          List.iter
            (fun proof ->
              let mk =
                try Crypto.method_key (gs "verificationMethod" proof)
                with _ -> fail ~version:v "invalid-proof"
              in
              if not (List.mem (s mk) (arr keys)) then
                fail ~version:v "unauthorized-key";
              if not (Crypto.verify entry proof) then fail ~version:v "invalid-proof")
            proofs;
          let vid = gs "versionId" entry in
          let hash =
            match String.split_on_char '-' vid with
            | [ number; hash ] when number = string_of_int v && hash <> "" -> hash
            | _ -> fail ~version:v "invalid-version-id"
          in
          (try ignore (Crypto.base58_decode hash)
           with _ -> fail ~version:v "invalid-version-id");
          if not (Crypto.sha256_hash hash) then fail ~version:v "invalid-hash-algorithm";
          let previous = if v = 1 then gs "scid" params else !prev in
          if entry_hash entry previous <> hash then
            fail ~version:v "entry-hash-mismatch";
          let t =
            try timestamp (gs "versionTime" entry)
            with _ -> fail ~version:v "invalid-version-time"
          in
          if t <= !time then fail ~version:v "invalid-version-time";
          if t > now +. 300. then fail ~version:v "future-version-time";
          if v = 1 then (
            let id = gs "scid" params in
            if not (Crypto.sha256_hash id) then fail ~version:v "invalid-hash-algorithm";
            let preliminary = set "versionId" (s "{SCID}") (remove "proof" entry) in
            let preliminary = parse (replace (serialize preliminary) id "{SCID}") in
            if scid preliminary <> id then fail ~version:v "scid-mismatch");
          active := params;
          prev := vid;
          time := t;
          valid := !valid @ [ { entry; params; witness = w } ]
        with
        | Failure e -> error := Some e
        | _ -> error := Some { code = "invalid-entry"; version = Some v; fork = None })
    entries;
  if !error = None && List.exists (fun sn -> sn.witness <> o []) !valid then (
    let records =
      match witness with
      | None -> Some []
      | Some (Array rs) ->
          if
            List.for_all
              (fun r ->
                try
                  List.length (obj r) = 2
                  && has "versionId" r && has "proof" r
                  &&
                  match (get "versionId" r, get "proof" r) with
                  | String _, Array _ -> true
                  | _ -> false
                with _ -> false)
              rs
          then Some rs
          else None
      | _ -> None
    in
    let first = ref None in
    List.iteri
      (fun i sn ->
        if !first = None && i >= prefix_length && sn.witness <> o [] then
          let v = i + 1 in
          match records with
          | None ->
              first :=
                Some { code = "invalid-witness-file"; version = Some v; fork = None }
          | Some rs ->
              let ids =
                List.map (fun w -> gs "id" w) (arr (get "witnesses" sn.witness))
              in
              let approved = ref [] in
              List.iter
                (fun r ->
                  let vid = gs "versionId" r in
                  let later =
                    List.exists
                      (fun sn -> gs "versionId" sn.entry = vid)
                      (List.filteri (fun k _ -> k >= i) !valid)
                  in
                  if later then
                    List.iter
                      (fun p ->
                        try
                          let mk = Crypto.method_key (gs "verificationMethod" p) in
                          let id = "did:key:" ^ mk in
                          if
                            List.mem id ids
                            && Crypto.verify (o [ ("versionId", s vid) ]) p
                          then approved := id :: !approved
                        with _ -> ())
                      (arr (get "proof" r)))
                rs;
              let count = List.length (List.sort_uniq compare !approved) in
              if
                float_of_int count
                < match get "threshold" sn.witness with Number f -> f | _ -> infinity
              then
                first :=
                  Some
                    {
                      code = "witness-threshold-not-met";
                      version = Some v;
                      fork = None;
                    })
      !valid;
    match !first with
    | None -> ()
    | Some e ->
        error := Some e;
        valid := List.filteri (fun i _ -> i + 1 < Option.get e.version) !valid);
  { all = entries; valid = !valid; error = !error }

type copy = {
  source : string;
  log : string option;
  witness_file : t option;
  mutable checked : checked option;
  mutable status : string;
}

let warning ?source code =
  o
    ([ ("code", s code); ("message", s code) ]
    @ match source with None -> [] | Some v -> [ ("source", s v) ])

let last xs = List.hd (List.rev xs)

let option_validate opts =
  List.iter
    (fun (k, v) ->
      let valid =
        match k with
        | "versionId" -> ( match v with String _ -> true | _ -> false)
        | "versionTime" -> (
            try
              ignore (timestamp (str v));
              true
            with _ -> false)
        | "versionNumber" | "minCopies" -> positive v
        | _ -> false
      in
      if not valid then fail "invalid-option")
    (obj opts);
  if
    List.length
      (List.filter
         (fun k -> has k opts)
         [ "versionId"; "versionTime"; "versionNumber" ])
    > 1
  then fail "invalid-option"

let resolve_exn input =
  let opts = if has "options" input then get "options" input else o [] in
  (try option_validate opts with
  | Failure e -> raise (Failure e)
  | _ -> fail "invalid-option");
  let now = try timestamp (gs "now" input) with _ -> fail "invalid-option" in
  let primary =
    {
      source = "primary";
      log = Some (gs "log" input);
      witness_file = (if has "witness" input then Some (get "witness" input) else None);
      checked = None;
      status = "invalid";
    }
  in
  let others =
    if has "copies" input then
      List.map
        (fun c ->
          {
            source = gs "source" c;
            log = (if has "unavailable" c then None else Some (gs "log" c));
            witness_file = (if has "witness" c then Some (get "witness" c) else None);
            checked = None;
            status = "invalid";
          })
        (arr (get "copies" input))
    else []
  in
  let copies = primary :: others in
  let inspect ?(prefix = []) c =
    match c.log with
    | None ->
        c.status <- "unavailable";
        None
    | Some log ->
        let checked =
          try Some (check ~prefix log c.witness_file now) with Failure _ -> None
        in
        c.checked <- checked;
        checked
  in
  let reference = ref None in
  List.iter
    (fun c ->
      if !reference = None then
        match inspect c with
        | Some ch when ch.error = None ->
            c.status <- "current";
            reference := Some c
        | _ -> ())
    copies;
  let fallback = !reference = None in
  (if fallback then
     match primary.checked with
     | Some ch when ch.valid <> [] -> reference := Some primary
     | Some ch -> (
         match ch.error with Some e -> raise (Failure e) | None -> fail "invalid-log")
     | None -> fail "invalid-log");
  let refcopy () = Option.get !reference in
  let refcheck () = Option.get (refcopy ()).checked in
  let fork c ch =
    let r = refcheck () in
    let rec first k a b =
      match (a, b) with
      | x :: xs, y :: ys when gs "versionId" x = gs "versionId" y -> first (k + 1) xs ys
      | x :: _, y :: _ -> (k, gs "versionId" x, gs "versionId" y)
      | _ -> fail "invalid-log"
    in
    let v, rv, cv = first 1 r.all ch.all in
    fail ~version:v
      ~fork:
        (o
           [
             ("version", n v);
             ( "copies",
               a
                 [
                   o [ ("source", s (refcopy ()).source); ("versionId", s rv) ];
                   o [ ("source", s c.source); ("versionId", s cv) ];
                 ] );
           ])
      "fork-detected"
  in
  if not fallback then
    List.iter
      (fun c ->
        if c != refcopy () then
          if match c.checked with Some ch -> ch.error <> None | None -> false then
            c.status <- "invalid"
          else
            match c.log with
            | None -> c.status <- "unavailable"
            | Some log -> (
                let raw = try Some (parse_log log) with _ -> None in
                match raw with
                | None -> c.status <- "invalid"
                | Some xs -> (
                    let r = refcheck () in
                    let count = List.length xs and rc = List.length r.all in
                    let k = min count rc in
                    let same =
                      try
                        gs "versionId" (List.nth xs (k - 1))
                        = gs "versionId" (List.nth r.all (k - 1))
                      with Json.Invalid _ -> false
                    in
                    if same && count <= rc then
                      c.status <- (if count = rc then "current" else "behind")
                    else
                      let ch =
                        match c.checked with
                        | Some ch -> Some ch
                        | None -> inspect ~prefix:(if same then r.valid else []) c
                      in
                      match ch with
                      | Some ch when ch.error = None ->
                          if same then (
                            c.status <- "current";
                            reference := Some c)
                          else fork c ch
                      | _ -> c.status <- "invalid")))
      copies;
  let r = refcheck () in
  if not fallback then
    List.iter
      (fun c ->
        if c == refcopy () then c.status <- "current"
        else if c.status = "current" || c.status = "behind" then
          match c.log with
          | Some log ->
              let xs = parse_log log in
              c.status <-
                (if List.length xs = List.length r.all then "current" else "behind")
          | _ -> ())
      copies;
  let warnings = ref [] in
  let push w = warnings := !warnings @ [ w ] in
  if not fallback then
    List.iter
      (fun c ->
        match c.status with
        | "behind" -> push (warning ~source:c.source "copy-behind")
        | "invalid" -> push (warning ~source:c.source "copy-invalid")
        | "unavailable" -> push (warning ~source:c.source "copy-unavailable")
        | _ -> ())
      copies;
  (if has "retainedVersionId" input then
     let retained = gs "retainedVersionId" input in
     let v =
       try int_of_string (List.hd (String.split_on_char '-' retained))
       with _ -> fail "invalid-option"
     in
     if v > List.length r.valid then push (warning "retained-version-not-found")
     else if v < 1 then fail "invalid-option"
     else
       let actual = gs "versionId" (List.nth r.valid (v - 1)).entry in
       if actual <> retained then
         fail ~version:v
           ~fork:
             (o
                [
                  ("version", n v);
                  ( "copies",
                    a
                      [
                        o [ ("source", s (refcopy ()).source); ("versionId", s actual) ];
                        o [ ("source", s "retained"); ("versionId", s retained) ];
                      ] );
                ])
           "fork-detected");
  let min_copies =
    if has "minCopies" opts then
      match get "minCopies" opts with Number f -> f | _ -> 1.
    else 1.
  in
  let matching =
    if fallback then 1
    else
      List.length
        (List.filter (fun c -> c.status = "current" || c.status = "behind") copies)
  in
  if float_of_int matching < min_copies then fail "min-copies-not-met";
  (if r.valid = [] then
     match r.error with Some e -> raise (Failure e) | None -> fail "invalid-log");
  let target =
    if has "versionNumber" opts then
      let f = match get "versionNumber" opts with Number f -> f | _ -> 0. in
      if f > float_of_int max_int then None else Some (int_of_float f)
    else if has "versionId" opts then
      let id = gs "versionId" opts in
      let rec find i = function
        | [] -> None
        | entry :: xs ->
            if try gs "versionId" entry = id with _ -> false then Some i
            else find (i + 1) xs
      in
      find 1 r.all
    else if has "versionTime" opts then (
      let t = timestamp (gs "versionTime" opts) in
      let found = ref None in
      List.iteri
        (fun i entry ->
          try if timestamp (gs "versionTime" entry) <= t then found := Some (i + 1)
          with _ -> ())
        r.all;
      !found)
    else Some (List.length r.valid)
  in
  let v = match target with None -> fail "not-found" | Some v -> v in
  (if v > List.length r.valid then
     match r.error with
     | Some e when v >= Option.value e.version ~default:1 -> raise (Failure e)
     | _ -> fail "not-found");
  if v < 1 then fail "not-found";
  let selected = List.nth r.valid (v - 1)
  and latest = last r.valid
  and initial = List.hd r.valid in
  (match r.error with Some _ -> push (warning "invalid-entries") | None -> ());
  let p = selected.params in
  let metadata =
    [
      ("versionId", get "versionId" selected.entry);
      ("versionTime", get "versionTime" selected.entry);
      ("versionNumber", n v);
      ("created", get "versionTime" initial.entry);
      ("updated", get "versionTime" latest.entry);
      ("scid", get "scid" initial.params);
      ("deactivated", get "deactivated" latest.params);
      ("ttl", get "ttl" p);
      ( "witness",
        if get "witness" latest.params = o [] then Null else get "witness" latest.params
      );
      ("watchers", get "watchers" p);
      ("updateKeys", get "updateKeys" p);
      ("nextKeyHashes", get "nextKeyHashes" p);
      ("warnings", a !warnings);
    ]
  in
  let include_copies =
    others <> [] || has "checkWatchers" opts || has "extraWatchers" opts
    || min_copies > 1.
  in
  let metadata =
    metadata
    @
    if include_copies then
      [
        ( "copies",
          a
            (List.map
               (fun c ->
                 let vid =
                   match c.log with
                   | None -> []
                   | Some log -> (
                       try [ ("versionId", get "versionId" (last (parse_log log))) ]
                       with _ -> [])
                 in
                 o ([ ("source", s c.source) ] @ vid @ [ ("status", s c.status) ]))
               copies) );
      ]
    else []
  in
  o
    [
      ("valid", Bool true);
      ("state", get "state" selected.entry);
      ("metadata", o metadata);
      ( "firstInvalidVersion",
        match r.error with
        | None -> Null
        | Some e -> ( match e.version with None -> Null | Some v -> n v) );
      ("error", match r.error with None -> Null | Some e -> error_json e);
    ]

let resolve input =
  try resolve_exn input
  with Failure e -> o [ ("valid", Bool false); ("error", error_json e) ]

let dispatch op input =
  match op with
  | "jcs" -> o [ ("output", s (canonicalize (parse (gs "text" input)))) ]
  | "hash" -> o [ ("output", s (Crypto.hash (gs "data" input))) ]
  | "multikey" -> o [ ("multikey", s (Crypto.multikey (gs "seed" input))) ]
  | "key-hash" -> o [ ("output", s (Crypto.hash (gs "multikey" input))) ]
  | "scid" -> o [ ("scid", s (scid (get "entry" input))) ]
  | "entry-hash" ->
      o [ ("hash", s (entry_hash (get "entry" input) (gs "previousVersionId" input))) ]
  | "sign" ->
      o
        [
          ( "proof",
            Crypto.sign
              ?verification_method:
                (if has "verificationMethod" input then
                   Some (gs "verificationMethod" input)
                 else None)
              ?created:(if has "created" input then Some (gs "created" input) else None)
              (get "document" input) (gs "seed" input) );
        ]
  | "verify" ->
      o [ ("valid", Bool (Crypto.verify (get "document" input) (get "proof" input))) ]
  | "create" -> create input
  | "update" -> update input
  | "resolve" -> resolve input
  | "witness" ->
      o
        [
          ( "proof",
            Crypto.sign
              ?created:(if has "created" input then Some (gs "created" input) else None)
              (o [ ("versionId", get "versionId" input) ])
              (gs "seed" input) );
        ]
  | _ -> invalid "unknown operation"

let perform op input =
  try Ok (dispatch op input) with
  | Json.Invalid e | Invalid_argument e | Stdlib.Failure e -> Error e
  | Failure e -> Error e.code

type controller_input = {
  state : Json.t;
  parameters : Json.t;
  version_time : string;
  signers : string list;
}
(** Typed, result-returning application API. JSON objects remain extensible so
    specialisation-specific state and parameters are preserved. *)

type generation = { log : string; version_id : string; scid : string option }

type selector =
  | Latest
  | Version_id of string
  | Version_time of string
  | Version_number of int

type supplied_copy = { source : string; log : string option; witness : Json.t option }

type resolution_request = {
  log : string;
  witness : Json.t option;
  now : string;
  selector : selector;
  min_copies : int;
  copies : supplied_copy list;
  retained_version_id : string option;
}

type resolved = {
  state : Json.t;
  metadata : Json.t;
  first_invalid_version : int option;
  error : error option;
}

type resolution = Resolved of resolved | Rejected of error

let controller_json (input : controller_input) =
  o
    [
      ("state", input.state);
      ("parameters", input.parameters);
      ("versionTime", s input.version_time);
      ("signers", a (List.map s input.signers));
    ]

let generation_of_json output =
  {
    log = gs "log" output;
    version_id = gs "versionId" output;
    scid = (if has "scid" output then Some (gs "scid" output) else None);
  }

let create_entry input =
  match perform "create" (controller_json input) with
  | Ok output -> Ok (generation_of_json output)
  | Error message -> Error message

let update_entry ~log input =
  match perform "update" (set "log" (s log) (controller_json input)) with
  | Ok output -> Ok (generation_of_json output)
  | Error message -> Error message

let error_of_json j =
  {
    code = gs "code" j;
    version =
      (match get "version" j with Number f -> Some (int_of_float f) | _ -> None);
    fork = (if has "fork" j then Some (get "fork" j) else None);
  }

let resolve_log (request : resolution_request) =
  let selection =
    match request.selector with
    | Latest -> []
    | Version_id id -> [ ("versionId", s id) ]
    | Version_time time -> [ ("versionTime", s time) ]
    | Version_number number -> [ ("versionNumber", n number) ]
  in
  let copies =
    List.map
      (fun (copy : supplied_copy) ->
        o
          ([ ("source", s copy.source) ]
          @ (match copy.log with
            | Some log -> [ ("log", s log) ]
            | None -> [ ("unavailable", s "unavailable") ])
          @
          match copy.witness with
          | Some witness -> [ ("witness", witness) ]
          | None -> []))
      request.copies
  in
  let input =
    o
      ([
         ("log", s request.log);
         ("now", s request.now);
         ("options", o (selection @ [ ("minCopies", n request.min_copies) ]));
         ("copies", a copies);
       ]
      @ (match request.witness with
        | None -> []
        | Some witness -> [ ("witness", witness) ])
      @
      match request.retained_version_id with
      | None -> []
      | Some id -> [ ("retainedVersionId", s id) ])
  in
  match perform "resolve" input with
  | Error message -> Error message
  | Ok output ->
      let error =
        match get "error" output with Null -> None | j -> Some (error_of_json j)
      in
      if get "valid" output = Bool false then Ok (Rejected (Option.get error))
      else
        Ok
          (Resolved
             {
               state = get "state" output;
               metadata = get "metadata" output;
               first_invalid_version =
                 (match get "firstInvalidVersion" output with
                 | Number f -> Some (int_of_float f)
                 | _ -> None);
               error;
             })
