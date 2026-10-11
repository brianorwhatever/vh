open Json

let expect condition message = if not condition then failwith message
let unwrap = function Ok value -> value | Error message -> failwith message
let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

let () =
  (* RFC 8032 test 1 independently checks the OpenSSL Ed25519 seed convention. *)
  let key = Crypto.public (Crypto.hex seed) in
  expect
    (key = Crypto.hex "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    "RFC 8032 public key";
  expect
    (Crypto.sign_bytes (Crypto.hex seed) ""
    = Crypto.hex
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    "RFC 8032 signature";
  List.iter
    (fun bytes ->
      expect
        (Crypto.base58_decode (Crypto.base58_encode bytes) = bytes)
        "base58 byte preservation")
    [ ""; "\000"; "\000\000\255"; String.init 256 Char.chr ];
  expect
    (Crypto.sha512 "abc"
    = Crypto.hex
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
    "SHA512 abc";
  expect (canonicalize (parse "{\"a\":1,\"a\":2}") = "{\"a\":2}") "duplicate last wins";
  List.iter
    (fun input ->
      expect
        (match parse_result input with Error _ -> true | _ -> false)
        "strict parser")
    [ "1e400"; "\"\\ud800\""; "{\"\\udfff\":0}"; "[1,]"; "01"; "\"\192\128\"" ];
  let mk = Crypto.multikey seed in
  let initial : Vh_log.controller_input =
    {
      state = Object [ ("id", String "example:{SCID}"); ("counter", Number 1.) ];
      parameters = Object [ ("updateKeys", Array [ String mk ]) ];
      version_time = "2026-01-01T00:00:00Z";
      signers = [ seed ];
    }
  in
  let generated = unwrap (Vh_log.create_entry initial) in
  let request : Vh_log.resolution_request =
    {
      log = generated.log;
      witness = None;
      now = "2026-01-03T00:00:00Z";
      selector = Latest;
      min_copies = 1;
      copies = [];
      retained_version_id = None;
    }
  in
  let resolved = unwrap (Vh_log.resolve_log request) in
  (match resolved with
  | Resolved value -> expect (get "counter" value.state = Number 1.) "create resolve"
  | _ -> failwith "create rejected");
  let updated =
    unwrap
      (Vh_log.update_entry ~log:generated.log
         {
           initial with
           parameters = Object [ ("deactivated", Bool true) ];
           version_time = "2026-01-02T00:00:00Z";
           state = Object [ ("counter", Number 2.) ];
         })
  in
  (match
     unwrap
       (Vh_log.resolve_log
          { request with log = updated.log; selector = Version_number 1 })
   with
  | Resolved value ->
      expect
        (get "deactivated" value.metadata = Bool true
        && get "counter" value.state = Number 1.)
        "deactivation older target"
  | _ -> failwith "older target rejected");
  (match
     unwrap (Vh_log.resolve_log { request with log = generated.log ^ "not JSON\n" })
   with
  | Resolved value ->
      expect
        (value.first_invalid_version = Some 2
        && (Option.get value.error).code = "invalid-log")
        "partial parsing"
  | _ -> failwith "valid prefix rejected");
  let normal_update =
    unwrap
      (Vh_log.update_entry ~log:generated.log
         {
           initial with
           parameters = Object [];
           version_time = "2026-01-02T00:00:00Z";
           state = Object [ ("counter", Number 3.) ];
         })
  in
  let parsed =
    String.split_on_char '\n' normal_update.log
    |> List.filter (( <> ) "")
    |> List.map Json.parse
  in
  let edited_prefix =
    Json.set "state" (Object [ ("edited", Bool true) ]) (List.hd parsed)
  in
  let supplied_log =
    Json.serialize edited_prefix ^ "\n" ^ Json.serialize (List.nth parsed 1) ^ "\n"
  in
  let copy : Vh_log.supplied_copy =
    { source = "watcher"; log = Some supplied_log; witness = None }
  in
  (match unwrap (Vh_log.resolve_log { request with copies = [ copy ] }) with
  | Resolved value ->
      expect
        (get "counter" value.state = Number 3.)
        "matching prefix trusts verified versionId"
  | _ -> failwith "matching extension rejected");
  let divergent : Vh_log.supplied_copy =
    { source = "fork"; log = Some normal_update.log; witness = None }
  in
  (match
     unwrap
       (Vh_log.resolve_log
          {
            request with
            log = updated.log;
            copies = [ divergent ];
            selector = Version_number 1;
          })
   with
  | Rejected error ->
      expect
        (error.code = "fork-detected" && error.version = Some 2)
        "fork rejects earlier target"
  | _ -> failwith "fork accepted");
  let malformed_copy : Vh_log.supplied_copy =
    { source = "malformed"; log = Some "{}\n"; witness = None }
  in
  (match unwrap (Vh_log.resolve_log { request with copies = [ malformed_copy ] }) with
  | Resolved value ->
      let codes =
        Json.arr (Json.get "warnings" value.metadata) |> List.map (Json.get "code")
      in
      expect (List.mem (Json.String "copy-invalid") codes) "malformed copy discarded"
  | _ -> failwith "malformed copy invalidated reference");
  let document = Object [ ("versionId", String generated.version_id) ] in
  let proof = Crypto.sign document seed in
  expect (Crypto.verify document proof) "proof roundtrip";
  expect
    (not (Crypto.verify (Object [ ("versionId", String "changed") ]) proof))
    "proof rejects altered document";
  print_endline "OCaml library tests passed"
