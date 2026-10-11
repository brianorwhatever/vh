external digest : int -> string -> string = "vh_digest"
external public : string -> string = "vh_public"
external sign_bytes : string -> string -> string = "vh_sign"
external verify_bytes : string -> string -> string -> bool = "vh_verify"

let sha256 = digest 256
let sha512 = digest 512
let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let base58_encode s =
  let digits = ref [] in
  String.iter
    (fun c ->
      let carry = ref (Char.code c) in
      let ds =
        List.map
          (fun d ->
            let n = (d * 256) + !carry in
            carry := n / 58;
            n mod 58)
          !digits
      in
      let rec more acc =
        if !carry = 0 then acc
        else
          let d = !carry mod 58 in
          carry := !carry / 58;
          more (acc @ [ d ])
      in
      digits := more ds)
    s;
  let z = ref 0 in
  while !z < String.length s && s.[!z] = '\000' do
    incr z
  done;
  String.make !z '1'
  ^ String.concat "" (List.map (fun d -> String.make 1 alphabet.[d]) (List.rev !digits))

let base58_decode s =
  let bytes = ref [] in
  String.iter
    (fun c ->
      let v = try String.index alphabet c with Not_found -> invalid_arg "base58" in
      let carry = ref v in
      let bs =
        List.map
          (fun b ->
            let n = (b * 58) + !carry in
            carry := n / 256;
            n mod 256)
          !bytes
      in
      let rec more acc =
        if !carry = 0 then acc
        else
          let d = !carry mod 256 in
          carry := !carry / 256;
          more (acc @ [ d ])
      in
      bytes := more bs)
    s;
  let z = ref 0 in
  while !z < String.length s && s.[!z] = '1' do
    incr z
  done;
  String.make !z '\000'
  ^ String.concat "" (List.map (fun b -> String.make 1 (Char.chr b)) (List.rev !bytes))

let hash s = base58_encode ("\x12\x20" ^ sha256 s)
let hash512 s = base58_encode ("\x13\x40" ^ sha512 s)

let hex s =
  if String.length s mod 2 <> 0 then invalid_arg "hex";
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))

let multikey seed = "z" ^ base58_encode ("\xed\x01" ^ public (hex seed))

let key_bytes mk =
  if String.length mk < 2 || mk.[0] <> 'z' then invalid_arg "multikey";
  let b = base58_decode (String.sub mk 1 (String.length mk - 1)) in
  if String.length b <> 34 || String.sub b 0 2 <> "\xed\x01" then invalid_arg "multikey";
  String.sub b 2 32

let valid_key s =
  try
    ignore (key_bytes s);
    true
  with _ -> false

let multihash s =
  try
    let b = base58_decode s in
    (String.length b = 34 && String.sub b 0 2 = "\x12\x20")
    || (String.length b = 66 && String.sub b 0 2 = "\x13\x40")
  with _ -> false

let sha256_hash s =
  try
    let b = base58_decode s in
    String.length b = 34 && String.sub b 0 2 = "\x12\x20"
  with _ -> false

let method_key vm =
  match String.split_on_char '#' vm with
  | [ id; mk ] when id = "did:key:" ^ mk && valid_key mk -> mk
  | _ -> invalid_arg "verificationMethod"

let proof_input doc proof =
  sha256 (Json.canonicalize (Json.remove "proofValue" proof))
  ^ sha256 (Json.canonicalize (Json.remove "proof" doc))

let sign ?verification_method ?created doc seed =
  let mk = multikey seed in
  let vm = Option.value verification_method ~default:("did:key:" ^ mk ^ "#" ^ mk) in
  let p =
    Json.Object
      ([
         ("type", Json.String "DataIntegrityProof");
         ("cryptosuite", Json.String "eddsa-jcs-2022");
         ("verificationMethod", Json.String vm);
       ]
      @ (match created with None -> [] | Some s -> [ ("created", Json.String s) ])
      @ [ ("proofPurpose", Json.String "assertionMethod") ])
  in
  Json.set "proofValue"
    (Json.String ("z" ^ base58_encode (sign_bytes (hex seed) (proof_input doc p))))
    p

let verify doc p =
  try
    let s k = Json.str (Json.get k p) in
    let mk = method_key (s "verificationMethod") in
    if
      s "type" <> "DataIntegrityProof"
      || s "cryptosuite" <> "eddsa-jcs-2022"
      || s "proofPurpose" <> "assertionMethod"
    then false
    else
      let v = s "proofValue" in
      String.length v > 1
      && v.[0] = 'z'
      && verify_bytes (key_bytes mk) (proof_input doc p)
           (base58_decode (String.sub v 1 (String.length v - 1)))
  with _ -> false

let multikey_result seed =
  try Ok (multikey seed)
  with Invalid_argument message | Failure message -> Error message

let sign_result ?verification_method ?created document seed =
  try Ok (sign ?verification_method ?created document seed)
  with Invalid_argument message | Failure message | Json.Invalid message ->
    Error message

let witness ?created ~version_id ~seed () =
  sign_result ?created (Json.Object [ ("versionId", Json.String version_id) ]) seed
