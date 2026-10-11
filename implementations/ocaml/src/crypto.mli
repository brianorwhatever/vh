val sha256 : string -> string
(** Small native bindings to maintained OpenSSL primitives. Byte-level helpers take raw
    bytes; controller-facing seed arguments are 32-byte hex strings. *)

val sha512 : string -> string
val base58_encode : string -> string
val base58_decode : string -> string
val hash : string -> string
val hash512 : string -> string
val hex : string -> string
val public : string -> string
val sign_bytes : string -> string -> string
val verify_bytes : string -> string -> string -> bool
val multikey : string -> string
val multikey_result : string -> (string, string) result
val key_bytes : string -> string
val valid_key : string -> bool
val multihash : string -> bool
val sha256_hash : string -> bool
val method_key : string -> string
val sign : ?verification_method:string -> ?created:string -> Json.t -> string -> Json.t

val sign_result :
  ?verification_method:string ->
  ?created:string ->
  Json.t ->
  string ->
  (Json.t, string) result

val verify : Json.t -> Json.t -> bool

val witness :
  ?created:string -> version_id:string -> seed:string -> unit -> (Json.t, string) result
