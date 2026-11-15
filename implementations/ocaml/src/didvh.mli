(** did:vh ([didvh-interop-0], docs/didvh-profile.md) on the VH-Log verifier. *)

val did_scid : string -> string option
(** The SCID of a did:vh DID ([did:vh:] and 46 base58btc characters). *)

val spec : scid:string -> Vh_log.spec
(** The did:vh specialisation for resolving [did:vh:<scid>]. *)

val reference_kind : Json.t -> string option
(** A [srcLog]/[srcWitness] reference's kind ([web], [loopback], [file] or [other]),
    or [None] ([invalidOptions]). *)

val src_locations : string -> (string * string) option
(** [srcLog] and [srcWitness] from a percent-decoded [src] value, or [None]
    ([invalidDidUrl]). *)

val parse_did_url : Json.t -> (string * (string * Json.t) list * string option) option
(** A DID URL's DID, resolution options and fragment, or [None] ([invalidDidUrl]). *)

val create : Json.t -> Json.t
(** [didvh-create]: [{document, parameters, versionTime, signers}] to
    [{log, did, scid, versionId}]. Raises on malformed input. *)

val update : Json.t -> Json.t
(** [didvh-update]: [{log, document, parameters, versionTime, signers}] to
    [{log, versionId}]. Raises on malformed input. *)

val resolve : ?remote:bool -> now:Json.t -> Json.t -> Json.t -> Json.t
(** [resolve ~now did options]: offline resolution returning
    [{didResolutionMetadata, didDocument, didDocumentMetadata}]. *)

val perform : string -> Json.t -> (Json.t, string) result
(** The JSON Lines protocol: the VH-Log operations and the six did:vh ones. *)
