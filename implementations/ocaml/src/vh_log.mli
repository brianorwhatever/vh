type error = { code : string; version : int option; fork : Json.t option }
(** Independent VH-Log interop-0 implementation. *)

type controller_input = {
  state : Json.t;
  parameters : Json.t;
  version_time : string;
  signers : string list;
}

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

val create_entry : controller_input -> (generation, string) result
val update_entry : log:string -> controller_input -> (generation, string) result
val resolve_log : resolution_request -> (resolution, string) result
val scid : Json.t -> string
val entry_hash : Json.t -> string -> string

type spec = {
  version_param : string;  (** [logVersion] for VH-Log, [method] for did:vh *)
  accepted : string list;  (** accepted values; others are [unsupported-log-version] *)
  version_syntax : (string -> bool) option;
      (** when set, a missing (entry 1) or malformed value is [invalid-parameter] *)
  closed : string list option;  (** when set, any other parameter is [invalid-parameter] *)
  state_check : (string -> Json.t -> bool) option;
      (** run on every entry after the SCID check with the log's SCID and the entry's
          state; [false] fails the entry with [invalid-state] *)
}
(** A specialisation of the VH-Log verifier. Plain VH-Log is [vh_log_spec]. *)

val vh_log_spec : spec

val create_json : ?defaults:(string * string) list -> Json.t -> Json.t
(** Protocol [create]; [defaults] are parameters added, in order, when absent
    (VH-Log: [scid] then [logVersion]). Raises on malformed input. *)

val update_json : Json.t -> Json.t
(** Protocol [update]. Raises on malformed input. *)

val resolve_json : ?spec:spec -> Json.t -> Json.t
(** Protocol [resolve] under a specialisation. *)

val valid_time : string -> bool
(** The profile's [versionTime] format. *)

val valid_watcher_url : string -> bool
(** The profile's [watchers] URL rule. *)

val perform : string -> Json.t -> (Json.t, string) result
(** JSON Lines protocol adapter. An invalid log is a successful call whose result has
    [valid = false]; malformed operations return [Error]. *)
