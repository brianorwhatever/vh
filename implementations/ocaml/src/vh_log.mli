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

val perform : string -> Json.t -> (Json.t, string) result
(** JSON Lines protocol adapter. An invalid log is a successful call whose result has
    [valid = false]; malformed operations return [Error]. *)
