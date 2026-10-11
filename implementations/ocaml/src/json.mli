(** I-JSON-safe JSON with IEEE-754 binary64 numbers. Objects parsed from text use
    last-key-wins semantics; producers should supply unique keys. *)
type t =
  | Null
  | Bool of bool
  | Number of float
  | String of string
  | Array of t list
  | Object of (string * t) list

exception Invalid of string

val invalid : string -> 'a
val obj : t -> (string * t) list
val arr : t -> t list
val str : t -> string
val get : string -> t -> t
val has : string -> t -> bool
val remove : string -> t -> t
val set : string -> t -> t -> t
val parse : string -> t
val parse_result : string -> (t, string) result
val serialize : ?canonical:bool -> t -> string
val canonicalize : t -> string
