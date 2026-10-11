import json_value.{type Json}
@external(erlang, "vh_native", "sha")
pub fn sha(s: String) -> BitArray
@external(erlang, "vh_native", "hash")
pub fn hash(s: String) -> String
@external(erlang, "vh_native", "check_hash")
pub fn check_hash(v: Json) -> String
@external(erlang, "vh_native", "valid_key")
pub fn valid_key(v: Json) -> Bool
@external(erlang, "vh_native", "method_key")
pub fn method_key(v: Json) -> Result(String, Nil)
@external(erlang, "vh_native", "multikey")
pub fn multikey(seed: String) -> String
@external(erlang, "vh_native", "sign")
pub fn sign(seed: String, message: BitArray) -> String
@external(erlang, "vh_native", "verify")
pub fn verify(key: String, signature: Json, message: BitArray) -> Bool
@external(erlang, "vh_native", "time")
pub fn time(v: Json) -> Result(Int, Nil)
@external(erlang, "vh_native", "version")
pub fn version(v: Json) -> Result(#(Int, String), Nil)
@external(erlang, "vh_native", "retained_version")
pub fn retained_version(v: Json) -> Result(Int, Nil)
@external(erlang, "vh_native", "url")
pub fn url(v: Json) -> Bool
@external(erlang, "vh_native", "run")
pub fn run() -> Nil
