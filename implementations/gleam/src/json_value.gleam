import gleam/dict.{type Dict}
import gleam/list
import gleam/order.{type Order}
import gleam/string

pub type Json {
  Obj(Dict(String, Json))
  Arr(List(Json))
  Str(String)
  Num(Float)
  Boolean(Bool)
  Null
}

pub fn object(pairs: List(#(String, Json))) -> Json {
  Obj(dict.from_list(pairs))
}

pub fn fields(v: Json) -> List(#(String, Json)) {
  case v {
    Obj(d) -> dict.to_list(d)
    _ -> []
  }
}

pub fn items(v: Json) -> List(Json) {
  case v {
    Arr(a) -> a
    _ -> []
  }
}

pub fn text(v: Json) -> String {
  case v {
    Str(s) -> s
    _ -> ""
  }
}

pub fn number(v: Json) -> Float {
  case v {
    Num(n) -> n
    _ -> 0.0
  }
}

pub fn get(v: Json, key: String) -> Json {
  case v {
    Obj(d) ->
      case dict.get(d, key) {
        Ok(x) -> x
        Error(_) -> Null
      }
    _ -> Null
  }
}

pub fn has(v: Json, key: String) -> Bool {
  case v {
    Obj(d) -> dict.has_key(d, key)
    _ -> False
  }
}

pub fn set(v: Json, key: String, value: Json) -> Json {
  case v {
    Obj(d) -> Obj(dict.insert(d, key, value))
    _ -> object([#(key, value)])
  }
}

pub fn remove(v: Json, key: String) -> Json {
  case v {
    Obj(d) -> Obj(dict.delete(d, key))
    _ -> v
  }
}

pub fn default(v: Json, key: String, fallback: Json) -> Json {
  case has(v, key) {
    True -> get(v, key)
    False -> fallback
  }
}

pub fn is_object(v: Json) -> Bool {
  case v {
    Obj(_) -> True
    _ -> False
  }
}

pub fn is_array(v: Json) -> Bool {
  case v {
    Arr(_) -> True
    _ -> False
  }
}

pub fn is_string(v: Json) -> Bool {
  case v {
    Str(_) -> True
    _ -> False
  }
}

@external(erlang, "vh_native", "parse")
pub fn parse(s: String) -> Result(Json, String)

@external(erlang, "vh_native", "quote")
fn quote(s: String) -> String

@external(erlang, "vh_native", "number")
fn format_number(n: Float) -> String

@external(erlang, "vh_native", "utf16_compare")
fn compare(a: String, b: String) -> Order

@external(erlang, "vh_native", "integer")
pub fn integer(v: Json) -> Bool

@external(erlang, "vh_native", "int")
pub fn int(n: Int) -> Json

@external(erlang, "vh_native", "to_int")
pub fn to_int(n: Json) -> Int

pub fn jcs(v: Json) -> String {
  case v {
    Obj(d) -> {
      let pairs = dict.to_list(d) |> list.sort(fn(a, b) { compare(a.0, b.0) })
      "{"
      <> string.join(
        list.map(pairs, fn(p) { quote(p.0) <> ":" <> jcs(p.1) }),
        ",",
      )
      <> "}"
    }
    Arr(a) -> "[" <> string.join(list.map(a, jcs), ",") <> "]"
    Str(s) -> quote(s)
    Num(n) -> format_number(n)
    Boolean(True) -> "true"
    Boolean(False) -> "false"
    Null -> "null"
  }
}
