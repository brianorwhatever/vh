//// Driver dispatch (docs/interop-protocol.md): the did:vh operations, and
//// everything else through `vh_log.dispatch`.

import json_value.{type Json}
import vh_log
import vh_log/didvh

pub fn dispatch(op: String, input: Json) -> Result(Json, String) {
  case op {
    "didvh-create" -> Ok(didvh.create(input))
    "didvh-update" -> Ok(didvh.update(input))
    "didvh-resolve" -> Ok(didvh.resolve_request(input))
    "didvh-ref" -> Ok(didvh.ref_result(input))
    "didvh-src" -> Ok(didvh.src_result(input))
    "didvh-did-url" -> Ok(didvh.did_url_result(input))
    _ -> vh_log.dispatch(op, input)
  }
}
