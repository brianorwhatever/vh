//! Interop driver: JSON Lines requests on stdin, responses on stdout
//! (docs/interop-protocol.md).

use serde_json::{Map, Value, json};
use std::io::{self, BufRead, Write};
use vh_log::{
    CopyInput, ProofOptions, ResolveInput, ResolveOptions, ResolveResult, Signer, VhLogError,
    canonicalize, compute_entry_hash, compute_scid, create_log, create_proof, hash_b58, key_hash,
    resolve, update_log, verify_proof, witness_proof,
};

type OpResult = Result<Value, String>;

fn field<'a>(input: &'a Value, key: &str) -> Result<&'a Value, String> {
    input.get(key).ok_or_else(|| format!("missing input.{key}"))
}

fn string<'a>(input: &'a Value, key: &str) -> Result<&'a str, String> {
    field(input, key)?
        .as_str()
        .ok_or_else(|| format!("input.{key} must be a string"))
}

/// An optional string field; `null` counts as absent.
fn opt_string(input: &Value, key: &str) -> Result<Option<String>, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("input.{key} must be a string")),
    }
}

fn object(input: &Value, key: &str) -> Result<Map<String, Value>, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(m)) => Ok(m.clone()),
        Some(_) => Err(format!("input.{key} must be an object")),
    }
}

fn signer(seed: &str) -> Result<Signer, String> {
    Signer::from_seed_hex(seed).map_err(|e| e.to_string())
}

fn signers(input: &Value) -> Result<Vec<Signer>, String> {
    field(input, "signers")?
        .as_array()
        .ok_or("input.signers must be an array")?
        .iter()
        .map(|s| signer(s.as_str().ok_or("signers must be hex strings")?))
        .collect()
}

fn entry_map(input: &Value) -> Result<Map<String, Value>, String> {
    field(input, "entry")?
        .as_object()
        .cloned()
        .ok_or_else(|| "input.entry must be an object".into())
}

fn to_value<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("serialises")
}

fn parse_copies(value: &Value) -> Result<Vec<CopyInput>, String> {
    let Some(items) = value.as_array() else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .map(|c| {
            let source = string(c, "source")?.to_string();
            Ok(match c.get("unavailable") {
                Some(reason) => CopyInput::Unavailable {
                    source,
                    reason: reason
                        .as_str()
                        .map_or_else(|| reason.to_string(), String::from),
                },
                None => CopyInput::Available {
                    source,
                    log: string(c, "log")?.to_string(),
                    witness: c.get("witness").cloned(),
                },
            })
        })
        .collect()
}

fn resolve_op(input: &Value) -> OpResult {
    let invalid = |e: VhLogError| Ok(ResolveResult::Invalid(e).to_json());
    let options = match ResolveOptions::from_json(input.get("options").unwrap_or(&Value::Null)) {
        Ok(o) => o,
        Err(e) => return invalid(e),
    };
    let retained_version_id = match input.get("retainedVersionId") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return invalid(VhLogError::new(
                vh_log::ErrorCode::InvalidOption,
                "retainedVersionId is not a versionId",
                None,
            ));
        }
    };
    let request = ResolveInput {
        log: string(input, "log")?.to_string(),
        witness: input.get("witness").cloned(),
        now: input
            .get("now")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        options,
        copies: input.get("copies").map(parse_copies).transpose()?,
        retained_version_id,
    };
    Ok(resolve(&request).to_json())
}

fn handle(op: &str, input: &Value) -> OpResult {
    Ok(match op {
        "jcs" => {
            let parsed: Value =
                serde_json::from_str(string(input, "text")?).map_err(|e| e.to_string())?;
            json!({ "output": canonicalize(&parsed) })
        }
        "hash" => json!({ "output": hash_b58(string(input, "data")?.as_bytes()) }),
        "multikey" => json!({ "multikey": signer(string(input, "seed")?)?.multikey() }),
        "key-hash" => json!({ "output": key_hash(string(input, "multikey")?) }),
        "scid" => json!({ "scid": compute_scid(&entry_map(input)?) }),
        "entry-hash" => json!({
            "hash": compute_entry_hash(&entry_map(input)?, string(input, "previousVersionId")?)
        }),
        "sign" => {
            let options = ProofOptions {
                verification_method: opt_string(input, "verificationMethod")?,
                created: opt_string(input, "created")?,
                ..ProofOptions::default()
            };
            let proof = create_proof(
                field(input, "document")?,
                &signer(string(input, "seed")?)?,
                &options,
            );
            json!({ "proof": proof })
        }
        "verify" => {
            json!({ "valid": verify_proof(field(input, "document")?, field(input, "proof")?) })
        }
        "create" => {
            let created = create_log(
                field(input, "state")?.clone(),
                object(input, "parameters")?,
                string(input, "versionTime")?,
                &signers(input)?,
            );
            json!({ "log": created.log, "scid": created.scid, "versionId": created.version_id })
        }
        "update" => {
            let updated = update_log(
                string(input, "log")?,
                field(input, "state")?.clone(),
                object(input, "parameters")?,
                string(input, "versionTime")?,
                &signers(input)?,
            )
            .map_err(|e| e.to_string())?;
            json!({ "log": updated.log, "versionId": updated.version_id })
        }
        "witness" => {
            let created = opt_string(input, "created")?;
            let proof = witness_proof(
                string(input, "versionId")?,
                &signer(string(input, "seed")?)?,
                created.as_deref(),
            );
            json!({ "proof": to_value(&proof) })
        }
        "resolve" => resolve_op(input)?,
        other => return Err(format!("unknown op {other}")),
    })
}

fn respond(line: &str) -> Value {
    let request: Value = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return json!({ "id": null, "ok": false, "error": format!("malformed request: {e}") });
        }
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let input = request.get("input").cloned().unwrap_or_else(|| json!({}));
    match handle(op, &input) {
        Ok(result) => json!({ "id": id, "ok": true, "result": result }),
        Err(error) => json!({ "id": id, "ok": false, "error": error }),
    }
}

fn main() -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        if stdin.read_until(b'\n', &mut buffer)? == 0 {
            return Ok(());
        }
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
        }
        let line = String::from_utf8_lossy(&buffer);
        if line.trim().is_empty() {
            continue;
        }
        let response = respond(&line);
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
}
