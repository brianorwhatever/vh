//! Log Controller operations: hashing, sealing and serialising entries (profile §5).

use crate::error::GenerateError;
use crate::hash::hash_b58;
use crate::jcs::canonicalize;
use crate::proof::{Proof, ProofOptions, Signer, create_proof};
use serde_json::{Map, Value};

pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const LOG_VERSION: &str = "vh-log:1.0";
pub const LOG_FILE_NAME: &str = "vh-log.jsonl";
pub const WITNESS_FILE_NAME: &str = "vh-log-witness.json";

/// Field order of a serialised entry (profile §5).
const FIELD_ORDER: [&str; 5] = ["versionId", "versionTime", "parameters", "state", "proof"];

fn without_proof(entry: &Map<String, Value>) -> Map<String, Value> {
    let mut rest = entry.clone();
    rest.remove("proof");
    rest
}

/// SCID of a preliminary entry (placeholders in place, `versionId` = `{SCID}`).
pub fn compute_scid(preliminary: &Map<String, Value>) -> String {
    hash_b58(canonicalize(&Value::Object(without_proof(preliminary))).as_bytes())
}

/// Entry hash: the entry without `proof`, with `versionId` set to its predecessor's.
pub fn compute_entry_hash(entry: &Map<String, Value>, previous_version_id: &str) -> String {
    let mut document = without_proof(entry);
    document.insert(
        "versionId".into(),
        Value::String(previous_version_id.into()),
    );
    hash_b58(canonicalize(&Value::Object(document)).as_bytes())
}

/// Compact JSON with the field order from profile §5, plus the trailing newline.
pub fn serialize_entry(entry: &Map<String, Value>) -> String {
    let mut ordered = Map::new();
    for key in FIELD_ORDER {
        if let Some(v) = entry.get(key) {
            ordered.insert(key.into(), v.clone());
        }
    }
    for (k, v) in entry {
        if !ordered.contains_key(k) {
            ordered.insert(k.clone(), v.clone());
        }
    }
    serde_json::to_string(&Value::Object(ordered)).expect("JSON serialises") + "\n"
}

/// Splits a log file into lines on `\n` only, dropping the final empty line.
pub fn parse_log_lines(log: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = log.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines
}

/// Overrides used when sealing entries, for building test logs.
#[derive(Debug, Clone, Default)]
pub struct SealOptions {
    /// Proof options applied to every signer.
    pub proof: ProofOptions,
    /// Override for the version number written into `versionId`.
    pub version_number: Option<String>,
    /// Override for the hash written into `versionId`.
    pub entry_hash: Option<String>,
}

fn sign_entry(document: &Map<String, Value>, signers: &[Signer], options: &SealOptions) -> Value {
    let mut proof_options = options.proof.clone();
    if proof_options.created.is_none() {
        proof_options.created = document
            .get("versionTime")
            .and_then(Value::as_str)
            .map(String::from);
    }
    let doc = Value::Object(document.clone());
    Value::Array(
        signers
            .iter()
            .map(|s| create_proof(&doc, s, &proof_options).to_value())
            .collect(),
    )
}

/// Turns a genesis body into a signed first entry: computes the SCID, replaces
/// the placeholder, computes the entry hash and signs. The body's fields are
/// kept as given (no validation). Returns the entry and the SCID.
pub fn seal_genesis(
    body: &Map<String, Value>,
    signers: &[Signer],
    options: &SealOptions,
) -> (Map<String, Value>, String) {
    let mut preliminary = body.clone();
    preliminary.insert("versionId".into(), Value::String(SCID_PLACEHOLDER.into()));
    let scid = compute_scid(&preliminary);
    let text = serde_json::to_string(&preliminary)
        .expect("JSON serialises")
        .replace(SCID_PLACEHOLDER, &scid);
    let mut document: Map<String, Value> =
        serde_json::from_str(&text).expect("replacing {SCID} keeps the JSON valid");
    let hash = options
        .entry_hash
        .clone()
        .unwrap_or_else(|| compute_entry_hash(&document, &scid));
    let number = options.version_number.as_deref().unwrap_or("1");
    document.insert(
        "versionId".into(),
        Value::String(format!("{number}-{hash}")),
    );
    let proof = sign_entry(&document, signers, options);
    document.insert("proof".into(), proof);
    (document, scid)
}

/// Mirrors ECMAScript `Number.parseInt(s, 10)` on the leading part of a `versionId`.
fn parse_int_prefix(s: &str) -> Option<i128> {
    let s = s.trim_start();
    let (negative, rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits: String = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .take(30)
        .collect();
    let n: i128 = digits.parse().ok()?;
    Some(if negative { -n } else { n })
}

/// Signs a later entry whose predecessor has `previous_version_id`.
pub fn seal_entry(
    body: &Map<String, Value>,
    previous_version_id: &str,
    signers: &[Signer],
    options: &SealOptions,
) -> Map<String, Value> {
    let mut document = body.clone();
    document.insert(
        "versionId".into(),
        Value::String(previous_version_id.into()),
    );
    let hash = options
        .entry_hash
        .clone()
        .unwrap_or_else(|| compute_entry_hash(&document, previous_version_id));
    let number = options.version_number.clone().unwrap_or_else(|| {
        let prefix = previous_version_id.split('-').next().unwrap_or("");
        parse_int_prefix(prefix).map_or_else(|| "NaN".into(), |n| (n + 1).to_string())
    });
    document.insert(
        "versionId".into(),
        Value::String(format!("{number}-{hash}")),
    );
    let proof = sign_entry(&document, signers, options);
    document.insert("proof".into(), proof);
    document
}

/// Result of [`create_log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedLog {
    /// The log file: one line, terminated by `\n`.
    pub log: String,
    pub scid: String,
    pub version_id: String,
}

/// Creates a new log. `{SCID}` in `parameters` and `state` is replaced with the
/// SCID; `scid` and `logVersion` parameters are added if absent.
pub fn create_log(
    state: Value,
    parameters: Map<String, Value>,
    version_time: &str,
    signers: &[Signer],
) -> CreatedLog {
    let mut parameters = parameters;
    if !parameters.contains_key("logVersion") {
        parameters.insert("logVersion".into(), Value::String(LOG_VERSION.into()));
    }
    if !parameters.contains_key("scid") {
        parameters.insert("scid".into(), Value::String(SCID_PLACEHOLDER.into()));
    }
    let mut body = Map::new();
    body.insert("versionId".into(), Value::String(SCID_PLACEHOLDER.into()));
    body.insert("versionTime".into(), Value::String(version_time.into()));
    body.insert("parameters".into(), Value::Object(parameters));
    body.insert("state".into(), state);
    let (entry, scid) = seal_genesis(&body, signers, &SealOptions::default());
    let version_id = entry["versionId"].as_str().expect("set above").to_string();
    CreatedLog {
        log: serialize_entry(&entry),
        scid,
        version_id,
    }
}

/// Result of [`update_log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatedLog {
    /// The log with the new line appended.
    pub log: String,
    pub version_id: String,
}

/// Appends a new entry to `log`, chaining its hash from the last line. Use
/// `parameters` `{"deactivated": true}` to deactivate.
pub fn update_log(
    log: &str,
    state: Value,
    parameters: Map<String, Value>,
    version_time: &str,
    signers: &[Signer],
) -> Result<UpdatedLog, GenerateError> {
    let last = *parse_log_lines(log).last().ok_or(GenerateError::EmptyLog)?;
    let previous: Value =
        serde_json::from_str(last).map_err(|e| GenerateError::InvalidLastLine(e.to_string()))?;
    let previous_version_id = previous
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| GenerateError::InvalidLastLine("no string versionId".into()))?;
    let mut body = Map::new();
    body.insert(
        "versionId".into(),
        Value::String(previous_version_id.into()),
    );
    body.insert("versionTime".into(), Value::String(version_time.into()));
    body.insert("parameters".into(), Value::Object(parameters));
    body.insert("state".into(), state);
    let entry = seal_entry(&body, previous_version_id, signers, &SealOptions::default());
    let version_id = entry["versionId"].as_str().expect("set above").to_string();
    let mut out = log.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&serialize_entry(&entry));
    Ok(UpdatedLog {
        log: out,
        version_id,
    })
}

/// A witness proof: `eddsa-jcs-2022` over `{"versionId": …}` (profile §3).
pub fn witness_proof(version_id: &str, signer: &Signer, created: Option<&str>) -> Proof {
    let mut document = Map::new();
    document.insert("versionId".into(), Value::String(version_id.into()));
    let options = ProofOptions {
        created: created.map(String::from),
        ..ProofOptions::default()
    };
    create_proof(&Value::Object(document), signer, &options)
}
