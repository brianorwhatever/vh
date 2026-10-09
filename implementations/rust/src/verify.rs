//! Log verification: the per-entry checks of profile §4 and witness verification.

use crate::encoding::public_key_from_multikey;
use crate::error::{ErrorCode, VhLogError};
use crate::hash::{MultihashCheck, check_sha256_multihash, key_hash};
use crate::log::{
    LOG_VERSION, SCID_PLACEHOLDER, compute_entry_hash, compute_scid, parse_log_lines,
};
use crate::proof::{multikey_from_verification_method, verify_proof};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashSet;

/// Seconds a `versionTime` may be ahead of the resolver's clock (profile §4).
pub const FUTURE_TOLERANCE_SECONDS: i64 = 300;
const SUPPORTED_LOG_VERSIONS: [&str; 1] = [LOG_VERSION];
const ENTRY_KEYS: [&str; 5] = ["versionId", "versionTime", "parameters", "state", "proof"];
/// Default `ttl` in seconds.
pub const DEFAULT_TTL: u64 = 3600;

/// One witness in a witness configuration. Extra properties are kept.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Witness {
    pub id: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A non-empty witness configuration (`{}` is represented as `None`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WitnessConfig {
    pub threshold: u64,
    pub witnesses: Vec<Witness>,
}

/// The parameters active after an entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    pub log_version: String,
    pub scid: String,
    pub update_keys: Vec<String>,
    pub next_key_hashes: Vec<String>,
    /// `None` when the parameter is `{}` (no witnesses).
    pub witness: Option<WitnessConfig>,
    pub watchers: Vec<String>,
    pub deactivated: bool,
    pub ttl: u64,
}

/// A log entry that passed the structure check.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub version_id: String,
    pub version_time: String,
    pub parameters: Map<String, Value>,
    pub state: Map<String, Value>,
    pub proof: Vec<Value>,
}

impl LogEntry {
    /// Checks the entry's top-level structure (profile §6 `invalid-entry`).
    fn from_map(raw: &Map<String, Value>) -> Option<Self> {
        if raw.len() != ENTRY_KEYS.len() || !ENTRY_KEYS.iter().all(|k| raw.contains_key(*k)) {
            return None;
        }
        Some(LogEntry {
            version_id: raw["versionId"].as_str()?.to_string(),
            version_time: raw["versionTime"].as_str()?.to_string(),
            parameters: raw["parameters"].as_object()?.clone(),
            state: raw["state"].as_object()?.clone(),
            proof: raw["proof"].as_array()?.clone(),
        })
    }
}

/// An entry that passed every per-entry check.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEntry {
    pub entry: LogEntry,
    /// The entry exactly as parsed, used for hashing.
    pub raw: Map<String, Value>,
    pub version_number: u64,
    /// Seconds since the Unix epoch.
    pub time: i64,
    /// Parameters active after this entry.
    pub parameters: Parameters,
    /// Witness list this entry must satisfy, or `None` if it needs no witnessing.
    pub witness_rule: Option<WitnessConfig>,
}

/// The outcome of verifying a whole log file.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedLog {
    /// The valid (and witnessed) prefix of the log.
    pub entries: Vec<VerifiedEntry>,
    /// The raw lines of the log, for copy comparison.
    pub lines: Vec<String>,
    /// The first failure, if any.
    pub failure: Option<VhLogError>,
}

impl VerifiedLog {
    /// Every line is a valid, witnessed entry.
    pub fn is_fully_valid(&self) -> bool {
        self.failure.is_none() && self.entries.len() == self.lines.len()
    }
}

fn as_integer(v: &Value) -> Option<f64> {
    v.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0)
}

fn as_string_array(v: &Value) -> Option<Vec<String>> {
    v.as_array()?
        .iter()
        .map(|x| x.as_str().map(String::from))
        .collect()
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses a `versionTime` (`YYYY-MM-DDTHH:MM:SSZ` or `…+00:00`) to seconds since the
/// epoch; returns `None` unless it is a valid whole-second UTC timestamp.
///
/// Like the reference implementation (which uses `Date.UTC`), years 0000–0099 are rejected.
pub fn parse_version_time(value: &str) -> Option<i64> {
    let b = value.as_bytes();
    let rest = match b.len() {
        20 if b[19] == b'Z' => &b[..19],
        25 if &b[19..] == b"+00:00" => &b[..19],
        _ => return None,
    };
    let shape = b"dddd-dd-ddTdd:dd:dd";
    if !rest.iter().zip(shape).all(|(&c, &s)| {
        if s == b'd' {
            c.is_ascii_digit()
        } else {
            c == s
        }
    }) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| value[r].parse::<i64>().expect("digits");
    let (y, mo, d, h, mi, s) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    );
    if y < 100
        || !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(y, mo)
        || h > 23
        || mi > 59
        || s > 59
    {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

fn validate_witness(value: &Value, version: u64) -> Result<Option<WitnessConfig>, VhLogError> {
    let fail = |why: String| {
        VhLogError::at(
            ErrorCode::InvalidParameter,
            version,
            format!("witness: {why}"),
        )
    };
    let obj = value
        .as_object()
        .ok_or_else(|| fail("must be an object".into()))?;
    if obj.is_empty() {
        return Ok(None);
    }
    let list = obj
        .get("witnesses")
        .and_then(Value::as_array)
        .filter(|w| !w.is_empty())
        .ok_or_else(|| fail("witnesses must be a non-empty array".into()))?;
    let mut ids = HashSet::new();
    let mut witnesses = Vec::new();
    for w in list {
        let Some((id, map)) = w
            .as_object()
            .and_then(|m| Some((m.get("id")?.as_str()?, m)))
        else {
            return Err(fail("each witness needs a string id".into()));
        };
        let is_did_key = id
            .strip_prefix("did:key:")
            .and_then(public_key_from_multikey)
            .is_some();
        if !is_did_key {
            return Err(fail(format!("witness id {id} is not an Ed25519 did:key")));
        }
        // A valid did:key is ASCII, so NFC normalisation (profile §3) is the identity.
        if !ids.insert(id.to_string()) {
            return Err(fail(format!("duplicate witness id {id}")));
        }
        let mut extra = map.clone();
        extra.remove("id");
        witnesses.push(Witness {
            id: id.to_string(),
            extra,
        });
    }
    let threshold = obj
        .get("threshold")
        .and_then(as_integer)
        .filter(|&t| t >= 1.0 && t <= ids.len() as f64)
        .ok_or_else(|| {
            fail("threshold must be an integer between 1 and the number of witnesses".into())
        })?;
    Ok(Some(WitnessConfig {
        threshold: threshold as u64,
        witnesses,
    }))
}

/// Applies an entry's `parameters` to the previously active set (Read step 1
/// and the pre-rotation rule of step 7).
fn apply_parameters(
    raw: &Map<String, Value>,
    previous: Option<&Parameters>,
    version: u64,
) -> Result<Parameters, VhLogError> {
    let invalid = |msg: &str| VhLogError::at(ErrorCode::InvalidParameter, version, msg);
    let unsupported = |msg: String| VhLogError::at(ErrorCode::UnsupportedLogVersion, version, msg);
    if let Some(key) = raw.iter().find(|(_, v)| v.is_null()).map(|(k, _)| k) {
        return Err(invalid(&format!("{key} must not be null")));
    }
    if previous.is_none() && !raw.contains_key("logVersion") {
        return Err(unsupported("logVersion missing from first entry".into()));
    }
    if let Some(lv) = raw.get("logVersion") {
        let position = lv
            .as_str()
            .and_then(|s| SUPPORTED_LOG_VERSIONS.iter().position(|v| *v == s))
            .ok_or_else(|| unsupported(format!("unsupported logVersion {lv}")))?;
        if let Some(prev) = previous {
            let prev_position = SUPPORTED_LOG_VERSIONS
                .iter()
                .position(|v| *v == prev.log_version);
            if prev_position.is_some_and(|p| position < p) {
                return Err(unsupported("logVersion may not be lowered".into()));
            }
        }
    }
    if previous.is_none() {
        if !raw.get("scid").is_some_and(Value::is_string) {
            return Err(invalid("scid missing from first entry"));
        }
        if !raw.contains_key("updateKeys") {
            return Err(invalid("updateKeys missing from first entry"));
        }
    } else if raw.contains_key("scid") {
        return Err(invalid("scid may only appear in the first entry"));
    }
    let update_keys = match raw.get("updateKeys") {
        None => None,
        Some(v) => Some(
            as_string_array(v)
                .filter(|keys| keys.iter().all(|k| public_key_from_multikey(k).is_some()))
                .ok_or_else(|| invalid("updateKeys must be an array of Ed25519 multikeys"))?,
        ),
    };
    let next_key_hashes = match raw.get("nextKeyHashes") {
        None => None,
        Some(v) => Some(
            as_string_array(v)
                .filter(|hs| {
                    hs.iter()
                        .all(|h| check_sha256_multihash(h) == MultihashCheck::Ok)
                })
                .ok_or_else(|| invalid("nextKeyHashes must be an array of SHA-256 multihashes"))?,
        ),
    };
    let witness = match raw.get("witness") {
        Some(v) => validate_witness(v, version)?,
        None => previous.and_then(|p| p.witness.clone()),
    };
    let watchers = match raw.get("watchers") {
        None => None,
        Some(v) => Some(
            as_string_array(v)
                .filter(|urls| urls.iter().all(|u| url::Url::parse(u).is_ok()))
                .ok_or_else(|| invalid("watchers must be an array of URLs"))?,
        ),
    };
    let deactivated = match raw.get("deactivated") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| invalid("deactivated must be a boolean"))?,
    };
    let ttl = match raw.get("ttl") {
        None => None,
        Some(v) => Some(
            as_integer(v)
                .filter(|&t| (0.0..=2f64.powi(31)).contains(&t))
                .ok_or_else(|| invalid("ttl must be an integer between 0 and 2^31"))?
                as u64,
        ),
    };

    if let Some(prev) = previous.filter(|p| !p.next_key_hashes.is_empty()) {
        let violation = |msg: String| VhLogError::at(ErrorCode::PrerotationViolation, version, msg);
        let Some(keys) = &update_keys else {
            return Err(violation(
                "updateKeys must be explicit while pre-rotation is active".into(),
            ));
        };
        if next_key_hashes.is_none() {
            return Err(violation(
                "nextKeyHashes must be explicit while pre-rotation is active".into(),
            ));
        }
        if let Some(key) = keys
            .iter()
            .find(|k| !prev.next_key_hashes.contains(&key_hash(k)))
        {
            return Err(violation(format!("key {key} was not committed")));
        }
    }

    let inherit = |own: Option<Vec<String>>, f: fn(&Parameters) -> &Vec<String>| {
        own.or_else(|| previous.map(|p| f(p).clone()))
            .unwrap_or_default()
    };
    Ok(Parameters {
        log_version: raw
            .get("logVersion")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| previous.map(|p| p.log_version.clone()))
            .unwrap_or_default(),
        scid: raw
            .get("scid")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| previous.map(|p| p.scid.clone()))
            .unwrap_or_default(),
        update_keys: inherit(update_keys, |p| &p.update_keys),
        next_key_hashes: inherit(next_key_hashes, |p| &p.next_key_hashes),
        witness,
        watchers: inherit(watchers, |p| &p.watchers),
        deactivated,
        ttl: ttl.or(previous.map(|p| p.ttl)).unwrap_or(DEFAULT_TTL),
    })
}

fn verify_proofs(
    raw: &Map<String, Value>,
    proofs: &[Value],
    active_keys: &[String],
    version: u64,
) -> Result<(), VhLogError> {
    if proofs.is_empty() {
        return Err(VhLogError::at(
            ErrorCode::InvalidProof,
            version,
            "proof array is empty",
        ));
    }
    let mut document = raw.clone();
    document.remove("proof");
    let document = Value::Object(document);
    for proof in proofs {
        let multikey = proof
            .get("verificationMethod")
            .and_then(Value::as_str)
            .and_then(multikey_from_verification_method)
            .ok_or_else(|| {
                VhLogError::at(
                    ErrorCode::InvalidProof,
                    version,
                    "proof verificationMethod is not did:key:<mk>#<mk>",
                )
            })?;
        if !active_keys.iter().any(|k| k == multikey) {
            return Err(VhLogError::at(
                ErrorCode::UnauthorizedKey,
                version,
                format!("{multikey} is not an active update key"),
            ));
        }
        if !verify_proof(&document, proof) {
            return Err(VhLogError::at(
                ErrorCode::InvalidProof,
                version,
                "proof failed verification",
            ));
        }
    }
    Ok(())
}

fn verify_version_id(
    raw: &Map<String, Value>,
    version_id: &str,
    expected: u64,
    previous_version_id: &str,
) -> Result<(), VhLogError> {
    let err = |code, msg: String| VhLogError::at(code, expected, msg);
    let parsed = version_id.split_once('-').filter(|(n, h)| {
        !n.is_empty()
            && !n.starts_with('0')
            && n.bytes().all(|b| b.is_ascii_digit())
            && !h.is_empty()
            && !h.contains('-')
    });
    let Some((_, hash)) = parsed.filter(|(n, _)| n.parse::<u64>().ok() == Some(expected)) else {
        return Err(err(
            ErrorCode::InvalidVersionId,
            format!("expected versionId {expected}-<hash>, got {version_id}"),
        ));
    };
    match check_sha256_multihash(hash) {
        MultihashCheck::NotBase58 => {
            return Err(err(
                ErrorCode::InvalidVersionId,
                "entry hash is not base58btc".into(),
            ));
        }
        MultihashCheck::UnsupportedAlgorithm => {
            return Err(err(
                ErrorCode::InvalidHashAlgorithm,
                "entry hash is not a SHA-256 multihash".into(),
            ));
        }
        MultihashCheck::Ok => {}
    }
    if compute_entry_hash(raw, previous_version_id) != hash {
        return Err(err(
            ErrorCode::EntryHashMismatch,
            "entry hash does not match".into(),
        ));
    }
    Ok(())
}

fn verify_scid(raw: &Map<String, Value>, scid: &str) -> Result<(), VhLogError> {
    match check_sha256_multihash(scid) {
        MultihashCheck::UnsupportedAlgorithm => {
            return Err(VhLogError::at(
                ErrorCode::InvalidHashAlgorithm,
                1,
                "SCID is not a SHA-256 multihash",
            ));
        }
        MultihashCheck::NotBase58 => {
            return Err(VhLogError::at(
                ErrorCode::ScidMismatch,
                1,
                "SCID is not base58btc",
            ));
        }
        MultihashCheck::Ok => {}
    }
    let mut rest = raw.clone();
    rest.remove("proof");
    rest.insert("versionId".into(), Value::String(SCID_PLACEHOLDER.into()));
    let text = serde_json::to_string(&rest)
        .expect("JSON serialises")
        .replace(scid, SCID_PLACEHOLDER);
    let preliminary: Map<String, Value> =
        serde_json::from_str(&text).expect("replacing a base58 string keeps the JSON valid");
    if compute_scid(&preliminary) != scid {
        return Err(VhLogError::at(
            ErrorCode::ScidMismatch,
            1,
            "SCID does not match",
        ));
    }
    Ok(())
}

/// Runs the per-entry checks (profile §4, steps 1–7) on one parsed line.
fn verify_entry(
    raw: Map<String, Value>,
    previous: Option<&VerifiedEntry>,
    now: i64,
) -> Result<VerifiedEntry, VhLogError> {
    let version = previous.map_or(1, |p| p.version_number + 1);
    if previous.is_some_and(|p| p.parameters.deactivated) {
        return Err(VhLogError::at(
            ErrorCode::EntryAfterDeactivation,
            version,
            "entry follows a deactivating entry",
        ));
    }
    let entry = LogEntry::from_map(&raw).ok_or_else(|| {
        VhLogError::at(
            ErrorCode::InvalidEntry,
            version,
            "entry does not have the required properties and types",
        )
    })?;
    let parameters = apply_parameters(&entry.parameters, previous.map(|p| &p.parameters), version)?;

    let (active_keys, witness_rule) = match previous {
        None => (parameters.update_keys.clone(), parameters.witness.clone()),
        Some(prev) => {
            let keys = if prev.parameters.next_key_hashes.is_empty() {
                prev.parameters.update_keys.clone()
            } else {
                parameters.update_keys.clone()
            };
            let enables =
                entry.parameters.contains_key("witness") && prev.parameters.witness.is_none();
            let rule = if enables {
                parameters.witness.clone()
            } else {
                prev.parameters.witness.clone()
            };
            (keys, rule)
        }
    };
    verify_proofs(&raw, &entry.proof, &active_keys, version)?;
    let previous_version_id =
        previous.map_or(parameters.scid.as_str(), |p| p.entry.version_id.as_str());
    verify_version_id(&raw, &entry.version_id, version, previous_version_id)?;

    let time = parse_version_time(&entry.version_time).ok_or_else(|| {
        VhLogError::at(
            ErrorCode::InvalidVersionTime,
            version,
            format!("invalid versionTime {}", entry.version_time),
        )
    })?;
    if previous.is_some_and(|p| time <= p.time) {
        return Err(VhLogError::at(
            ErrorCode::InvalidVersionTime,
            version,
            "versionTime must be later than the previous entry's",
        ));
    }
    if time > now + FUTURE_TOLERANCE_SECONDS {
        return Err(VhLogError::at(
            ErrorCode::FutureVersionTime,
            version,
            "versionTime is in the future",
        ));
    }
    if previous.is_none() {
        verify_scid(&raw, &parameters.scid)?;
    }
    Ok(VerifiedEntry {
        entry,
        raw,
        version_number: version,
        time,
        parameters,
        witness_rule,
    })
}

/// A witness file entry: proofs over one `versionId`.
struct WitnessRecord<'a> {
    version_id: &'a str,
    proofs: &'a [Value],
}

fn as_witness_file(witness: &Value) -> Option<Vec<WitnessRecord<'_>>> {
    witness
        .as_array()?
        .iter()
        .map(|item| {
            Some(WitnessRecord {
                version_id: item.get("versionId")?.as_str()?,
                proofs: item.get("proof")?.as_array()?,
            })
        })
        .collect()
}

/// Returns the index of the first entry that is not witnessed, with its error
/// (Verifying Witness Proofs During Resolution).
fn check_witnesses(
    entries: &[VerifiedEntry],
    witness: Option<&Value>,
) -> Option<(usize, VhLogError)> {
    let first = entries.iter().position(|e| e.witness_rule.is_some())?;
    let file = match witness {
        None => Vec::new(),
        Some(w) => match as_witness_file(w) {
            Some(file) => file,
            None => {
                let error = VhLogError::at(
                    ErrorCode::InvalidWitnessFile,
                    first as u64 + 1,
                    "witness file is malformed",
                );
                return Some((first, error));
            }
        },
    };
    struct Approval<'a> {
        id: String,
        index: usize,
        proof: &'a Value,
        version_id: &'a str,
    }
    // A proof for entry j approves every entry <= j.
    let mut approvals = Vec::new();
    for record in &file {
        let Some(index) = entries
            .iter()
            .rposition(|e| e.entry.version_id == record.version_id)
        else {
            continue;
        };
        for proof in record.proofs {
            if let Some(mk) = proof
                .get("verificationMethod")
                .and_then(Value::as_str)
                .and_then(multikey_from_verification_method)
            {
                approvals.push(Approval {
                    id: format!("did:key:{mk}"),
                    index,
                    proof,
                    version_id: record.version_id,
                });
            }
        }
    }
    let mut valid: Vec<Option<bool>> = vec![None; approvals.len()];
    for (i, entry) in entries.iter().enumerate().skip(first) {
        let Some(rule) = &entry.witness_rule else {
            continue;
        };
        let ids: HashSet<&str> = rule.witnesses.iter().map(|w| w.id.as_str()).collect();
        let mut approved: HashSet<&str> = HashSet::new();
        for (k, a) in approvals.iter().enumerate() {
            if a.index >= i && ids.contains(a.id.as_str()) && !approved.contains(a.id.as_str()) {
                let ok = *valid[k].get_or_insert_with(|| {
                    let mut doc = Map::new();
                    doc.insert("versionId".into(), Value::String(a.version_id.into()));
                    verify_proof(&Value::Object(doc), a.proof)
                });
                if ok {
                    approved.insert(a.id.as_str());
                }
            }
        }
        if (approved.len() as u64) < rule.threshold {
            let error = VhLogError::at(
                ErrorCode::WitnessThresholdNotMet,
                i as u64 + 1,
                format!(
                    "entry {} has {} of {} required witness approvals",
                    i + 1,
                    approved.len(),
                    rule.threshold
                ),
            );
            return Some((i, error));
        }
    }
    None
}

/// Verifies a whole log file, returning its valid, witnessed prefix and the first failure.
///
/// `witness` is the parsed witness file, if there is one; `now` is the resolver's
/// clock in seconds since the epoch.
pub fn verify_log(log: &str, witness: Option<&Value>, now: i64) -> VerifiedLog {
    let lines: Vec<String> = parse_log_lines(log).into_iter().map(String::from).collect();
    let mut entries: Vec<VerifiedEntry> = Vec::new();
    let mut failure = None;
    if lines.is_empty() {
        let failure = Some(VhLogError::new(ErrorCode::InvalidLog, "log is empty", None));
        return VerifiedLog {
            entries,
            lines,
            failure,
        };
    }
    for (i, line) in lines.iter().enumerate() {
        let version = i as u64 + 1;
        let result = match serde_json::from_str::<Value>(line) {
            Err(_) => Err(VhLogError::at(
                ErrorCode::InvalidLog,
                version,
                format!("line {version} is not JSON"),
            )),
            Ok(Value::Object(raw)) => verify_entry(raw, entries.last(), now),
            Ok(_) => Err(VhLogError::at(
                ErrorCode::InvalidLog,
                version,
                format!("line {version} is not a JSON object"),
            )),
        };
        match result {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
    }
    if let Some((index, error)) = check_witnesses(&entries, witness) {
        entries.truncate(index);
        failure = Some(error);
    }
    VerifiedLog {
        entries,
        lines,
        failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_time_formats() {
        assert_eq!(parse_version_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_version_time("2026-01-01T00:00:00+00:00"),
            Some(1_767_225_600)
        );
        assert_eq!(
            parse_version_time("2024-02-29T23:59:59Z"),
            Some(1_709_251_199)
        );
        for bad in [
            "2023-02-29T00:00:00Z",
            "2026-01-01T00:00:00.5Z",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00+01:00",
            "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "0050-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_version_time(bad), None, "{bad}");
        }
    }
}
