//! did:vh (docs/didvh-profile.md).
//!
//! A did:vh DID log has the same format and verification as a VH-Log log
//! (did:vh and VH-Log are both derived from did:webvh), so the log is verified
//! by the VH-Log code with the did:vh [`Specialisation`]. This module adds the
//! DID syntax, the `srcLog`/`srcWitness` and DID URL rules, the resolution
//! options, and DID Resolution metadata and errors.
//!
//! ```
//! use serde_json::{json, Map};
//! use vh_log::Signer;
//! use vh_log::didvh::{ResolverContext, create_did, resolve_did};
//!
//! let key = Signer::from_seed_hex(&"01".repeat(32))?;
//! let mut params = Map::new();
//! params.insert("updateKeys".into(), json!([key.multikey()]));
//! let created = create_did(json!({"id": "did:vh:{SCID}"}), params, "2026-01-01T00:00:00Z", &[key]);
//!
//! let context = ResolverContext { now: Some("2026-06-01T00:00:00Z".into()), remote: false };
//! let result = resolve_did(&created.did, &json!({"didLog": created.log}), &context);
//! assert_eq!(result.did_document.unwrap()["id"], json!(created.did));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::error::{ErrorCode, GenerateError, VhLogError};
use crate::log::{UpdatedLog, create_log_with, parse_log_lines, update_log};
use crate::proof::Signer;
use crate::resolve::{ResolveInput, ResolveOptions, ResolveResult, Warning, resolve_with};
use crate::verify::{
    Specialisation, WitnessConfig, is_watcher_url, parse_version_time, verify_log_with,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fmt;

/// The `method` parameter value this library supports.
pub const DID_VH_METHOD: &str = "did:vh:1.0";
pub const DID_PREFIX: &str = "did:vh:";

/// did:vh error codes (DID Resolution, plus the did:vh-specific ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DidVhErrorCode {
    InvalidDid,
    InvalidDidUrl,
    InvalidOptions,
    NotFound,
    FeatureNotSupported,
    LogForked,
    InsufficientCopies,
}

impl DidVhErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            DidVhErrorCode::InvalidDid => "invalidDid",
            DidVhErrorCode::InvalidDidUrl => "invalidDidUrl",
            DidVhErrorCode::InvalidOptions => "invalidOptions",
            DidVhErrorCode::NotFound => "notFound",
            DidVhErrorCode::FeatureNotSupported => "featureNotSupported",
            DidVhErrorCode::LogForked => "logForked",
            DidVhErrorCode::InsufficientCopies => "insufficientCopies",
        }
    }
}

impl fmt::Display for DidVhErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A did:vh failure, with the VH-Log error behind it where there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidVhError {
    pub code: DidVhErrorCode,
    pub message: String,
    pub vh_log: Option<VhLogError>,
}

impl DidVhError {
    pub fn new(code: DidVhErrorCode, message: impl Into<String>) -> Self {
        DidVhError {
            code,
            message: message.into(),
            vh_log: None,
        }
    }
}

impl fmt::Display for DidVhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DidVhError {}

// ---------------------------------------------------------------- the DID

fn is_base58(c: u8) -> bool {
    c.is_ascii_alphanumeric() && !matches!(c, b'0' | b'O' | b'I' | b'l')
}

/// The SCID of a did:vh DID, or `None` if `did` does not match the ABNF.
pub fn parse_did(did: &str) -> Option<&str> {
    let scid = did.strip_prefix(DID_PREFIX)?;
    (scid.len() == 46 && scid.bytes().all(is_base58)).then_some(scid)
}

/// A well-formed `method` value: `did:vh:<major>.<minor>`, no leading zeros.
fn is_method_syntax(value: &str) -> bool {
    let number = |s: &str| {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
    };
    value
        .strip_prefix(DID_PREFIX)
        .and_then(|v| v.split_once('.'))
        .is_some_and(|(major, minor)| number(major) && number(minor))
}

/// The did:vh specialisation of VH-Log: `method` instead of `logVersion`, a
/// closed parameter set, and `state.id` = `did:vh:<SCID>` in every entry. With
/// `expected_scid`, the log's SCID must also be that of the DID being resolved.
pub fn specialisation(expected_scid: Option<String>) -> Specialisation {
    Specialisation {
        version_parameter: "method".into(),
        versions: vec![DID_VH_METHOD.into()],
        version_syntax: Some(is_method_syntax),
        extra_parameters: Some(Vec::new()),
        check_state: Some(Box::new(move |state, scid, version| {
            if let Some(expected) = &expected_scid
                && scid != expected
            {
                return Err(VhLogError::new(
                    ErrorCode::InvalidState,
                    format!("the log is for did:vh:{scid}, not did:vh:{expected}"),
                    Some(version),
                ));
            }
            let id = format!("{DID_PREFIX}{scid}");
            if state.get("id").and_then(Value::as_str) != Some(id.as_str()) {
                return Err(VhLogError::new(
                    ErrorCode::InvalidState,
                    format!("state.id must be {id}"),
                    Some(version),
                ));
            }
            Ok(())
        })),
    }
}

// ---------------------------------------------------------------- create / update

/// Result of [`create_did`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedDid {
    pub log: String,
    pub did: String,
    pub scid: String,
    pub version_id: String,
}

/// Creates a did:vh DID log. The document uses `did:vh:{SCID}` wherever it
/// refers to the DID; `method` and `scid` are added to the parameters if
/// absent. Like VH-Log generation, it does not validate its input.
pub fn create_did(
    document: Value,
    parameters: Map<String, Value>,
    version_time: &str,
    signers: &[Signer],
) -> CreatedDid {
    let created = create_log_with(
        document,
        parameters,
        version_time,
        signers,
        "method",
        DID_VH_METHOD,
    );
    CreatedDid {
        did: format!("{DID_PREFIX}{}", created.scid),
        log: created.log,
        scid: created.scid,
        version_id: created.version_id,
    }
}

/// Appends an entry to a did:vh DID log. Deactivate with parameters
/// `{"deactivated": true}`.
pub fn update_did(
    log: &str,
    document: Value,
    parameters: Map<String, Value>,
    version_time: &str,
    signers: &[Signer],
) -> Result<UpdatedLog, GenerateError> {
    update_log(log, document, parameters, version_time, signers)
}

// ---------------------------------------------------------------- shared URL checks

/// Percent-decodes `s` to a UTF-8 string, or `None` if an escape or the UTF-8 is malformed.
pub fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn is_digits(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_octet(s: &str) -> bool {
    is_digits(s, 3) && (s == "0" || !s.starts_with('0')) && s.parse::<u16>().is_ok_and(|n| n <= 255)
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host == "[::1]" {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| is_octet(p)) && parts[0] == "127"
}

fn is_domain_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    // An IPv4 literal, or a name ending in a number.
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    labels.iter().all(|l| {
        let b = l.as_bytes();
        (1..=63).contains(&b.len())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
    })
}

/// Splits `scheme:rest` (profile §3 steps 1–2); `None` unless `value` is
/// printable ASCII starting with a scheme. The scheme is lowercased.
fn split_scheme(value: &str) -> Option<(String, &str)> {
    if value.is_empty() || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return None;
    }
    let (scheme, rest) = value.split_once(':')?;
    let mut chars = scheme.bytes();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic()
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-'))
    {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), rest))
}

/// Checks an `http(s)` authority (profile §3); returns the lowercased host.
fn check_authority(authority: &str, https: bool) -> Option<String> {
    if authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let after = &authority[close + 1..];
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (&authority[..=close], port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let host = host.to_ascii_lowercase();
    if port.is_some_and(|p| !(is_digits(p, 5) && p.parse::<u32>().is_ok_and(|n| n <= 65535))) {
        return None;
    }
    let ok = if https {
        !host.starts_with('[') && is_domain_name(&host)
    } else {
        is_loopback_host(&host)
    };
    ok.then_some(host)
}

/// Checks the segments of a path that starts with `/` (profile §3). Each is
/// percent-decoded and must not be `.` or `..` or contain `/`, `\` or NUL.
/// With `strict` (the `src` DID URL parameter), it must also be non-empty and
/// not start or end with whitespace.
fn check_segments(path: &str, strict: bool) -> bool {
    path[1..].split('/').all(|raw| {
        let Some(segment) = percent_decode(raw) else {
            return false;
        };
        if segment == "." || segment == ".." || segment.contains(['/', '\\', '\0']) {
            return false;
        }
        if strict {
            // Rust's char::is_whitespace is exactly Unicode White_Space.
            let (Some(first), Some(last)) = (segment.chars().next(), segment.chars().last()) else {
                return false;
            };
            if first.is_whitespace() || last.is_whitespace() {
                return false;
            }
        }
        true
    })
}

// ---------------------------------------------------------------- srcLog / srcWitness references

/// The kind of a `srcLog` or `srcWitness` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RefKind {
    Web,
    Loopback,
    File,
    Other,
}

impl RefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RefKind::Web => "web",
            RefKind::Loopback => "loopback",
            RefKind::File => "file",
            RefKind::Other => "other",
        }
    }
}

/// Validates a `srcLog` or `srcWitness` reference, which names a file
/// (profile §3.1), and returns its kind. Fails with `invalidOptions`.
pub fn check_ref(reference: &str) -> Result<RefKind, DidVhError> {
    let invalid = |why: &str| {
        DidVhError::new(
            DidVhErrorCode::InvalidOptions,
            format!("reference {reference:?}: {why}"),
        )
    };
    let (scheme, rest) =
        split_scheme(reference).ok_or_else(|| invalid("not a printable-ASCII absolute URL"))?;
    if rest.contains('#') {
        return Err(invalid("must not have a fragment"));
    }
    match scheme.as_str() {
        "https" | "http" => {
            let after = rest
                .strip_prefix("//")
                .ok_or_else(|| invalid("missing authority"))?;
            let end = after.find(['/', '?']).unwrap_or(after.len());
            let (authority, after_authority) = after.split_at(end);
            let path = after_authority
                .split_once('?')
                .map_or(after_authority, |(p, _)| p);
            let https = scheme == "https";
            if check_authority(authority, https).is_none() {
                return Err(invalid(if https {
                    "invalid https host"
                } else {
                    "http is only allowed with a loopback host"
                }));
            }
            if path.is_empty() {
                return Err(invalid("must have a path"));
            }
            if !check_segments(path, false) {
                return Err(invalid("invalid path segment"));
            }
            Ok(if https {
                RefKind::Web
            } else {
                RefKind::Loopback
            })
        }
        "file" => {
            if rest.contains('?') {
                return Err(invalid("must not have a query"));
            }
            let path = if let Some(after) = rest.strip_prefix("//") {
                let slash = after
                    .find('/')
                    .ok_or_else(|| invalid("file URL needs an absolute path"))?;
                let host = after[..slash].to_ascii_lowercase();
                if !host.is_empty() && host != "localhost" {
                    return Err(invalid("file URL host must be empty or localhost"));
                }
                &after[slash..]
            } else if rest.starts_with('/') {
                rest
            } else {
                return Err(invalid("file URL needs an absolute path"));
            };
            if !check_segments(path, false) {
                return Err(invalid("invalid path segment"));
            }
            Ok(RefKind::File)
        }
        _ if rest.is_empty() => Err(invalid("empty URL")),
        _ => Ok(RefKind::Other),
    }
}

// ---------------------------------------------------------------- the src DID URL parameter

/// The references derived from a `src` DID URL parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrcReferences {
    pub src_log: String,
    pub src_witness: String,
}

/// Validates a (percent-decoded) `src` DID URL parameter and derives the
/// `srcLog` and `srcWitness` references from it (profile §3.2). Fails with
/// `invalidDidUrl`.
pub fn src_references(src: &str) -> Result<SrcReferences, DidVhError> {
    let invalid =
        |why: &str| DidVhError::new(DidVhErrorCode::InvalidDidUrl, format!("src {src:?}: {why}"));
    let (scheme, rest) =
        split_scheme(src).ok_or_else(|| invalid("not a printable-ASCII absolute URL"))?;
    if rest.contains(['?', '#']) {
        return Err(invalid("must not have a query or fragment"));
    }
    if scheme == "http" || scheme == "file" {
        return Err(invalid("http and file are not allowed in a DID URL"));
    }
    let after = rest
        .strip_prefix("//")
        .filter(|a| !a.is_empty() && !a.starts_with('/'))
        .ok_or_else(|| invalid("not a hierarchical URL with an authority"))?;
    let base = rest.strip_suffix('/').unwrap_or(rest);
    if scheme == "https" {
        let after = after.strip_suffix('/').unwrap_or(after);
        let (authority, path) = after.split_at(after.find('/').unwrap_or(after.len()));
        if check_authority(authority, true).is_none() {
            return Err(invalid("invalid https host"));
        }
        if !path.is_empty() && !check_segments(path, true) {
            return Err(invalid("invalid path segment"));
        }
    }
    Ok(SrcReferences {
        src_log: format!("{scheme}:{base}/did.jsonl"),
        src_witness: format!("{scheme}:{base}/did-witness.json"),
    })
}

// ---------------------------------------------------------------- DID URLs

/// A dereferenced did:vh DID URL.
#[derive(Debug, Clone, PartialEq)]
pub struct DidUrl {
    pub did: String,
    /// Resolution options from the query: `srcLog` and `srcWitness` (from
    /// `src`), `versionId`, `versionTime`, `versionNumber`.
    pub options: Map<String, Value>,
    pub fragment: Option<String>,
}

const URL_PARAMETERS: [&str; 4] = ["src", "versionId", "versionTime", "versionNumber"];
const OPTION_ONLY: [&str; 8] = [
    "didLog",
    "didWitness",
    "srcLog",
    "srcWitness",
    "checkWatchers",
    "extraWatchers",
    "minCopies",
    "includeDidLog",
];

/// Parses a did:vh DID URL as a dereferencer does (profile §4). Fails with
/// `invalidDidUrl`.
pub fn parse_did_url(did_url: &str) -> Result<DidUrl, DidVhError> {
    let invalid =
        |why: String| DidVhError::new(DidVhErrorCode::InvalidDidUrl, format!("{did_url:?}: {why}"));
    let (before_fragment, fragment) = match did_url.split_once('#') {
        Some((b, f)) => (b, Some(f.to_string())),
        None => (did_url, None),
    };
    let (did, query) = match before_fragment.split_once('?') {
        Some((d, q)) => (d, Some(q)),
        None => (before_fragment, None),
    };
    if parse_did(did).is_none() {
        return Err(invalid("not a did:vh DID".into()));
    }
    let mut seen: Vec<String> = Vec::new();
    let mut options = Map::new();
    for pair in query.into_iter().flat_map(|q| q.split('&')) {
        let (raw_key, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| invalid(format!("query parameter {pair:?} has no value")))?;
        let (Some(key), Some(value)) = (percent_decode(raw_key), percent_decode(raw_value)) else {
            return Err(invalid("malformed percent-encoding".into()));
        };
        if OPTION_ONLY.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{key} is a resolution option, not a DID URL parameter"
            )));
        }
        if !URL_PARAMETERS.contains(&key.as_str()) {
            continue;
        }
        if seen.contains(&key) {
            return Err(invalid(format!("{key} given more than once")));
        }
        seen.push(key.clone());
        match key.as_str() {
            "src" => {
                let refs = src_references(&value)?;
                options.insert("srcLog".into(), Value::String(refs.src_log));
                options.insert("srcWitness".into(), Value::String(refs.src_witness));
            }
            "versionNumber" => {
                if !is_digits(&value, 16) || value.starts_with('0') {
                    return Err(invalid("versionNumber must be a positive integer".into()));
                }
                let n: u64 = value.parse().expect("digits");
                options.insert(key, json!(n));
            }
            _ => {
                options.insert(key, Value::String(value));
            }
        }
    }
    Ok(DidUrl {
        did: did.to_string(),
        options,
        fragment,
    })
}

// ---------------------------------------------------------------- resolve

/// The resolver's context (profile §5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolverContext {
    /// `versionTime`-format time used as the resolver's clock; defaults to the current time.
    pub now: Option<String>,
    /// True for a resolver that accepts requests from other systems.
    pub remote: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProblemDetails {
    pub title: DidVhErrorCode,
    pub detail: String,
    /// The VH-Log error behind a did:vh error, where there is one.
    #[serde(rename = "vhLog", skip_serializing_if = "Option::is_none")]
    pub vh_log: Option<VhLogError>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidResolutionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DidVhErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_details: Option<ProblemDetails>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_witness: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentMetadata {
    pub version_id: String,
    pub version_time: String,
    pub created: String,
    pub updated: String,
    pub scid: String,
    pub deactivated: bool,
    pub ttl: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessConfig>,
    pub watchers: Vec<String>,
}

/// The result of [`resolve_did`].
#[derive(Debug, Clone, PartialEq)]
pub struct DidResolution {
    pub did_resolution_metadata: DidResolutionMetadata,
    pub did_document: Option<Value>,
    /// `None` on error (serialised as `{}`).
    pub did_document_metadata: Option<DidDocumentMetadata>,
}

impl DidResolution {
    fn failure(error: DidVhError) -> Self {
        DidResolution {
            did_resolution_metadata: DidResolutionMetadata {
                content_type: None,
                error: Some(error.code),
                problem_details: Some(ProblemDetails {
                    title: error.code,
                    detail: error.message,
                    vh_log: error.vh_log,
                }),
                warnings: Vec::new(),
                did_log: None,
                did_witness: None,
            },
            did_document: None,
            did_document_metadata: None,
        }
    }

    /// The error code, if resolution failed.
    pub fn error(&self) -> Option<DidVhErrorCode> {
        self.did_resolution_metadata.error
    }

    /// The JSON form: `{didResolutionMetadata, didDocument, didDocumentMetadata}`.
    pub fn to_json(&self) -> Value {
        json!({
            "didResolutionMetadata": self.did_resolution_metadata,
            "didDocument": self.did_document,
            "didDocumentMetadata": self.did_document_metadata.as_ref().map_or_else(|| json!({}), |m| json!(m)),
        })
    }
}

fn positive_integer(v: &Value) -> Option<u64> {
    v.as_f64()
        .filter(|f| f.fract() == 0.0 && *f >= 1.0)
        .map(|f| f as u64)
}

/// did:vh Resolution Options validation (profile §5, step 2).
fn validate_options(options: &Value, remote: bool) -> Result<&Map<String, Value>, DidVhError> {
    let invalid = |why: &str| DidVhError::new(DidVhErrorCode::InvalidOptions, why);
    let o = options
        .as_object()
        .ok_or_else(|| invalid("resolution options must be an object"))?;
    let has = |k: &str| o.contains_key(k);
    if has("didLog") == has("srcLog") {
        return Err(invalid("exactly one of didLog and srcLog must be given"));
    }
    if has("didWitness") && has("srcWitness") {
        return Err(invalid(
            "at most one of didWitness and srcWitness may be given",
        ));
    }
    if o.get("didLog").is_some_and(|v| !v.is_string()) {
        return Err(invalid("didLog must be a string"));
    }
    if o.get("didWitness").is_some_and(|v| !v.is_array()) {
        return Err(invalid("didWitness must be an array"));
    }
    for key in ["srcLog", "srcWitness"] {
        let Some(value) = o.get(key) else { continue };
        let kind = value
            .as_str()
            .ok_or_else(|| invalid(&format!("{key} must be a string")))
            .and_then(check_ref)?;
        if remote && matches!(kind, RefKind::File | RefKind::Loopback) {
            return Err(invalid(&format!(
                "{key}: a resolver that serves other systems must not use local file or loopback references"
            )));
        }
    }
    let selectors = ["versionId", "versionTime", "versionNumber"]
        .iter()
        .filter(|k| has(k))
        .count();
    if selectors > 1 {
        return Err(invalid(
            "at most one of versionId, versionTime and versionNumber may be given",
        ));
    }
    if o.get("versionId").is_some_and(|v| !v.is_string()) {
        return Err(invalid("versionId must be a string"));
    }
    if o.get("versionTime")
        .is_some_and(|v| v.as_str().and_then(parse_version_time).is_none())
    {
        return Err(invalid(
            "versionTime must be a whole-second UTC ISO 8601 time",
        ));
    }
    if o.get("versionNumber")
        .is_some_and(|v| positive_integer(v).is_none())
    {
        return Err(invalid("versionNumber must be a positive integer"));
    }
    if let Some(c) = o.get("checkWatchers") {
        let ok =
            c.as_str() == Some("all") || c.as_f64().is_some_and(|f| f.fract() == 0.0 && f >= 0.0);
        if !ok {
            return Err(invalid(
                "checkWatchers must be a non-negative integer or \"all\"",
            ));
        }
    }
    if let Some(w) = o.get("extraWatchers") {
        let ok = w.as_array().is_some_and(|urls| {
            urls.iter().all(|u| {
                u.as_str()
                    .is_some_and(|u| u.starts_with("https://") && is_watcher_url(u))
            })
        });
        if !ok {
            return Err(invalid("extraWatchers must be an array of https URLs"));
        }
    }
    if o.get("minCopies")
        .is_some_and(|v| positive_integer(v).is_none())
    {
        return Err(invalid("minCopies must be a positive integer"));
    }
    if o.get("includeDidLog").is_some_and(|v| !v.is_boolean()) {
        return Err(invalid("includeDidLog must be a boolean"));
    }
    Ok(o)
}

fn map_error(code: ErrorCode) -> DidVhErrorCode {
    match code {
        ErrorCode::NotFound => DidVhErrorCode::NotFound,
        ErrorCode::InvalidOption => DidVhErrorCode::InvalidOptions,
        ErrorCode::ForkDetected => DidVhErrorCode::LogForked,
        ErrorCode::MinCopiesNotMet => DidVhErrorCode::InsufficientCopies,
        ErrorCode::UnsupportedLogVersion => DidVhErrorCode::FeatureNotSupported,
        _ => DidVhErrorCode::InvalidDid,
    }
}

fn from_vh_log(error: VhLogError) -> DidVhError {
    DidVhError {
        code: map_error(error.code),
        message: error.message.clone(),
        vh_log: Some(error),
    }
}

/// The current time in `versionTime` format.
fn current_time() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since the epoch (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// did:vh `resolve(did, resolutionOptions)` (profile §5). This resolver is
/// offline: it verifies a log passed in `didLog` (and `didWitness`), and
/// returns `featureNotSupported` when it would have to retrieve anything.
pub fn resolve_did(did: &str, options: &Value, context: &ResolverContext) -> DidResolution {
    match resolve_inner(did, options, context) {
        Ok(r) => r,
        Err(e) => DidResolution::failure(e),
    }
}

fn resolve_inner(
    did: &str,
    options: &Value,
    context: &ResolverContext,
) -> Result<DidResolution, DidVhError> {
    let scid = parse_did(did).ok_or_else(|| {
        DidVhError::new(
            DidVhErrorCode::InvalidDid,
            format!("{did:?} is not a did:vh DID"),
        )
    })?;
    let o = validate_options(options, context.remote)?;
    let unsupported = |why: &str| DidVhError::new(DidVhErrorCode::FeatureNotSupported, why);
    if o.contains_key("srcLog") {
        return Err(unsupported(
            "this resolver does not retrieve srcLog references",
        ));
    }
    let watchers = o
        .get("checkWatchers")
        .is_some_and(|c| c.as_f64() != Some(0.0))
        || o.get("extraWatchers")
            .and_then(Value::as_array)
            .is_some_and(|w| !w.is_empty());
    if watchers {
        return Err(unsupported(
            "this resolver does not retrieve copies from watchers",
        ));
    }
    let spec = specialisation(Some(scid.to_string()));
    let now = context.now.clone().unwrap_or_else(current_time);
    let log = o["didLog"].as_str().expect("validated");
    let witness = o.get("didWitness");
    // Whether the log needs witnessing does not depend on the witness file. Without
    // one, the first entry that needs it fails, which cuts it from `entries`.
    let clock = parse_version_time(&now)
        .or_else(|| parse_version_time(&current_time()))
        .expect("valid time");
    let unwitnessed = verify_log_with(log, None, clock, &spec);
    let witnessed = unwitnessed
        .failure
        .as_ref()
        .is_some_and(|f| f.code == ErrorCode::WitnessThresholdNotMet)
        || unwitnessed.entries.iter().any(|e| e.witness_rule.is_some());
    if witnessed && o.contains_key("srcWitness") {
        return Err(unsupported(
            "this resolver does not retrieve srcWitness references",
        ));
    }
    let resolve_options = ResolveOptions {
        version_id: o.get("versionId").and_then(Value::as_str).map(String::from),
        version_time: o
            .get("versionTime")
            .and_then(Value::as_str)
            .map(String::from),
        version_number: o.get("versionNumber").and_then(positive_integer),
        min_copies: o.get("minCopies").and_then(positive_integer),
    };
    let input = ResolveInput {
        log: log.to_string(),
        witness: witness.cloned(),
        now,
        options: resolve_options,
        copies: None,
        retained_version_id: None,
    };
    let result = match resolve_with(&input, &spec) {
        ResolveResult::Invalid(e) => return Err(from_vh_log(e)),
        ResolveResult::Valid(r) => r,
    };
    let selected = ["versionId", "versionTime", "versionNumber"]
        .iter()
        .any(|k| o.contains_key(*k));
    if let Some(e) = result
        .error
        .as_ref()
        .filter(|e| e.code == ErrorCode::UnsupportedLogVersion)
        && !selected
    {
        // Entries after the last valid one may change the document or its keys (profile §5).
        return Err(from_vh_log(e.clone()));
    }
    let m = result.metadata;
    // A deactivated DID's document is not returned; earlier versions still are (profile §5).
    let is_last = m.version_time == m.updated;
    let mut meta = DidResolutionMetadata {
        content_type: Some("application/did+json".into()),
        error: None,
        problem_details: None,
        warnings: m.warnings,
        did_log: None,
        did_witness: None,
    };
    if o.get("includeDidLog") == Some(&Value::Bool(true)) {
        let lines = parse_log_lines(log);
        let valid = result
            .first_invalid_version
            .map_or(lines.len(), |v| v as usize - 1);
        meta.did_log = Some(lines[..valid].iter().map(|l| format!("{l}\n")).collect());
        if witnessed {
            meta.did_witness = Some(witness.cloned().unwrap_or_else(|| json!([])));
        }
    }
    Ok(DidResolution {
        did_resolution_metadata: meta,
        did_document: if m.deactivated && is_last {
            None
        } else {
            Some(Value::Object(result.state))
        },
        did_document_metadata: Some(DidDocumentMetadata {
            version_id: m.version_id,
            version_time: m.version_time,
            created: m.created,
            updated: m.updated,
            scid: m.scid,
            deactivated: m.deactivated,
            ttl: m.ttl,
            witness: m.witness,
            watchers: m.watchers,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_syntax() {
        for ok in ["did:vh:1.0", "did:vh:0.0", "did:vh:10.23"] {
            assert!(is_method_syntax(ok), "{ok}");
        }
        for bad in [
            "did:webvh:1.0",
            "did:vh:01.0",
            "did:vh:1.01",
            "did:vh:1",
            "did:vh:1.",
            "did:vh:.1",
            "did:vh:1.0.0",
        ] {
            assert!(!is_method_syntax(bad), "{bad}");
        }
    }

    #[test]
    fn current_time_is_a_version_time() {
        assert!(parse_version_time(&current_time()).is_some());
    }
}
