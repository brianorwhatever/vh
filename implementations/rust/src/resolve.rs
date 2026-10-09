//! Resolution: version selection, partial validity and copy comparison (profile §4).

use crate::error::{ErrorCode, ForkCopy, ForkReport, VhLogError};
use crate::verify::{VerifiedEntry, VerifiedLog, WitnessConfig, parse_version_time, verify_log};
use serde::Serialize;
use serde_json::{Map, Value};

const PRIMARY: &str = "primary";
const OPTION_KEYS: [&str; 4] = ["versionId", "versionTime", "versionNumber", "minCopies"];

/// Resolution options. At most one version selector may be set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveOptions {
    pub version_id: Option<String>,
    pub version_time: Option<String>,
    pub version_number: Option<u64>,
    pub min_copies: Option<u64>,
}

impl ResolveOptions {
    /// Parses the protocol's `options` object, rejecting unknown options and wrong types
    /// with `invalid-option`. Semantic checks happen in [`resolve`].
    pub fn from_json(value: &Value) -> Result<Self, VhLogError> {
        let invalid = |msg: String| VhLogError::new(ErrorCode::InvalidOption, msg, None);
        let map = match value {
            Value::Null => return Ok(Self::default()),
            Value::Object(map) => map,
            _ => return Err(invalid("options must be an object".into())),
        };
        if let Some(key) = map.keys().find(|k| !OPTION_KEYS.contains(&k.as_str())) {
            return Err(invalid(format!("unsupported option {key}")));
        }
        let string = |key: &str| -> Result<Option<String>, VhLogError> {
            map.get(key)
                .map(|v| {
                    v.as_str()
                        .map(String::from)
                        .ok_or_else(|| invalid(format!("{key} must be a string")))
                })
                .transpose()
        };
        let positive = |key: &str| -> Result<Option<u64>, VhLogError> {
            map.get(key)
                .map(|v| {
                    v.as_f64()
                        .filter(|f| f.fract() == 0.0 && *f >= 1.0)
                        .map(|f| f as u64)
                        .ok_or_else(|| invalid(format!("{key} must be a positive integer")))
                })
                .transpose()
        };
        Ok(ResolveOptions {
            version_id: string("versionId")?,
            version_time: string("versionTime")?,
            version_number: positive("versionNumber")?,
            min_copies: positive("minCopies")?,
        })
    }

    fn validate(&self) -> Result<(), VhLogError> {
        let invalid = |msg: &str| VhLogError::new(ErrorCode::InvalidOption, msg, None);
        let selectors = [
            self.version_id.is_some(),
            self.version_time.is_some(),
            self.version_number.is_some(),
        ];
        if selectors.iter().filter(|s| **s).count() > 1 {
            return Err(invalid("at most one version selector may be given"));
        }
        if self
            .version_time
            .as_deref()
            .is_some_and(|t| parse_version_time(t).is_none())
        {
            return Err(invalid(
                "versionTime must be a whole-second UTC ISO 8601 time",
            ));
        }
        if self.version_number == Some(0) || self.min_copies == Some(0) {
            return Err(invalid(
                "versionNumber and minCopies must be positive integers",
            ));
        }
        Ok(())
    }
}

/// A copy of the log obtained from a watcher (or elsewhere).
#[derive(Debug, Clone, PartialEq)]
pub enum CopyInput {
    Available {
        source: String,
        log: String,
        witness: Option<Value>,
    },
    Unavailable {
        source: String,
        reason: String,
    },
}

impl CopyInput {
    pub fn source(&self) -> &str {
        match self {
            CopyInput::Available { source, .. } | CopyInput::Unavailable { source, .. } => source,
        }
    }
}

/// Everything a resolution needs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResolveInput {
    pub log: String,
    /// The parsed witness file, if there is one.
    pub witness: Option<Value>,
    /// The resolver's clock, as a `versionTime`-format string.
    pub now: String,
    pub options: ResolveOptions,
    /// Other copies to compare against; `Some` (even if empty) enables copy comparison.
    pub copies: Option<Vec<CopyInput>>,
    /// A `versionId` remembered from an earlier resolution.
    pub retained_version_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CopyStatus {
    Current,
    Behind,
    Invalid,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WarningCode {
    InvalidEntries,
    CopyInvalid,
    CopyUnavailable,
    CopyBehind,
    RetainedVersionNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: WarningCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyReport {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    pub status: CopyStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    pub version_id: String,
    pub version_time: String,
    pub version_number: u64,
    pub created: String,
    pub updated: String,
    pub scid: String,
    pub deactivated: bool,
    pub ttl: u64,
    pub witness: Option<WitnessConfig>,
    pub watchers: Vec<String>,
    pub update_keys: Vec<String>,
    pub next_key_hashes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copies: Option<Vec<CopyReport>>,
    pub warnings: Vec<Warning>,
}

/// A successful resolution, possibly of a partially valid log.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolution {
    pub state: Map<String, Value>,
    pub metadata: ResolutionMetadata,
    pub first_invalid_version: Option<u64>,
    pub error: Option<VhLogError>,
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveResult {
    Valid(Box<Resolution>),
    Invalid(VhLogError),
}

impl ResolveResult {
    /// The protocol's JSON form (`{"valid": true, …}` or `{"valid": false, "error": …}`).
    pub fn to_json(&self) -> Value {
        match self {
            ResolveResult::Valid(r) => {
                let Value::Object(mut map) = serde_json::to_value(r).expect("serialises") else {
                    unreachable!()
                };
                map.insert("valid".into(), Value::Bool(true));
                Value::Object(map)
            }
            ResolveResult::Invalid(e) => {
                serde_json::json!({ "valid": false, "error": e })
            }
        }
    }
}

fn line_version_id(lines: &[String], index: usize) -> Option<String> {
    let value: Value = serde_json::from_str(lines.get(index)?).ok()?;
    value.get("versionId")?.as_str().map(String::from)
}

/// Picks the target entry (Selecting a Version). A target at or after the first
/// invalid entry fails with that entry's error (profile §4).
fn select_entry<'a>(
    verified: &'a VerifiedLog,
    options: &ResolveOptions,
) -> Result<&'a VerifiedEntry, VhLogError> {
    let VerifiedLog {
        entries,
        lines,
        failure,
    } = verified;
    let invalid = || {
        let f = failure.as_ref().expect("an invalid line implies a failure");
        VhLogError::new(
            f.code,
            format!("requested version is invalid: {}", f.message),
            f.version,
        )
    };
    if let Some(id) = &options.version_id {
        if let Some(found) = entries.iter().find(|e| &e.entry.version_id == id) {
            return Ok(found);
        }
        if (entries.len()..lines.len()).any(|i| line_version_id(lines, i).as_ref() == Some(id)) {
            return Err(invalid());
        }
        return Err(VhLogError::new(
            ErrorCode::NotFound,
            format!("no entry with versionId {id}"),
            None,
        ));
    }
    if let Some(n) = options.version_number {
        if n <= entries.len() as u64 {
            return Ok(&entries[n as usize - 1]);
        }
        if n <= lines.len() as u64 {
            return Err(invalid());
        }
        return Err(VhLogError::new(
            ErrorCode::NotFound,
            format!("no entry with version number {n}"),
            None,
        ));
    }
    if let Some(t) = &options.version_time {
        let time = parse_version_time(t).expect("validated");
        if failure.is_some() && entries.len() < lines.len() {
            let first_invalid_time = serde_json::from_str::<Value>(&lines[entries.len()])
                .ok()
                .and_then(|v| {
                    v.get("versionTime")
                        .and_then(Value::as_str)
                        .and_then(parse_version_time)
                });
            if first_invalid_time.is_some_and(|fit| fit <= time) {
                return Err(invalid());
            }
        }
        return entries
            .iter()
            .rev()
            .find(|e| e.time <= time)
            .ok_or_else(|| {
                VhLogError::new(ErrorCode::NotFound, format!("no entry active at {t}"), None)
            });
    }
    Ok(entries.last().expect("at least one valid entry"))
}

fn build_result(
    verified: &VerifiedLog,
    options: &ResolveOptions,
    mut warnings: Vec<Warning>,
    copies: Option<Vec<CopyReport>>,
) -> Result<Resolution, VhLogError> {
    let target = select_entry(verified, options)?;
    let first = &verified.entries[0];
    let last = verified.entries.last().expect("non-empty");
    if let Some(f) = &verified.failure {
        let from = f.version.map_or("?".to_string(), |v| v.to_string());
        warnings.push(Warning {
            code: WarningCode::InvalidEntries,
            source: None,
            message: format!(
                "entries from version {from} fail verification: {}",
                f.message
            ),
        });
    }
    let metadata = ResolutionMetadata {
        version_id: target.entry.version_id.clone(),
        version_time: target.entry.version_time.clone(),
        version_number: target.version_number,
        created: first.entry.version_time.clone(),
        updated: last.entry.version_time.clone(),
        scid: first.parameters.scid.clone(),
        deactivated: last.parameters.deactivated,
        ttl: last.parameters.ttl,
        witness: last.parameters.witness.clone(),
        watchers: last.parameters.watchers.clone(),
        update_keys: target.parameters.update_keys.clone(),
        next_key_hashes: target.parameters.next_key_hashes.clone(),
        copies,
        warnings,
    };
    Ok(Resolution {
        state: target.entry.state.clone(),
        metadata,
        first_invalid_version: verified
            .failure
            .as_ref()
            .map(|_| verified.entries.len() as u64 + 1),
        error: verified.failure.clone(),
    })
}

fn check_retained(
    reference: &VerifiedLog,
    reference_source: &str,
    retained: &str,
    warnings: &mut Vec<Warning>,
) -> Result<(), VhLogError> {
    let digits = retained
        .split_once('-')
        .map(|(n, _)| n)
        .filter(|n| !n.is_empty() && !n.starts_with('0') && n.bytes().all(|b| b.is_ascii_digit()));
    let Some(digits) = digits else {
        return Err(VhLogError::new(
            ErrorCode::InvalidOption,
            "retainedVersionId is not a versionId",
            None,
        ));
    };
    let n = digits.parse::<u64>().unwrap_or(u64::MAX);
    let count = reference.entries.len() as u64;
    if count < n {
        warnings.push(Warning {
            code: WarningCode::RetainedVersionNotFound,
            source: None,
            message: format!("the log has {count} valid entries, fewer than retained version {n}"),
        });
        return Ok(());
    }
    let version_id = &reference.entries[n as usize - 1].entry.version_id;
    if version_id != retained {
        let mut error = VhLogError::new(
            ErrorCode::ForkDetected,
            format!("retained versionId differs at version {n}"),
            Some(n),
        );
        error.fork = Some(ForkReport {
            version: n,
            copies: vec![
                ForkCopy {
                    source: "retained".into(),
                    version_id: retained.into(),
                },
                ForkCopy {
                    source: reference_source.into(),
                    version_id: version_id.clone(),
                },
            ],
        });
        return Err(error);
    }
    Ok(())
}

/// First version number at which two logs' versionIds differ.
fn divergence(a: &[String], b: &[String]) -> u64 {
    let n = a.len().min(b.len());
    (0..n)
        .find(|&i| line_version_id(a, i) != line_version_id(b, i))
        .unwrap_or(n) as u64
        + 1
}

/// Comparing Copies of a Log, with copies supplied in the request instead of fetched.
fn resolve_copies(input: &ResolveInput, now: i64) -> Result<Resolution, VhLogError> {
    let mut all = vec![CopyInput::Available {
        source: PRIMARY.into(),
        log: input.log.clone(),
        witness: input.witness.clone(),
    }];
    all.extend(input.copies.iter().flatten().cloned());
    let verified: Vec<Option<VerifiedLog>> = all
        .iter()
        .map(|c| match c {
            CopyInput::Available { log, witness, .. } => {
                Some(verify_log(log, witness.as_ref(), now))
            }
            CopyInput::Unavailable { .. } => None,
        })
        .collect();
    let v = |i: usize| verified[i].as_ref().expect("available copy");
    let mut warnings = Vec::new();
    let mut status: Vec<Option<CopyStatus>> = vec![None; all.len()];
    let mark_invalid =
        |i: usize, status: &mut Vec<Option<CopyStatus>>, warnings: &mut Vec<Warning>| {
            status[i] = Some(CopyStatus::Invalid);
            let f = v(i).failure.as_ref();
            warnings.push(Warning {
                code: WarningCode::CopyInvalid,
                source: Some(all[i].source().into()),
                message: format!(
                    "copy fails verification at version {}: {}",
                    f.and_then(|f| f.version)
                        .map_or("?".into(), |v| v.to_string()),
                    f.map_or("", |f| f.message.as_str())
                ),
            });
        };

    for (i, c) in all.iter().enumerate() {
        if let CopyInput::Unavailable { source, reason } = c {
            status[i] = Some(CopyStatus::Unavailable);
            warnings.push(Warning {
                code: WarningCode::CopyUnavailable,
                source: Some(source.clone()),
                message: reason.clone(),
            });
        }
    }

    let mut reference = None;
    for i in 0..all.len() {
        if status[i].is_some() {
            continue;
        }
        if v(i).is_fully_valid() {
            reference = Some(i);
            break;
        }
        mark_invalid(i, &mut status, &mut warnings);
    }
    let Some(mut r) = reference else {
        return Err(v(0)
            .failure
            .clone()
            .unwrap_or_else(|| VhLogError::new(ErrorCode::InvalidLog, "no copy verifies", None)));
    };

    let mut matched = vec![false; all.len()];
    matched[r] = true;
    for i in 0..all.len() {
        if status[i].is_some() || matched[i] {
            continue;
        }
        let ref_log = v(r);
        let copy_lines = &v(i).lines;
        if copy_lines.is_empty() {
            mark_invalid(i, &mut status, &mut warnings);
            continue;
        }
        let ref_lines = &ref_log.lines;
        let (mut same, mut extends) = (false, false);
        if copy_lines.len() <= ref_lines.len() {
            same = line_version_id(copy_lines, copy_lines.len() - 1).as_ref()
                == Some(&ref_log.entries[copy_lines.len() - 1].entry.version_id);
        } else {
            extends = line_version_id(copy_lines, ref_lines.len() - 1).as_ref()
                == Some(&ref_log.entries.last().expect("non-empty").entry.version_id);
        }
        if same {
            matched[i] = true;
        } else if extends {
            if v(i).is_fully_valid() {
                matched[i] = true;
                r = i;
            } else {
                mark_invalid(i, &mut status, &mut warnings);
            }
        } else if !v(i).is_fully_valid() {
            mark_invalid(i, &mut status, &mut warnings);
        } else {
            let version = divergence(ref_lines, copy_lines);
            let fork_copy = |source: &str, lines: &[String]| ForkCopy {
                source: source.into(),
                version_id: line_version_id(lines, version as usize - 1).unwrap_or_default(),
            };
            let mut error = VhLogError::new(
                ErrorCode::ForkDetected,
                format!("copies diverge at version {version}"),
                Some(version),
            );
            error.fork = Some(ForkReport {
                version,
                copies: vec![
                    fork_copy(all[r].source(), ref_lines),
                    fork_copy(all[i].source(), copy_lines),
                ],
            });
            return Err(error);
        }
    }

    let reference = v(r);
    if let Some(retained) = &input.retained_version_id {
        check_retained(reference, all[r].source(), retained, &mut warnings)?;
    }
    let mut copies = Vec::new();
    for (i, c) in all.iter().enumerate() {
        let source = c.source().to_string();
        match status[i] {
            Some(CopyStatus::Unavailable) => copies.push(CopyReport {
                source,
                version_id: None,
                status: CopyStatus::Unavailable,
            }),
            Some(s) => {
                let lines = &v(i).lines;
                let version_id = lines
                    .len()
                    .checked_sub(1)
                    .and_then(|last| line_version_id(lines, last));
                copies.push(CopyReport {
                    source,
                    version_id,
                    status: s,
                });
            }
            None => {
                let lines = &v(i).lines;
                let behind = reference.lines.len() as i64 - lines.len() as i64;
                if behind > 0 {
                    warnings.push(Warning {
                        code: WarningCode::CopyBehind,
                        source: Some(source.clone()),
                        message: format!("copy is {behind} entries behind"),
                    });
                }
                copies.push(CopyReport {
                    source,
                    version_id: line_version_id(lines, lines.len() - 1),
                    status: if behind > 0 {
                        CopyStatus::Behind
                    } else {
                        CopyStatus::Current
                    },
                });
            }
        }
    }
    let usable = copies
        .iter()
        .filter(|c| matches!(c.status, CopyStatus::Current | CopyStatus::Behind))
        .count() as u64;
    let min_copies = input.options.min_copies.unwrap_or(1);
    if usable < min_copies {
        return Err(VhLogError::new(
            ErrorCode::MinCopiesNotMet,
            format!("{usable} matching copies, {min_copies} required"),
            None,
        ));
    }
    build_result(reference, &input.options, warnings, Some(copies))
}

fn resolve_inner(input: &ResolveInput) -> Result<Resolution, VhLogError> {
    let now = parse_version_time(&input.now).ok_or_else(|| {
        VhLogError::new(
            ErrorCode::InvalidOption,
            "now must be a whole-second UTC ISO 8601 time",
            None,
        )
    })?;
    input.options.validate()?;
    if input.copies.is_some() || input.options.min_copies.unwrap_or(1) > 1 {
        return resolve_copies(input, now);
    }
    let verified = verify_log(&input.log, input.witness.as_ref(), now);
    if verified.entries.is_empty() {
        return Err(verified.failure.expect("an empty prefix implies a failure"));
    }
    let mut warnings = Vec::new();
    if let Some(retained) = &input.retained_version_id {
        check_retained(&verified, PRIMARY, retained, &mut warnings)?;
    }
    build_result(&verified, &input.options, warnings, None)
}

/// Resolves a log (Reading a VH-Log), comparing copies if any are given.
pub fn resolve(input: &ResolveInput) -> ResolveResult {
    match resolve_inner(input) {
        Ok(r) => ResolveResult::Valid(Box::new(r)),
        Err(e) => ResolveResult::Invalid(e),
    }
}
