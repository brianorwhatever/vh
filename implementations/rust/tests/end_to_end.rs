//! Create/update/witness/resolve round trips through the public API.

use serde_json::{Map, Value, json};
use vh_log::*;

const NOW: &str = "2026-06-01T00:00:00Z";

fn signer(byte: u8) -> Signer {
    Signer::from_seed(&[byte; 32])
}

fn params(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn resolve_log(log: &str, witness: Option<Value>, options: ResolveOptions) -> ResolveResult {
    resolve(&ResolveInput {
        log: log.into(),
        witness,
        now: NOW.into(),
        options,
        ..ResolveInput::default()
    })
}

fn valid(result: ResolveResult) -> Resolution {
    match result {
        ResolveResult::Valid(r) => *r,
        ResolveResult::Invalid(e) => panic!("expected a valid resolution, got {e}"),
    }
}

fn invalid(result: ResolveResult) -> VhLogError {
    match result {
        ResolveResult::Invalid(e) => e,
        ResolveResult::Valid(r) => panic!("expected failure, got {:?}", r.metadata),
    }
}

#[test]
fn create_update_resolve() {
    let key = signer(1);
    let created = create_log(
        json!({"id": "example:{SCID}"}),
        params(json!({"updateKeys": [key.multikey()]})),
        "2026-01-01T00:00:00Z",
        std::slice::from_ref(&key),
    );
    assert!(created.version_id.starts_with("1-Qm"));
    let updated = update_log(
        &created.log,
        json!({"id": format!("example:{}", created.scid), "n": 2}),
        Map::new(),
        "2026-01-02T00:00:00Z",
        std::slice::from_ref(&key),
    )
    .unwrap();
    assert_eq!(parse_log_lines(&updated.log).len(), 2);

    let r = valid(resolve_log(&updated.log, None, ResolveOptions::default()));
    assert_eq!(r.metadata.version_id, updated.version_id);
    assert_eq!(r.metadata.version_number, 2);
    assert_eq!(r.metadata.scid, created.scid);
    assert_eq!(r.metadata.created, "2026-01-01T00:00:00Z");
    assert_eq!(r.metadata.updated, "2026-01-02T00:00:00Z");
    assert_eq!(r.state["n"], 2);
    assert_eq!(r.state["id"], format!("example:{}", created.scid));
    assert_eq!(r.metadata.ttl, 3600);
    assert!(r.first_invalid_version.is_none());

    let first = valid(resolve_log(
        &updated.log,
        None,
        ResolveOptions {
            version_number: Some(1),
            ..ResolveOptions::default()
        },
    ));
    assert_eq!(first.metadata.version_id, created.version_id);

    let missing = invalid(resolve_log(
        &updated.log,
        None,
        ResolveOptions {
            version_number: Some(3),
            ..ResolveOptions::default()
        },
    ));
    assert_eq!(missing.code, ErrorCode::NotFound);
}

#[test]
fn unauthorized_update_is_partially_valid() {
    let (key, other) = (signer(1), signer(2));
    let created = create_log(
        json!({}),
        params(json!({"updateKeys": [key.multikey()]})),
        "2026-01-01T00:00:00Z",
        std::slice::from_ref(&key),
    );
    let updated = update_log(
        &created.log,
        json!({}),
        Map::new(),
        "2026-01-02T00:00:00Z",
        &[other],
    )
    .unwrap();
    let r = valid(resolve_log(&updated.log, None, ResolveOptions::default()));
    assert_eq!(r.first_invalid_version, Some(2));
    assert_eq!(r.error.as_ref().unwrap().code, ErrorCode::UnauthorizedKey);
    assert_eq!(r.metadata.version_number, 1);
    assert_eq!(r.metadata.warnings[0].code, WarningCode::InvalidEntries);
}

#[test]
fn tampered_genesis_fails() {
    let key = signer(1);
    let created = create_log(
        json!({"a": 1}),
        params(json!({"updateKeys": [key.multikey()]})),
        "2026-01-01T00:00:00Z",
        &[key],
    );
    let tampered = created.log.replace("\"a\":1", "\"a\":2");
    let e = invalid(resolve_log(&tampered, None, ResolveOptions::default()));
    assert_eq!(e.code, ErrorCode::InvalidProof);
    assert_eq!(e.version, Some(1));
}

#[test]
fn witnessed_log_and_deactivation() {
    let (key, w1, w2) = (signer(1), signer(2), signer(3));
    let witness = json!({
        "threshold": 2,
        "witnesses": [{"id": format!("did:key:{}", w1.multikey())}, {"id": format!("did:key:{}", w2.multikey())}]
    });
    let created = create_log(
        json!({}),
        params(json!({"updateKeys": [key.multikey()], "witness": witness})),
        "2026-01-01T00:00:00Z",
        std::slice::from_ref(&key),
    );
    let deactivated = update_log(
        &created.log,
        json!({}),
        params(json!({"deactivated": true})),
        "2026-01-02T00:00:00Z",
        std::slice::from_ref(&key),
    )
    .unwrap();

    // One witness is below the threshold.
    let file = json!([{ "versionId": deactivated.version_id, "proof": [witness_proof(&deactivated.version_id, &w1, None)] }]);
    let e = invalid(resolve_log(
        &deactivated.log,
        Some(file),
        ResolveOptions::default(),
    ));
    assert_eq!(e.code, ErrorCode::WitnessThresholdNotMet);

    // Proofs over the last entry cover the earlier one too.
    let proofs: Vec<Proof> = [&w1, &w2]
        .iter()
        .map(|w| witness_proof(&deactivated.version_id, w, None))
        .collect();
    let file = json!([{ "versionId": deactivated.version_id, "proof": proofs }]);
    let r = valid(resolve_log(
        &deactivated.log,
        Some(file.clone()),
        ResolveOptions::default(),
    ));
    assert!(r.metadata.deactivated);
    assert_eq!(r.metadata.witness.as_ref().unwrap().threshold, 2);

    let after = update_log(
        &deactivated.log,
        json!({}),
        Map::new(),
        "2026-01-03T00:00:00Z",
        &[key],
    )
    .unwrap();
    let r = valid(resolve_log(
        &after.log,
        Some(file),
        ResolveOptions::default(),
    ));
    assert_eq!(r.error.unwrap().code, ErrorCode::EntryAfterDeactivation);
}

#[test]
fn copies_detect_forks() {
    let key = signer(1);
    let created = create_log(
        json!({}),
        params(json!({"updateKeys": [key.multikey()]})),
        "2026-01-01T00:00:00Z",
        std::slice::from_ref(&key),
    );
    let a = update_log(
        &created.log,
        json!({"v": "a"}),
        Map::new(),
        "2026-01-02T00:00:00Z",
        std::slice::from_ref(&key),
    )
    .unwrap();
    let b = update_log(
        &created.log,
        json!({"v": "b"}),
        Map::new(),
        "2026-01-02T00:00:00Z",
        &[key],
    )
    .unwrap();
    let input = |copy_log: &str| ResolveInput {
        log: a.log.clone(),
        now: NOW.into(),
        copies: Some(vec![CopyInput::Available {
            source: "https://w.example".into(),
            log: copy_log.into(),
            witness: None,
        }]),
        ..ResolveInput::default()
    };
    let r = valid(resolve(&input(&created.log)));
    let copies = r.metadata.copies.unwrap();
    assert_eq!(copies[1].status, CopyStatus::Behind);
    let e = invalid(resolve(&input(&b.log)));
    assert_eq!(e.code, ErrorCode::ForkDetected);
    assert_eq!(e.fork.unwrap().version, 2);
}

#[test]
fn invalid_options() {
    let e = invalid(resolve_log(
        "",
        None,
        ResolveOptions {
            version_number: Some(1),
            version_id: Some("1-x".into()),
            ..ResolveOptions::default()
        },
    ));
    assert_eq!(e.code, ErrorCode::InvalidOption);
    let e = ResolveOptions::from_json(&json!({"bogus": 1})).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidOption);
    assert_eq!(
        ResolveOptions::from_json(&json!({"versionNumber": 2.0}))
            .unwrap()
            .version_number,
        Some(2)
    );
    let e = invalid(resolve_log("", None, ResolveOptions::default()));
    assert_eq!(e.code, ErrorCode::InvalidLog);
}
