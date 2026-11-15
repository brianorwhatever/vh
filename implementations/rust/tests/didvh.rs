//! did:vh library tests: every did:vh vector, and the specialisation hook
//! keeping VH-Log and did:vh logs apart.

use serde_json::{Map, Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use vh_log::didvh::{self, DidVhError, ResolverContext};
use vh_log::*;

const NOW: &str = "2026-06-01T00:00:00Z";

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/didvh")
}

fn load(path: impl AsRef<Path>) -> Value {
    serde_json::from_str(&fs::read_to_string(vectors().join(path)).unwrap()).unwrap()
}

fn same(a: &Value, b: &Value) -> bool {
    canonicalize(a) == canonicalize(b)
}

fn signer() -> Signer {
    Signer::from_seed_hex(&"11".repeat(32)).unwrap()
}

fn update_keys() -> Map<String, Value> {
    let mut params = Map::new();
    params.insert("updateKeys".into(), json!([signer().multikey()]));
    params
}

#[test]
fn resolution_vectors() {
    let mut files: Vec<_> = fs::read_dir(vectors().join("resolution"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    for file in files {
        let cases = load(&file);
        for c in cases["cases"].as_array().unwrap() {
            let (name, input, expect) = (&c["name"], &c["input"], &c["expect"]);
            let context = ResolverContext {
                now: input["now"].as_str().map(String::from),
                remote: input["remote"].as_bool().unwrap_or(false),
            };
            let got =
                didvh::resolve_did(input["did"].as_str().unwrap(), &input["options"], &context)
                    .to_json();
            let meta = &got["didResolutionMetadata"];
            if let Some(error) = expect.get("error") {
                assert_eq!(&meta["error"], error, "{name}");
                if let Some(code) = expect.get("vhLogError") {
                    assert_eq!(&meta["problemDetails"]["vhLog"]["code"], code, "{name}");
                }
                assert!(got["didDocument"].is_null(), "{name}");
            } else {
                assert!(meta.get("error").is_none(), "{name}: {meta}");
                assert!(same(&got["didDocument"], &expect["didDocument"]), "{name}");
                assert!(
                    same(&got["didDocumentMetadata"], &expect["didDocumentMetadata"]),
                    "{name}: {got}"
                );
                for key in ["didLog", "didWitness"] {
                    let want = expect.get(key).unwrap_or(&Value::Null);
                    assert!(
                        same(meta.get(key).unwrap_or(&Value::Null), want),
                        "{name}: {key}"
                    );
                }
            }
        }
    }
}

fn outcome(result: Result<Value, DidVhError>) -> Value {
    result.unwrap_or_else(|e| json!({ "valid": false, "error": e.code }))
}

#[test]
fn reference_src_and_did_url_vectors() {
    for c in load("ref.json")["cases"].as_array().unwrap() {
        let got = match c["ref"].as_str() {
            Some(r) => {
                outcome(didvh::check_ref(r).map(|kind| json!({ "valid": true, "kind": kind })))
            }
            None => json!({ "valid": false, "error": "invalidOptions" }),
        };
        assert!(same(&got, &c["expect"]), "{}: {got}", c["name"]);
    }
    for c in load("src.json")["cases"].as_array().unwrap() {
        let src = c["src"].as_str().unwrap();
        let got =
            outcome(didvh::src_references(src).map(
                |r| json!({ "valid": true, "srcLog": r.src_log, "srcWitness": r.src_witness }),
            ));
        assert!(same(&got, &c["expect"]), "{}: {got}", c["name"]);
    }
    for c in load("did-url.json")["cases"].as_array().unwrap() {
        let got = match c["didUrl"].as_str() {
            Some(url) => outcome(didvh::parse_did_url(url).map(|u| {
                let mut out = json!({ "valid": true, "did": u.did, "options": u.options });
                if let Some(f) = u.fragment {
                    out["fragment"] = json!(f);
                }
                out
            })),
            None => json!({ "valid": false, "error": "invalidDidUrl" }),
        };
        assert!(same(&got, &c["expect"]), "{}: {got}", c["name"]);
    }
}

#[test]
fn create_update_and_resolve() {
    let document = json!({ "id": "did:vh:{SCID}", "controller": "did:vh:{SCID}" });
    let created = didvh::create_did(document, update_keys(), "2026-01-01T00:00:00Z", &[signer()]);
    assert_eq!(didvh::parse_did(&created.did), Some(created.scid.as_str()));
    let line: Value = serde_json::from_str(&created.log).unwrap();
    assert_eq!(line["parameters"]["method"], "did:vh:1.0");
    assert!(line["parameters"].get("logVersion").is_none());
    assert_eq!(line["state"]["controller"], json!(created.did));

    let updated = didvh::update_did(
        &created.log,
        json!({ "id": created.did, "v": 2 }),
        Map::new(),
        "2026-01-02T00:00:00Z",
        &[signer()],
    )
    .unwrap();
    let context = ResolverContext {
        now: Some(NOW.into()),
        remote: false,
    };
    let r = didvh::resolve_did(&created.did, &json!({ "didLog": updated.log }), &context);
    assert_eq!(r.did_document, Some(json!({ "id": created.did, "v": 2 })));
    assert_eq!(
        r.did_document_metadata.unwrap().version_id,
        updated.version_id
    );
}

#[test]
fn vh_log_and_did_vh_logs_are_not_interchangeable() {
    let context = ResolverContext {
        now: Some(NOW.into()),
        remote: false,
    };
    let vh = create_log(
        json!({ "id": "did:vh:{SCID}" }),
        update_keys(),
        "2026-01-01T00:00:00Z",
        &[signer()],
    );
    let as_did = didvh::resolve_did(
        &format!("did:vh:{}", vh.scid),
        &json!({ "didLog": vh.log }),
        &context,
    );
    assert_eq!(as_did.error(), Some(didvh::DidVhErrorCode::InvalidDid));

    let did = didvh::create_did(
        json!({ "id": "did:vh:{SCID}" }),
        update_keys(),
        "2026-01-01T00:00:00Z",
        &[signer()],
    );
    let as_log = resolve(&ResolveInput {
        log: did.log,
        now: NOW.into(),
        ..ResolveInput::default()
    });
    match as_log {
        ResolveResult::Invalid(e) => assert_eq!(e.code, ErrorCode::UnsupportedLogVersion),
        ResolveResult::Valid(_) => panic!("a did:vh log must not verify as VH-Log"),
    }
}
