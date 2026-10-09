//! Runs the shared vectors in `../../vectors` against the library directly.

use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use vh_log::*;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn load(path: impl AsRef<Path>) -> Value {
    serde_json::from_str(&fs::read_to_string(vectors().join(path)).unwrap()).unwrap()
}

fn same(a: &Value, b: &Value) -> bool {
    canonicalize(a) == canonicalize(b)
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}

#[test]
fn primitive_vectors() {
    let v = load("primitives.json");
    for c in v["jcs"].as_array().unwrap() {
        assert_eq!(
            jcs::canonicalize_str(str_of(c, "text")).unwrap(),
            str_of(c, "output")
        );
    }
    for c in v["hash"].as_array().unwrap() {
        assert_eq!(hash_b58(str_of(c, "data").as_bytes()), str_of(c, "output"));
    }
    for c in v["multikey"].as_array().unwrap() {
        let signer = Signer::from_seed_hex(str_of(c, "seed")).unwrap();
        assert_eq!(signer.multikey(), str_of(c, "multikey"));
    }
    for c in v["keyHash"].as_array().unwrap() {
        assert_eq!(key_hash(str_of(c, "multikey")), str_of(c, "output"));
    }
    for c in v["scid"].as_array().unwrap() {
        assert_eq!(
            compute_scid(c["entry"].as_object().unwrap()),
            str_of(c, "scid")
        );
    }
    for c in v["entryHash"].as_array().unwrap() {
        let hash = compute_entry_hash(
            c["entry"].as_object().unwrap(),
            str_of(c, "previousVersionId"),
        );
        assert_eq!(hash, str_of(c, "hash"));
    }
    for c in v["sign"].as_array().unwrap() {
        let signer = Signer::from_seed_hex(str_of(c, "seed")).unwrap();
        let options = ProofOptions {
            created: c.get("created").and_then(Value::as_str).map(String::from),
            ..ProofOptions::default()
        };
        let proof = create_proof(&c["document"], &signer, &options);
        assert!(same(&proof.to_value(), &c["proof"]));
        assert!(verify_proof(&c["document"], &c["proof"]));
        let mut tampered = c["document"].as_object().unwrap().clone();
        tampered.insert("extra".into(), Value::from(1));
        assert!(!verify_proof(&Value::Object(tampered), &c["proof"]));
    }
}

#[test]
fn generation_vectors() {
    let v = load("generation.json");
    for sc in v["scenarios"].as_array().unwrap() {
        let mut log = String::new();
        let mut scid = String::new();
        let mut version_ids = Vec::new();
        for step in sc["steps"].as_array().unwrap() {
            let input = if step["op"] == "create" {
                step["input"].clone()
            } else {
                let text = serde_json::to_string(&step["input"])
                    .unwrap()
                    .replace("{SCID}", &scid);
                serde_json::from_str(&text).unwrap()
            };
            let signers: Vec<Signer> = input["signers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| Signer::from_seed_hex(s.as_str().unwrap()).unwrap())
                .collect();
            let parameters = input
                .get("parameters")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let version_id = if step["op"] == "create" {
                let created = create_log(
                    input["state"].clone(),
                    parameters,
                    str_of(&input, "versionTime"),
                    &signers,
                );
                assert_eq!(created.scid, str_of(&step["expect"], "scid"));
                scid = created.scid;
                log = created.log;
                created.version_id
            } else {
                let updated = update_log(
                    &log,
                    input["state"].clone(),
                    parameters,
                    str_of(&input, "versionTime"),
                    &signers,
                )
                .unwrap();
                log = updated.log;
                updated.version_id
            };
            assert_eq!(
                version_id,
                str_of(&step["expect"], "versionId"),
                "{}",
                sc["name"]
            );
            let line: Value = serde_json::from_str(parse_log_lines(&log).last().unwrap()).unwrap();
            assert!(same(&line, &step["expect"]["line"]), "{}", sc["name"]);
            version_ids.push(version_id);
        }
        let witness_file = sc.get("witness").and_then(Value::as_array).map(|items| {
            Value::Array(
                items
                    .iter()
                    .map(|w| {
                        let version_id = &version_ids[w["step"].as_u64().unwrap() as usize - 1];
                        let proofs: Vec<Value> = w["seeds"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|s| {
                                let signer = Signer::from_seed_hex(s.as_str().unwrap()).unwrap();
                                witness_proof(version_id, &signer, None).to_value()
                            })
                            .collect();
                        serde_json::json!({ "versionId": version_id, "proof": proofs })
                    })
                    .collect(),
            )
        });
        if let Some(file) = &witness_file {
            assert!(same(file, &sc["witnessFile"]), "{}", sc["name"]);
        }
        let result = resolve(&ResolveInput {
            log,
            witness: witness_file,
            now: str_of(&sc["resolve"], "now").into(),
            ..ResolveInput::default()
        });
        let ResolveResult::Valid(r) = result else {
            panic!("{} did not resolve: {result:?}", sc["name"]);
        };
        assert!(r.error.is_none());
        assert!(same(&Value::Object(r.state), &sc["resolve"]["state"]));
        assert_eq!(r.metadata.version_id, str_of(&sc["resolve"], "versionId"));
    }
}

fn resolve_input(input: &Value) -> Result<ResolveInput, VhLogError> {
    let copies = input.get("copies").map(|cs| {
        cs.as_array()
            .unwrap()
            .iter()
            .map(|c| match c.get("unavailable") {
                Some(reason) => CopyInput::Unavailable {
                    source: str_of(c, "source").into(),
                    reason: reason.as_str().unwrap().into(),
                },
                None => CopyInput::Available {
                    source: str_of(c, "source").into(),
                    log: str_of(c, "log").into(),
                    witness: c.get("witness").cloned(),
                },
            })
            .collect()
    });
    Ok(ResolveInput {
        log: str_of(input, "log").into(),
        witness: input.get("witness").cloned(),
        now: str_of(input, "now").into(),
        options: ResolveOptions::from_json(input.get("options").unwrap_or(&Value::Null))?,
        copies,
        retained_version_id: input
            .get("retainedVersionId")
            .and_then(Value::as_str)
            .map(String::from),
    })
}

#[test]
fn resolution_vectors() {
    let mut count = 0;
    for file in fs::read_dir(vectors().join("resolution")).unwrap() {
        let path = file.unwrap().path();
        for c in load(&path)["cases"].as_array().unwrap() {
            count += 1;
            let name = format!(
                "{}/{}",
                path.file_stem().unwrap().to_string_lossy(),
                c["name"]
            );
            let expect = &c["expect"];
            let result = match resolve_input(&c["input"]) {
                Ok(input) => resolve(&input),
                Err(e) => ResolveResult::Invalid(e),
            };
            let got = result.to_json();
            assert_eq!(got["valid"], expect["valid"], "{name}: {got}");
            match expect.get("error") {
                Some(Value::Object(err)) => {
                    let codes: Vec<&Value> = match err.get("oneOf") {
                        Some(Value::Array(codes)) => codes.iter().collect(),
                        _ => vec![&err["code"]],
                    };
                    assert!(codes.contains(&&got["error"]["code"]), "{name}: {got}");
                    if let Some(version) = err.get("version") {
                        assert_eq!(&got["error"]["version"], version, "{name}");
                    }
                }
                _ => assert!(got["error"].is_null(), "{name}: {got}"),
            }
            if expect["valid"] == true {
                assert!(same(&got["state"], &expect["state"]), "{name}");
                let fiv = expect
                    .get("firstInvalidVersion")
                    .cloned()
                    .unwrap_or(Value::Null);
                assert_eq!(got["firstInvalidVersion"], fiv, "{name}");
                let mut warnings: Vec<String> = got["metadata"]["warnings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|w| str_of(w, "code").to_string())
                    .collect();
                warnings.sort();
                let want = expect
                    .get("warnings")
                    .cloned()
                    .unwrap_or(Value::Array(vec![]));
                assert!(
                    same(&serde_json::to_value(&warnings).unwrap(), &want),
                    "{name}: {warnings:?}"
                );
                for (k, v) in expect
                    .get("metadata")
                    .and_then(Value::as_object)
                    .unwrap_or(&Map::new())
                {
                    assert!(same(v, &got["metadata"][k]), "{name}: metadata.{k}");
                }
            }
        }
    }
    assert!(count > 100, "only {count} resolution vectors found");
}
