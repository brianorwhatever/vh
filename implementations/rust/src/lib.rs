//! VH-Log (Verifiable History Log): a Rust implementation of the
//! `vh-log-interop-0` profile.
//!
//! - [`create_log`], [`update_log`] and [`witness_proof`] are the Log Controller operations.
//! - [`verify_log`] runs every per-entry and witness check on a log file.
//! - [`resolve`] selects a version, handles partial validity and compares copies.
//! - [`jcs`], [`encoding`], [`hash`] and [`proof`] expose the primitives.
//!
//! ```
//! use serde_json::{json, Map};
//! use vh_log::{create_log, resolve, update_log, ResolveInput, ResolveResult, Signer};
//!
//! let key = Signer::from_seed_hex(&"01".repeat(32))?;
//! let mut params = Map::new();
//! params.insert("updateKeys".into(), json!([key.multikey()]));
//!
//! let created = create_log(json!({"id": "example:{SCID}"}), params, "2026-01-01T00:00:00Z", &[key.clone()]);
//! let updated = update_log(
//!     &created.log,
//!     json!({"id": format!("example:{}", created.scid), "name": "updated"}),
//!     Map::new(), // no parameter changes; use {"deactivated": true} to deactivate
//!     "2026-01-02T00:00:00Z",
//!     &[key],
//! )?;
//!
//! let result = resolve(&ResolveInput {
//!     log: updated.log,
//!     now: "2026-06-01T00:00:00Z".into(),
//!     ..ResolveInput::default()
//! });
//! match result {
//!     ResolveResult::Valid(r) => println!("{:?} {}", r.state, r.metadata.version_id),
//!     ResolveResult::Invalid(e) => eprintln!("{} {}", e.code, e.message),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod encoding;
pub mod error;
pub mod hash;
pub mod jcs;
pub mod log;
pub mod proof;
pub mod resolve;
pub mod verify;

pub use encoding::{
    base58btc_decode, base58btc_encode, multikey_from_public_key, public_key_from_multikey,
};
pub use error::{ErrorCode, ForkCopy, ForkReport, GenerateError, VhLogError};
pub use hash::{MultihashCheck, check_sha256_multihash, hash_b58, key_hash};
pub use jcs::canonicalize;
pub use log::{
    CreatedLog, LOG_VERSION, SCID_PLACEHOLDER, UpdatedLog, compute_entry_hash, compute_scid,
    create_log, parse_log_lines, serialize_entry, update_log, witness_proof,
};
pub use proof::{Proof, ProofOptions, Signer, create_proof, verify_proof};
pub use resolve::{
    CopyInput, CopyReport, CopyStatus, Resolution, ResolutionMetadata, ResolveInput,
    ResolveOptions, ResolveResult, Warning, WarningCode, resolve,
};
pub use verify::{
    LogEntry, Parameters, VerifiedEntry, VerifiedLog, Witness, WitnessConfig, parse_version_time,
    verify_log,
};
