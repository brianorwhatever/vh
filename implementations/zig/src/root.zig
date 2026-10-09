//! VH-Log (Verifiable History Log) for Zig, following the
//! `vh-log-interop-0` profile.
//!
//! Every function takes an explicit allocator. Results that own memory have a
//! `deinit` method.

const std = @import("std");

pub const json = @import("json.zig");
pub const numfmt = @import("numfmt.zig");
pub const codec = @import("codec.zig");
pub const proof = @import("proof.zig");
pub const time = @import("time.zig");
pub const log = @import("log.zig");
pub const resolver = @import("resolve.zig");
pub const ops = @import("ops.zig");

pub const Value = json.Value;
pub const Member = json.Member;
pub const ErrorCode = resolver.ErrorCode;

// JSON / JCS
pub const parseJson = json.parseOwned;
pub const canonicalize = json.canonicalize;
pub const canonicalizeText = json.canonicalizeText;

// Encodings
pub const base58Encode = codec.base58Encode;
pub const base58Decode = codec.base58Decode;
pub const sha256Multihash = codec.sha256Multihash;
pub const hashString = codec.hashString;
pub const encodeMultikey = codec.encodeMultikey;
pub const decodeMultikey = codec.decodeMultikey;
pub const multikeyFromSeed = proof.multikeyFromSeed;

/// Pre-rotation key hash: `base58btc(multihash(utf8(multikey)))`.
pub fn keyHash(allocator: std.mem.Allocator, multikey: []const u8) std.mem.Allocator.Error![]u8 {
    return codec.hashString(allocator, multikey);
}

// eddsa-jcs-2022
pub const createProof = proof.create;
pub const verifyProof = proof.verify;
pub const SignOptions = proof.SignOptions;

// Hashes
pub const scid = log.scid;
pub const entryHash = log.entryHash;

// Log Controller
pub const createLog = log.create;
pub const updateLog = log.update;
pub const witnessProof = log.witnessProof;
pub const CreateInput = log.CreateInput;
pub const UpdateInput = log.UpdateInput;

// Resolver
/// Verifies every entry and the witnesses; the result owns its memory.
pub const verifyLog = resolver.verifyOwned;
pub const Verification = resolver.Verification;
pub const resolve = resolver.resolve;
pub const ResolveRequest = resolver.Request;
pub const ResolveOptions = resolver.Options;
pub const Resolution = resolver.Resolution;
pub const CopyInput = resolver.CopyInput;
pub const WitnessInput = resolver.WitnessInput;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
