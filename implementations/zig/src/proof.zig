//! Data Integrity proofs with the `eddsa-jcs-2022` cryptosuite (profile §2).
//!
//! Signing input: SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document)), where
//! proofConfig is the proof without `proofValue`. Neither document nor proof
//! carries `@context`.

const std = @import("std");
const json = @import("json.zig");
const codec = @import("codec.zig");
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Value = json.Value;
const Member = json.Member;

pub const proof_type = "DataIntegrityProof";
pub const cryptosuite = "eddsa-jcs-2022";
pub const proof_purpose = "assertionMethod";

pub const SignOptions = struct {
    /// Defaults to `did:key:<mk>#<mk>`.
    verification_method: ?[]const u8 = null,
    /// Omitted when null.
    created: ?[]const u8 = null,
};

pub const Error = error{ InvalidSeed, SigningFailed } || json.StringifyError;

fn signingInput(allocator: Allocator, config: Value, document: Value) json.StringifyError![64]u8 {
    var out: [64]u8 = undefined;
    const c = try json.canonicalize(allocator, config);
    defer allocator.free(c);
    Sha256.hash(c, out[0..32], .{});
    const d = try json.canonicalize(allocator, document);
    defer allocator.free(d);
    Sha256.hash(d, out[32..64], .{});
    return out;
}

/// The multikey of the Ed25519 key derived from `seed`. Caller owns the result.
pub fn multikeyFromSeed(allocator: Allocator, seed: [32]u8) (Allocator.Error || error{InvalidSeed})![]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidSeed;
    return codec.encodeMultikey(allocator, kp.public_key.toBytes());
}

/// Creates a proof over `document`. All memory comes from `arena` (the result
/// references strings it allocates there).
pub fn create(arena: Allocator, document: Value, seed: [32]u8, options: SignOptions) Error!Value {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidSeed;
    const vm = options.verification_method orelse blk: {
        const mk = try codec.encodeMultikey(arena, kp.public_key.toBytes());
        break :blk try std.mem.concat(arena, u8, &.{ "did:key:", mk, "#", mk });
    };
    var members: std.ArrayList(Member) = .empty;
    try members.append(arena, .{ .key = "type", .value = .{ .string = proof_type } });
    try members.append(arena, .{ .key = "cryptosuite", .value = .{ .string = cryptosuite } });
    try members.append(arena, .{ .key = "verificationMethod", .value = .{ .string = vm } });
    if (options.created) |c| try members.append(arena, .{ .key = "created", .value = .{ .string = c } });
    try members.append(arena, .{ .key = "proofPurpose", .value = .{ .string = proof_purpose } });
    const config: Value = .{ .object = members.items };
    const input = try signingInput(arena, config, document);
    const sig = kp.sign(&input, null) catch return error.SigningFailed;
    const b58 = try codec.base58Encode(arena, &sig.toBytes());
    const pv = try std.mem.concat(arena, u8, &.{ "z", b58 });
    try members.append(arena, .{ .key = "proofValue", .value = .{ .string = pv } });
    return .{ .object = try members.toOwnedSlice(arena) };
}

/// Splits `did:key:<mk>#<mk>` and returns `<mk>` if both halves are equal.
pub fn didKeyMultikey(vm: []const u8) ?[]const u8 {
    const prefix = "did:key:";
    if (!std.mem.startsWith(u8, vm, prefix)) return null;
    const rest = vm[prefix.len..];
    const hash = std.mem.indexOfScalar(u8, rest, '#') orelse return null;
    const a = rest[0..hash];
    const b = rest[hash + 1 ..];
    if (a.len == 0 or !std.mem.eql(u8, a, b)) return null;
    return a;
}

/// Checks `type`, `cryptosuite`, `proofPurpose`, `proofValue` and the signature
/// of `proof` over `document` with `public_key`. Key authorisation is the
/// caller's job.
pub fn verifyWithKey(allocator: Allocator, document: Value, proof: Value, public_key: [32]u8) Allocator.Error!bool {
    if (proof != .object) return false;
    const t = proof.getString("type") orelse return false;
    if (!std.mem.eql(u8, t, proof_type)) return false;
    const cs = proof.getString("cryptosuite") orelse return false;
    if (!std.mem.eql(u8, cs, cryptosuite)) return false;
    const pp = proof.getString("proofPurpose") orelse return false;
    if (!std.mem.eql(u8, pp, proof_purpose)) return false;
    const pv = proof.getString("proofValue") orelse return false;
    if (pv.len < 2 or pv[0] != 'z') return false;
    const sig_bytes = codec.base58Decode(allocator, pv[1..]) catch |err| switch (err) {
        error.InvalidBase58 => return false,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(sig_bytes);
    if (sig_bytes.len != 64) return false;

    const config = try json.without(allocator, proof, "proofValue");
    defer allocator.free(config.object);
    const input = signingInput(allocator, config, document) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NonFinite => return false,
    };
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes[0..64].*);
    sig.verify(&input, pk) catch return false;
    return true;
}

/// The `verify` primitive: the verificationMethod must be `did:key:<mk>#<mk>`
/// and the signature must verify with `<mk>`. No authorisation check.
pub fn verify(allocator: Allocator, document: Value, proof: Value) Allocator.Error!bool {
    if (proof != .object) return false;
    const vm = proof.getString("verificationMethod") orelse return false;
    const mk = didKeyMultikey(vm) orelse return false;
    const pk = (try codec.decodeMultikey(allocator, mk)) orelse return false;
    return verifyWithKey(allocator, document, proof, pk);
}

test "sign and verify" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = (try json.parse(a, "{\"versionId\":\"1-QmExample\",\"hello\":\"world\"}")).value;
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa");
    const p = try create(a, doc, seed, .{ .created = "2026-01-01T00:00:00Z" });
    try std.testing.expectEqualStrings(
        "z528XY5PUhkrXjtbAWHryp8yhKWfPaBEDfQT3SMStNwMSZsDw1au8YWBxoqCGzgoFxhQg2JG7PdT8HnTHyJygSca3",
        p.getString("proofValue").?,
    );
    try std.testing.expect(try verify(a, doc, p));
    const tampered = try json.with(a, doc, "extra", .{ .number = 1 });
    try std.testing.expect(!try verify(a, tampered, p));
    try std.testing.expect(didKeyMultikey("did:key:z6Mkx#z6Mky") == null);
    try std.testing.expect(didKeyMultikey("did:web:x#x") == null);
}
