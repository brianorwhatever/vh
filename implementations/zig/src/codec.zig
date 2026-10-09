//! base58btc, multihash, multikey and hex helpers (profile §1).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const decode_map: [256]i8 = blk: {
    var m: [256]i8 = @splat(-1);
    for (alphabet, 0..) |c, i| m[c] = @intCast(i);
    break :blk m;
};

/// Bitcoin-alphabet base58 without a multibase prefix. Caller owns the result.
pub fn base58Encode(allocator: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) zeros += 1;
    // log(256)/log(58) ≈ 1.366
    const cap = (bytes.len - zeros) * 138 / 100 + 1;
    const digits = try allocator.alloc(u8, cap);
    defer allocator.free(digits);
    @memset(digits, 0);
    var len: usize = 0;
    for (bytes[zeros..]) |b| {
        var carry: u32 = b;
        var j: usize = 0;
        while (j < len or carry != 0) : (j += 1) {
            carry += @as(u32, digits[j]) << 8;
            digits[j] = @intCast(carry % 58);
            carry /= 58;
        }
        len = j;
    }
    const out = try allocator.alloc(u8, zeros + len);
    @memset(out[0..zeros], '1');
    for (0..len) |i| out[zeros + i] = alphabet[digits[len - 1 - i]];
    return out;
}

pub const DecodeError = error{InvalidBase58} || Allocator.Error;

/// Decodes base58btc. Caller owns the result.
pub fn base58Decode(allocator: Allocator, s: []const u8) DecodeError![]u8 {
    var zeros: usize = 0;
    while (zeros < s.len and s[zeros] == '1') zeros += 1;
    const cap = (s.len - zeros) * 733 / 1000 + 1;
    const bytes = try allocator.alloc(u8, cap);
    defer allocator.free(bytes);
    @memset(bytes, 0);
    var len: usize = 0;
    for (s[zeros..]) |c| {
        const d = decode_map[c];
        if (d < 0) return error.InvalidBase58;
        var carry: u32 = @intCast(d);
        var j: usize = 0;
        while (j < len or carry != 0) : (j += 1) {
            carry += @as(u32, bytes[j]) * 58;
            bytes[j] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        len = j;
    }
    const out = try allocator.alloc(u8, zeros + len);
    @memset(out[0..zeros], 0);
    for (0..len) |i| out[zeros + i] = bytes[len - 1 - i];
    return out;
}

pub const sha256_code = 0x12;

/// `0x12 0x20 ‖ SHA-256(data)`.
pub fn sha256Multihash(data: []const u8) [34]u8 {
    var out: [34]u8 = undefined;
    out[0] = sha256_code;
    out[1] = 32;
    Sha256.hash(data, out[2..34], .{});
    return out;
}

/// `base58btc(multihash(data))` — the SCID / entry hash / key hash function.
pub fn hashString(allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
    const mh = sha256Multihash(data);
    return base58Encode(allocator, &mh);
}

pub const MultihashKind = enum {
    /// A well-formed SHA-256 multihash (34 bytes).
    sha256,
    /// Valid base58 that is not a SHA-256 multihash (another algorithm, a wrong
    /// length, or not a multihash at all).
    other,
    /// Not base58btc.
    not_base58,
};

/// Classifies a base58btc-encoded multihash string.
pub fn classifyMultihash(allocator: Allocator, s: []const u8) Allocator.Error!MultihashKind {
    if (s.len == 0) return .other;
    const bytes = base58Decode(allocator, s) catch |err| switch (err) {
        error.InvalidBase58 => return .not_base58,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(bytes);
    if (bytes.len == 34 and bytes[0] == sha256_code and bytes[1] == 32) return .sha256;
    return .other;
}

pub const multikey_prefix = [2]u8{ 0xed, 0x01 };

/// `"z" + base58btc(0xed 0x01 ‖ pubkey)`. Caller owns the result.
pub fn encodeMultikey(allocator: Allocator, public_key: [32]u8) Allocator.Error![]u8 {
    var raw: [34]u8 = undefined;
    raw[0..2].* = multikey_prefix;
    raw[2..].* = public_key;
    const b = try base58Encode(allocator, &raw);
    defer allocator.free(b);
    const out = try allocator.alloc(u8, b.len + 1);
    out[0] = 'z';
    @memcpy(out[1..], b);
    return out;
}

/// Decodes an Ed25519 multikey to its 32-byte public key, or null if `s` is
/// not one.
pub fn decodeMultikey(allocator: Allocator, s: []const u8) Allocator.Error!?[32]u8 {
    if (s.len < 2 or s[0] != 'z') return null;
    const bytes = base58Decode(allocator, s[1..]) catch |err| switch (err) {
        error.InvalidBase58 => return null,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(bytes);
    if (bytes.len != 34 or bytes[0] != 0xed or bytes[1] != 0x01) return null;
    return bytes[2..34].*;
}

/// Parses a 32-byte hex seed.
pub fn parseSeed(hex: []const u8) error{InvalidSeed}![32]u8 {
    var out: [32]u8 = undefined;
    if (hex.len != 64) return error.InvalidSeed;
    _ = std.fmt.hexToBytes(&out, hex) catch return error.InvalidSeed;
    return out;
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "base58 round trip" {
    const a = testing.allocator;
    const cases = [_][]const u8{ "", "\x00", "\x00\x00\x01", "hello world", "\xff\xfe" };
    for (cases) |c| {
        const e = try base58Encode(a, c);
        defer a.free(e);
        const d = try base58Decode(a, e);
        defer a.free(d);
        try testing.expectEqualSlices(u8, c, d);
    }
    const e = try base58Encode(a, "hello world");
    defer a.free(e);
    try testing.expectEqualStrings("StV1DL6CwTryKyV", e);
    try testing.expectError(error.InvalidBase58, base58Decode(a, "0OIl"));
}

test "hash strings start with Qm" {
    const a = testing.allocator;
    const h = try hashString(a, "abc");
    defer a.free(h);
    try testing.expectEqualStrings("QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY", h);
    try testing.expectEqual(MultihashKind.sha256, try classifyMultihash(a, h));
    try testing.expectEqual(MultihashKind.not_base58, try classifyMultihash(a, "Qm0"));
    try testing.expectEqual(MultihashKind.other, try classifyMultihash(a, "QmUnknown"));
}

test "multikey" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0)));
    const mk = try encodeMultikey(a, kp.public_key.toBytes());
    defer a.free(mk);
    try testing.expectEqualStrings("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", mk);
    const pk = (try decodeMultikey(a, mk)).?;
    try testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &pk);
    try testing.expect((try decodeMultikey(a, "z6Mk")) == null);
    try testing.expect((try decodeMultikey(a, "QmatYkNGZnELf8cAGdyJpUca2PyY4szai3RHyyWofNY1pY")) == null);
}
