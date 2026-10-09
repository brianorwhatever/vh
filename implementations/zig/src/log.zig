//! Log Controller operations and the hash functions they share with the
//! resolver: SCID, entry hash, create, update and witness proofs.

const std = @import("std");
const json = @import("json.zig");
const codec = @import("codec.zig");
const proof = @import("proof.zig");
const Allocator = std.mem.Allocator;
const Value = json.Value;
const Member = json.Member;

pub const scid_placeholder = "{SCID}";
pub const log_version = "vh-log:1.0";

pub const Error = error{ InvalidLog, InvalidSeed, SigningFailed } || json.ParseError || json.StringifyError;

/// `base58btc(multihash(JCS(entry)))`. Caller owns the result.
pub fn hashValue(allocator: Allocator, v: Value) json.StringifyError![]u8 {
    const c = try json.canonicalize(allocator, v);
    defer allocator.free(c);
    return codec.hashString(allocator, c);
}

/// SCID of a preliminary entry that still has `{SCID}` placeholders.
pub fn scid(allocator: Allocator, preliminary: Value) json.StringifyError![]u8 {
    return hashValue(allocator, preliminary);
}

/// Entry hash: the entry without `proof`, with `versionId` set to the
/// predecessor's versionId (the SCID for entry 1). Caller owns the result.
pub fn entryHash(allocator: Allocator, entry: Value, previous_version_id: []const u8) json.StringifyError![]u8 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try json.with(a, try json.without(a, entry, "proof"), "versionId", .{ .string = previous_version_id });
    return hashValue(allocator, doc);
}

/// Replaces every occurrence of `needle` by `replacement` in `text`.
pub fn replaceAll(allocator: Allocator, text: []const u8, needle: []const u8, replacement: []const u8) Allocator.Error![]u8 {
    return std.mem.replaceOwned(u8, allocator, text, needle, replacement);
}

/// Recomputes the SCID of a published first entry (spec *Verify SCID*):
/// drop `proof`, set `versionId` to "{SCID}", textually replace the SCID by
/// "{SCID}" in the serialised entry, and hash the result. Caller owns it.
pub fn recomputeScid(allocator: Allocator, entry: Value, the_scid: []const u8) Error![]u8 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try json.with(a, try json.without(a, entry, "proof"), "versionId", .{ .string = scid_placeholder });
    const text = try json.stringify(a, doc);
    const replaced = try replaceAll(a, text, the_scid, scid_placeholder);
    const reparsed = json.parse(a, replaced) catch return error.InvalidLog;
    return hashValue(allocator, reparsed.value);
}

pub const CreateInput = struct {
    state: Value,
    parameters: Value,
    version_time: []const u8,
    signers: []const [32]u8,
};

pub const Created = struct {
    arena: *std.heap.ArenaAllocator,
    /// The log file: one compact JSON line terminated by "\n".
    log: []const u8,
    scid: []const u8,
    version_id: []const u8,
    entry: Value,

    pub fn deinit(self: Created) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

fn newArena(gpa: Allocator) Allocator.Error!*std.heap.ArenaAllocator {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = .init(gpa);
    return arena;
}

fn freeArena(arena: *std.heap.ArenaAllocator) void {
    const gpa = arena.child_allocator;
    arena.deinit();
    gpa.destroy(arena);
}

fn addProofs(a: Allocator, doc: Value, version_time_in: []const u8, signers: []const [32]u8) Error!Value {
    const version_time = try a.dupe(u8, version_time_in);
    const proofs = try a.alloc(Value, signers.len);
    for (signers, proofs) |seed, *p| {
        p.* = try proof.create(a, doc, seed, .{ .created = version_time });
    }
    return json.with(a, doc, "proof", .{ .array = proofs });
}

fn line(a: Allocator, entry: Value) Error![]u8 {
    const text = try json.stringify(a, entry);
    return std.mem.concat(a, u8, &.{ text, "\n" });
}

/// Creates a new log (spec *Create*, profile §5). Generators don't validate
/// semantics: `parameters` is used as given, with `scid` ("{SCID}") and
/// `logVersion` added if absent.
pub fn create(gpa: Allocator, input: CreateInput) Error!Created {
    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const a = arena.allocator();

    if (input.parameters != .object) return error.InvalidLog;
    var params = input.parameters;
    if (params.get("logVersion") == null) params = try json.with(a, params, "logVersion", .{ .string = log_version });
    if (params.get("scid") == null) params = try json.with(a, params, "scid", .{ .string = scid_placeholder });

    var members: std.ArrayList(Member) = .empty;
    try members.append(a, .{ .key = "versionId", .value = .{ .string = scid_placeholder } });
    try members.append(a, .{ .key = "versionTime", .value = .{ .string = try a.dupe(u8, input.version_time) } });
    try members.append(a, .{ .key = "parameters", .value = params });
    try members.append(a, .{ .key = "state", .value = input.state });
    const preliminary: Value = .{ .object = members.items };

    const the_scid = try scid(a, preliminary);
    const text = try json.stringify(a, preliminary);
    const replaced = try replaceAll(a, text, scid_placeholder, the_scid);
    const entry = (try json.parse(a, replaced)).value;
    // After replacement, versionId holds the SCID: exactly the entry-hash input.
    const hash = try hashValue(a, entry);
    const version_id = try std.mem.concat(a, u8, &.{ "1-", hash });
    const sealed = try json.with(a, entry, "versionId", .{ .string = version_id });
    const signed = try addProofs(a, sealed, input.version_time, input.signers);
    return .{
        .arena = arena,
        .log = try line(a, signed),
        .scid = the_scid,
        .version_id = version_id,
        .entry = signed,
    };
}

pub const UpdateInput = struct {
    state: Value,
    parameters: Value,
    version_time: []const u8,
    signers: []const [32]u8,
};

pub const Updated = struct {
    arena: *std.heap.ArenaAllocator,
    log: []const u8,
    version_id: []const u8,
    entry: Value,

    pub fn deinit(self: Updated) void {
        freeArena(self.arena);
    }
};

/// The last non-empty line of a JSON Lines text.
pub fn lastLine(log_text: []const u8) ?[]const u8 {
    var end = log_text.len;
    while (end > 0 and log_text[end - 1] == '\n') end -= 1;
    if (end == 0) return null;
    const start = if (std.mem.lastIndexOfScalar(u8, log_text[0..end], '\n')) |i| i + 1 else 0;
    return log_text[start..end];
}

/// Parses the version number of a `versionId` ("<n>-<hash>").
pub fn versionNumber(version_id: []const u8) ?u64 {
    const dash = std.mem.indexOfScalar(u8, version_id, '-') orelse return null;
    if (dash == 0) return null;
    return std.fmt.parseInt(u64, version_id[0..dash], 10) catch null;
}

/// Appends an entry to `log_text` (spec *Update*), chaining from its last line.
pub fn update(gpa: Allocator, log_text: []const u8, input: UpdateInput) Error!Updated {
    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const a = arena.allocator();

    const last_text = try a.dupe(u8, lastLine(log_text) orelse return error.InvalidLog);
    const last = json.parse(a, last_text) catch return error.InvalidLog;
    const previous = last.value.getString("versionId") orelse return error.InvalidLog;
    const n = versionNumber(previous) orelse return error.InvalidLog;

    var members: std.ArrayList(Member) = .empty;
    try members.append(a, .{ .key = "versionId", .value = .{ .string = previous } });
    try members.append(a, .{ .key = "versionTime", .value = .{ .string = try a.dupe(u8, input.version_time) } });
    try members.append(a, .{ .key = "parameters", .value = try json.clone(a, input.parameters) });
    try members.append(a, .{ .key = "state", .value = try json.clone(a, input.state) });
    const preliminary: Value = .{ .object = members.items };
    const hash = try hashValue(a, preliminary);
    const version_id = try std.fmt.allocPrint(a, "{d}-{s}", .{ n + 1, hash });
    const sealed = try json.with(a, preliminary, "versionId", .{ .string = version_id });
    const signed = try addProofs(a, sealed, input.version_time, input.signers);

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, log_text);
    if (log_text.len > 0 and log_text[log_text.len - 1] != '\n') try out.append(a, '\n');
    try out.appendSlice(a, try line(a, signed));
    return .{ .arena = arena, .log = out.items, .version_id = version_id, .entry = signed };
}

pub const OwnedValue = struct {
    arena: *std.heap.ArenaAllocator,
    value: Value,

    pub fn deinit(self: OwnedValue) void {
        freeArena(self.arena);
    }
};

/// A witness proof (profile §3): eddsa-jcs-2022 over `{"versionId": …}`.
pub fn witnessProof(gpa: Allocator, version_id: []const u8, seed: [32]u8, created: ?[]const u8) Error!OwnedValue {
    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const a = arena.allocator();
    const members = try a.alloc(Member, 1);
    members[0] = .{ .key = "versionId", .value = .{ .string = try a.dupe(u8, version_id) } };
    const p = try proof.create(a, .{ .object = members }, seed, .{ .created = created });
    return .{ .arena = arena, .value = p };
}
