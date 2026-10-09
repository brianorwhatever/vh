//! Log verification and resolution (spec *Read (Resolve)*, profile §3–§4, §6).

const std = @import("std");
const json = @import("json.zig");
const codec = @import("codec.zig");
const proof = @import("proof.zig");
const log = @import("log.zig");
const time = @import("time.zig");
const Allocator = std.mem.Allocator;
const Value = json.Value;
const Member = json.Member;

pub const ErrorCode = enum {
    invalid_log,
    invalid_entry,
    invalid_parameter,
    unsupported_log_version,
    prerotation_violation,
    invalid_proof,
    unauthorized_key,
    invalid_version_id,
    invalid_hash_algorithm,
    entry_hash_mismatch,
    invalid_version_time,
    future_version_time,
    scid_mismatch,
    entry_after_deactivation,
    witness_threshold_not_met,
    invalid_witness_file,
    fork_detected,
    min_copies_not_met,
    not_found,
    invalid_option,

    /// The profile's spelling, e.g. "invalid-log".
    pub fn name(self: ErrorCode) []const u8 {
        return switch (self) {
            inline else => |c| comptime blk: {
                const tag = @tagName(c);
                var out: [tag.len]u8 = undefined;
                for (tag, 0..) |ch, i| out[i] = if (ch == '_') '-' else ch;
                const final = out;
                break :blk &final;
            },
        };
    }
};

/// Future tolerance for versionTime (profile §4).
pub const future_tolerance_seconds = 300;

pub const Failure = struct {
    code: ErrorCode,
    /// 1-based entry number, or null for log-level failures.
    version: ?u64,
    message: []const u8,
};

/// Parameters active after an entry has been processed.
pub const Params = struct {
    update_keys: []const []const u8,
    next_key_hashes: []const []const u8,
    /// Witness configuration object; `{}` means no witnesses.
    witness: Value,
    /// Array of watcher URL strings.
    watchers: Value,
    ttl: f64,
    deactivated: bool,
};

pub const Entry = struct {
    version_id: []const u8,
    version_number: u64,
    version_time: []const u8,
    time: i64,
    state: Value,
    /// Parameters active after this entry (including its own changes).
    params: Params,
    /// The witness list that applies to this entry (`{}` = none needed).
    witness_applies: Value,
};

pub const WitnessInput = union(enum) {
    /// No witness file was found.
    absent,
    /// The witness file's parsed JSON (possibly malformed).
    present: Value,
};

/// A log split into lines, each parsed if possible.
pub const Lines = struct {
    text: []const []const u8,
    values: []?Value,
    /// Why a line didn't parse into a usable object (null if it did).
    problems: []?[]const u8,

    pub fn versionId(self: Lines, i: usize) ?[]const u8 {
        const v = self.values[i] orelse return null;
        return v.getString("versionId");
    }
};

/// Splits on "\n" only. A final terminating newline doesn't start a new line.
pub fn splitLines(a: Allocator, text: []const u8) Allocator.Error!Lines {
    var pieces: std.ArrayList([]const u8) = .empty;
    if (text.len > 0) {
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |p| try pieces.append(a, p);
        if (pieces.items.len > 0 and pieces.items[pieces.items.len - 1].len == 0) _ = pieces.pop();
    }
    const n = pieces.items.len;
    const values = try a.alloc(?Value, n);
    const problems = try a.alloc(?[]const u8, n);
    for (pieces.items, 0..) |p, i| {
        values[i] = null;
        problems[i] = null;
        const r = json.parse(a, p) catch |err| {
            problems[i] = switch (err) {
                error.NumberOverflow => "a number is too large to be a finite double (not I-JSON)",
                error.OutOfMemory => return error.OutOfMemory,
                else => "line is not valid JSON",
            };
            continue;
        };
        if (r.lone_surrogate) {
            problems[i] = "a string contains a lone surrogate (not I-JSON)";
        } else if (r.value != .object) {
            problems[i] = "line is not a JSON object";
        } else values[i] = r.value;
    }
    return .{ .text = pieces.items, .values = values, .problems = problems };
}

pub const Verification = struct {
    lines: Lines,
    /// The valid prefix of the log.
    entries: []Entry,
    /// What invalidated entry `entries.len + 1` (or the whole log); null if
    /// every entry is valid and witnessed.
    failure: ?Failure,
    /// Parsed versionTime of each line (null if unavailable).
    line_times: []?i64,
    /// The SCID from entry 1 (empty if entry 1 is invalid).
    scid: []const u8,

    pub fn fullyValid(self: Verification) bool {
        return self.failure == null and self.entries.len > 0;
    }

    pub fn deactivated(self: Verification) bool {
        for (self.entries) |e| if (e.params.deactivated) return true;
        return false;
    }
};

const Outcome = union(enum) {
    ok: Entry,
    fail: Failure,
};

const Verifier = struct {
    a: Allocator,
    now: i64,
    prev: ?Entry = null,
    scid: []const u8 = "",
    deactivated: bool = false,

    fn failf(v: *Verifier, code: ErrorCode, k: u64, comptime fmt: []const u8, args: anytype) Allocator.Error!Outcome {
        return .{ .fail = .{ .code = code, .version = k, .message = try std.fmt.allocPrint(v.a, fmt, args) } };
    }

    fn processEntry(v: *Verifier, k: u64, entry: Value) Allocator.Error!Outcome {
        const a = v.a;
        // 1. Deactivation.
        if (v.deactivated) return v.failf(.entry_after_deactivation, k, "entry {d} follows a deactivating entry", .{k});

        // 2. Structure.
        const fields = [_]struct { []const u8, std.meta.Tag(Value) }{
            .{ "versionId", .string }, .{ "versionTime", .string }, .{ "parameters", .object },
            .{ "state", .object },     .{ "proof", .array },
        };
        if (entry.object.len != fields.len) return v.failf(.invalid_entry, k, "entry {d} must have exactly the properties versionId, versionTime, parameters, state, proof", .{k});
        for (fields) |f| {
            const val = entry.get(f[0]) orelse return v.failf(.invalid_entry, k, "entry {d} is missing {s}", .{ k, f[0] });
            if (std.meta.activeTag(val) != f[1]) return v.failf(.invalid_entry, k, "entry {d}: {s} has the wrong type", .{ k, f[0] });
        }
        const version_id = entry.getString("versionId").?;
        const version_time = entry.getString("versionTime").?;
        const p = entry.get("parameters").?;
        const proofs = entry.get("proof").?.array;

        // 3. Parameters (including pre-rotation).
        const pr = try v.checkParameters(k, p);
        const params = switch (pr) {
            .fail => |f| return .{ .fail = f },
            .ok => |x| x,
        };

        // 4. Proofs.
        if (proofs.len == 0) return v.failf(.invalid_proof, k, "entry {d} has an empty proof array", .{k});
        const document = try json.without(a, entry, "proof");
        for (proofs, 1..) |pf, j| {
            if (pf != .object) return v.failf(.invalid_proof, k, "entry {d}: proof {d} is not an object", .{ k, j });
            const vm = pf.getString("verificationMethod") orelse
                return v.failf(.invalid_proof, k, "entry {d}: proof {d} has no verificationMethod", .{ k, j });
            const mk = proof.didKeyMultikey(vm) orelse
                return v.failf(.invalid_proof, k, "entry {d}: proof {d} verificationMethod is not did:key:<mk>#<mk>", .{ k, j });
            const authorized = for (params.auth_keys) |key| {
                if (std.mem.eql(u8, key, mk)) break true;
            } else false;
            if (!authorized) return v.failf(.unauthorized_key, k, "entry {d}: proof {d} key {s} is not an active update key", .{ k, j, mk });
            const pk = (try codec.decodeMultikey(a, mk)) orelse
                return v.failf(.invalid_proof, k, "entry {d}: proof {d} key is not an Ed25519 multikey", .{ k, j });
            if (!try proof.verifyWithKey(a, document, pf, pk))
                return v.failf(.invalid_proof, k, "entry {d}: proof {d} is invalid", .{ k, j });
        }

        // 5. versionId.
        const dash = std.mem.indexOfScalar(u8, version_id, '-') orelse
            return v.failf(.invalid_version_id, k, "entry {d}: versionId has no dash", .{k});
        if (std.mem.indexOfScalarPos(u8, version_id, dash + 1, '-') != null)
            return v.failf(.invalid_version_id, k, "entry {d}: versionId has more than one dash", .{k});
        const num_text = version_id[0..dash];
        const hash_text = version_id[dash + 1 ..];
        const num_ok = num_text.len > 0 and num_text[0] != '0' and for (num_text) |c| {
            if (!std.ascii.isDigit(c)) break false;
        } else true;
        const num: ?u64 = if (num_ok) std.fmt.parseInt(u64, num_text, 10) catch null else null;
        if (num == null or num.? != k)
            return v.failf(.invalid_version_id, k, "entry {d}: versionId number must be {d}", .{ k, k });
        if (hash_text.len == 0) return v.failf(.invalid_version_id, k, "entry {d}: versionId has no entry hash", .{k});
        switch (try codec.classifyMultihash(a, hash_text)) {
            .not_base58 => return v.failf(.invalid_version_id, k, "entry {d}: entry hash is not base58btc", .{k}),
            .other => return v.failf(.invalid_hash_algorithm, k, "entry {d}: entry hash is not a SHA-256 multihash", .{k}),
            .sha256 => {},
        }
        const predecessor = if (v.prev) |pe| pe.version_id else params.scid;
        const expected = log.entryHash(a, entry, predecessor) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NonFinite => unreachable,
        };
        if (!std.mem.eql(u8, expected, hash_text))
            return v.failf(.entry_hash_mismatch, k, "entry {d}: entry hash is {s}, expected {s}", .{ k, hash_text, expected });

        // 6. versionTime.
        const t = time.parse(version_time) orelse
            return v.failf(.invalid_version_time, k, "entry {d}: versionTime {s} is not a valid UTC timestamp in whole seconds", .{ k, version_time });
        if (v.prev) |pe| if (t <= pe.time)
            return v.failf(.invalid_version_time, k, "entry {d}: versionTime is not after the previous entry's", .{k});
        if (t > v.now + future_tolerance_seconds)
            return v.failf(.future_version_time, k, "entry {d}: versionTime is in the future", .{k});

        // 7. SCID (entry 1).
        if (k == 1) {
            switch (try codec.classifyMultihash(a, params.scid)) {
                .sha256 => {},
                else => return v.failf(.invalid_hash_algorithm, 1, "the SCID is not a SHA-256 multihash", .{}),
            }
            const recomputed = log.recomputeScid(a, entry, params.scid) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return v.failf(.scid_mismatch, 1, "the SCID could not be recomputed", .{}),
            };
            if (!std.mem.eql(u8, recomputed, params.scid))
                return v.failf(.scid_mismatch, 1, "the SCID is {s}, expected {s}", .{ params.scid, recomputed });
            v.scid = params.scid;
        }

        if (params.params.deactivated) v.deactivated = true;
        return .{ .ok = .{
            .version_id = version_id,
            .version_number = k,
            .version_time = version_time,
            .time = t,
            .state = entry.get("state").?,
            .params = params.params,
            .witness_applies = params.witness_applies,
        } };
    }

    const ParamResult = union(enum) {
        ok: struct {
            params: Params,
            auth_keys: []const []const u8,
            witness_applies: Value,
            scid: []const u8,
        },
        fail: Failure,
    };

    fn pfail(v: *Verifier, code: ErrorCode, k: u64, comptime fmt: []const u8, args: anytype) Allocator.Error!ParamResult {
        return .{ .fail = .{ .code = code, .version = k, .message = try std.fmt.allocPrint(v.a, fmt, args) } };
    }

    fn checkParameters(v: *Verifier, k: u64, p: Value) Allocator.Error!ParamResult {
        const a = v.a;
        const known = [_][]const u8{ "logVersion", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "deactivated", "ttl" };
        for (known) |name| {
            if (p.get(name)) |val| if (val == .null)
                return v.pfail(.invalid_parameter, k, "entry {d}: parameter {s} is null", .{ k, name });
        }

        // logVersion
        if (p.get("logVersion")) |lv| {
            if (lv != .string) return v.pfail(.invalid_parameter, k, "entry {d}: logVersion must be a string", .{k});
            if (!std.mem.eql(u8, lv.string, log.log_version))
                return v.pfail(.unsupported_log_version, k, "entry {d}: unsupported logVersion {s}", .{ k, lv.string });
        } else if (k == 1) return v.pfail(.unsupported_log_version, k, "the first entry has no logVersion", .{});

        // scid
        var the_scid: []const u8 = v.scid;
        if (p.get("scid")) |s| {
            if (k != 1) return v.pfail(.invalid_parameter, k, "entry {d}: scid may only appear in the first entry", .{k});
            if (s != .string) return v.pfail(.invalid_parameter, k, "scid must be a string", .{});
            the_scid = s.string;
        } else if (k == 1) return v.pfail(.invalid_parameter, k, "the first entry has no scid", .{});

        // updateKeys
        var update_keys: ?[]const []const u8 = null;
        if (p.get("updateKeys")) |uk| {
            update_keys = (try stringArray(a, uk, .multikey)) orelse
                return v.pfail(.invalid_parameter, k, "entry {d}: updateKeys must be an array of Ed25519 multikeys", .{k});
        } else if (k == 1) return v.pfail(.invalid_parameter, k, "the first entry has no updateKeys", .{});

        // nextKeyHashes
        var next_key_hashes: ?[]const []const u8 = null;
        if (p.get("nextKeyHashes")) |nk| {
            next_key_hashes = (try stringArray(a, nk, .multihash)) orelse
                return v.pfail(.invalid_parameter, k, "entry {d}: nextKeyHashes must be an array of SHA-256 multihashes", .{k});
        }

        // witness
        if (p.get("witness")) |w| {
            if (try witnessProblem(a, w)) |why| return v.pfail(.invalid_parameter, k, "entry {d}: witness is malformed: {s}", .{ k, why });
        }

        // watchers
        if (p.get("watchers")) |w| {
            const ok = w == .array and for (w.array) |u| {
                if (u != .string or !validWatcherUrl(u.string)) break false;
            } else true;
            if (!ok) return v.pfail(.invalid_parameter, k, "entry {d}: watchers must be an array of http(s) URLs", .{k});
        }

        // deactivated
        if (p.get("deactivated")) |d| {
            if (d != .bool) return v.pfail(.invalid_parameter, k, "entry {d}: deactivated must be a boolean", .{k});
        }

        // ttl
        if (p.get("ttl")) |t| {
            const ok = t == .number and t.number == @floor(t.number) and t.number >= 0 and t.number <= 2147483648.0;
            if (!ok) return v.pfail(.invalid_parameter, k, "entry {d}: ttl must be an integer from 0 to 2^31", .{k});
        }

        // Pre-rotation (spec Read step 7).
        const prev_params: ?Params = if (v.prev) |pe| pe.params else null;
        const prerotation = if (prev_params) |pp| pp.next_key_hashes.len > 0 else false;
        if (prerotation) {
            if (update_keys == null) return v.pfail(.prerotation_violation, k, "entry {d}: pre-rotation is active but updateKeys is not explicit", .{k});
            if (next_key_hashes == null) return v.pfail(.prerotation_violation, k, "entry {d}: pre-rotation is active but nextKeyHashes is not explicit", .{k});
            for (update_keys.?) |key| {
                const h = try codec.hashString(a, key);
                const committed = for (prev_params.?.next_key_hashes) |c| {
                    if (std.mem.eql(u8, c, h)) break true;
                } else false;
                if (!committed) return v.pfail(.prerotation_violation, k, "entry {d}: key {s} was not committed in the previous nextKeyHashes", .{ k, key });
            }
        }

        const empty_obj: Value = .{ .object = &.{} };
        const empty_arr: Value = .{ .array = &.{} };
        const base: Params = prev_params orelse .{
            .update_keys = &.{},
            .next_key_hashes = &.{},
            .witness = empty_obj,
            .watchers = empty_arr,
            .ttl = 3600,
            .deactivated = false,
        };
        var next = base;
        next.deactivated = false;
        if (update_keys) |uk| next.update_keys = uk;
        if (next_key_hashes) |nk| next.next_key_hashes = nk;
        if (p.get("witness")) |w| next.witness = w;
        if (p.get("watchers")) |w| next.watchers = w;
        if (p.get("ttl")) |t| next.ttl = t.number;
        if (p.get("deactivated")) |d| next.deactivated = d.bool;

        // Active update keys for this entry's proofs.
        const auth_keys = if (k == 1 or prerotation) next.update_keys else base.update_keys;

        // The witness list that applies to this entry (profile §3).
        const before = base.witness;
        const witness_applies = if (p.get("witness")) |w|
            (if (before.object.len == 0) w else before)
        else
            before;

        return .{ .ok = .{ .params = next, .auth_keys = auth_keys, .witness_applies = witness_applies, .scid = the_scid } };
    }
};

const ItemKind = enum { multikey, multihash };

fn stringArray(a: Allocator, v: Value, kind: ItemKind) Allocator.Error!?[]const []const u8 {
    if (v != .array) return null;
    const out = try a.alloc([]const u8, v.array.len);
    for (v.array, out) |item, *o| {
        if (item != .string) return null;
        switch (kind) {
            .multikey => if ((try codec.decodeMultikey(a, item.string)) == null) return null,
            .multihash => if ((try codec.classifyMultihash(a, item.string)) != .sha256) return null,
        }
        o.* = item.string;
    }
    return out;
}

/// Returns why a `witness` parameter value is malformed, or null if it is valid.
fn witnessProblem(a: Allocator, w: Value) Allocator.Error!?[]const u8 {
    if (w != .object) return "not an object";
    if (w.object.len == 0) return null;
    const ws = w.get("witnesses") orelse return "witnesses is missing";
    if (ws != .array) return "witnesses is not an array";
    if (ws.array.len == 0) return "witnesses is empty";
    for (ws.array, 0..) |item, i| {
        if (item != .object) return "a witness is not an object";
        const id = item.getString("id") orelse return "a witness has no string id";
        if (!std.mem.startsWith(u8, id, "did:key:")) return "a witness id is not a did:key";
        if ((try codec.decodeMultikey(a, id["did:key:".len..])) == null) return "a witness id is not an Ed25519 did:key";
        for (ws.array[0..i]) |other| {
            if (std.mem.eql(u8, other.getString("id").?, id)) return "duplicate witness id";
        }
    }
    const t = w.get("threshold") orelse return "threshold is missing";
    if (t != .number or t.number != @floor(t.number)) return "threshold is not an integer";
    if (t.number < 1) return "threshold is less than 1";
    if (t.number > @as(f64, @floatFromInt(ws.array.len))) return "threshold exceeds the number of witnesses";
    return null;
}

/// Profile §4: printable ASCII, http(s) scheme, non-empty authority.
pub fn validWatcherUrl(u: []const u8) bool {
    for (u) |c| if (c < 0x21 or c > 0x7e) return false;
    const rest = if (std.mem.startsWith(u8, u, "https://"))
        u["https://".len..]
    else if (std.mem.startsWith(u8, u, "http://"))
        u["http://".len..]
    else
        return false;
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    return end > 0;
}

/// Verifies a log: every entry in order, then witnesses over the valid prefix.
/// All memory comes from `a` (use an arena).
pub fn verify(a: Allocator, log_text: []const u8, witness: WitnessInput, now: i64) Allocator.Error!Verification {
    const lines = try splitLines(a, log_text);
    const line_times = try a.alloc(?i64, lines.text.len);
    for (lines.values, line_times) |lv, *t| {
        t.* = if (lv) |val| (if (val.getString("versionTime")) |s| time.parse(s) else null) else null;
    }
    var entries: std.ArrayList(Entry) = .empty;
    var failure: ?Failure = null;
    if (lines.text.len == 0) {
        failure = .{ .code = .invalid_log, .version = null, .message = "the log is empty" };
    }
    var verifier: Verifier = .{ .a = a, .now = now };
    for (lines.text, 0..) |_, i| {
        const k: u64 = i + 1;
        const val = lines.values[i] orelse {
            failure = .{ .code = .invalid_log, .version = k, .message = try std.fmt.allocPrint(a, "line {d}: {s}", .{ k, lines.problems[i].? }) };
            break;
        };
        switch (try verifier.processEntry(k, val)) {
            .fail => |f| {
                failure = f;
                break;
            },
            .ok => |e| {
                try entries.append(a, e);
                verifier.prev = e;
            },
        }
    }

    // Witnesses (spec: only after all other checks).
    var valid = entries.items;
    if (try checkWitnesses(a, valid, witness)) |wf| {
        failure = wf;
        valid = valid[0 .. wf.version.? - 1];
    }
    return .{ .lines = lines, .entries = valid, .failure = failure, .line_times = line_times, .scid = verifier.scid };
}

pub const OwnedVerification = struct {
    arena: *std.heap.ArenaAllocator,
    verification: Verification,

    pub fn deinit(self: OwnedVerification) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Like `verify`, but the result owns its memory (including copies of
/// `log_text` and the witness file).
pub fn verifyOwned(gpa: Allocator, log_text: []const u8, witness: WitnessInput, now: i64) Allocator.Error!OwnedVerification {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const v = try verify(a, try a.dupe(u8, log_text), try cloneWitness(a, witness), now);
    return .{ .arena = arena, .verification = v };
}

fn checkWitnesses(a: Allocator, entries: []const Entry, witness: WitnessInput) Allocator.Error!?Failure {
    var first_needing: ?usize = null;
    for (entries, 0..) |e, i| {
        if (e.witness_applies.object.len > 0) {
            first_needing = i;
            break;
        }
    }
    const first = first_needing orelse return null;

    var records: []const Value = &.{};
    switch (witness) {
        .absent => {},
        .present => |w| {
            const ok = w == .array and for (w.array) |r| {
                if (r != .object) break false;
                const vid = r.get("versionId") orelse break false;
                const pf = r.get("proof") orelse break false;
                if (vid != .string or pf != .array) break false;
            } else true;
            if (!ok) return .{
                .code = .invalid_witness_file,
                .version = first + 1,
                .message = "the witness file is not a JSON array of {versionId, proof[]}",
            };
            records = w.array;
        },
    }

    // Verified witness ids per entry index (proofs for versionIds not in the
    // valid log are ignored).
    const approvals = try a.alloc(std.ArrayList([]const u8), entries.len);
    for (approvals) |*ap| ap.* = .empty;
    for (records) |r| {
        const vid = r.getString("versionId").?;
        const idx = for (entries, 0..) |e, i| {
            if (std.mem.eql(u8, e.version_id, vid)) break i;
        } else continue;
        const doc_members = try a.alloc(Member, 1);
        doc_members[0] = .{ .key = "versionId", .value = .{ .string = vid } };
        const doc: Value = .{ .object = doc_members };
        for (r.get("proof").?.array) |pf| {
            if (pf != .object) continue;
            const vm = pf.getString("verificationMethod") orelse continue;
            const mk = proof.didKeyMultikey(vm) orelse continue;
            const pk = (try codec.decodeMultikey(a, mk)) orelse continue;
            if (!try proof.verifyWithKey(a, doc, pf, pk)) continue;
            try approvals[idx].append(a, try std.mem.concat(a, u8, &.{ "did:key:", mk }));
        }
    }

    for (entries[first..], first..) |e, i| {
        const cfg = e.witness_applies;
        if (cfg.object.len == 0) continue;
        const threshold: usize = @intFromFloat(cfg.get("threshold").?.number);
        var count: usize = 0;
        for (cfg.get("witnesses").?.array) |w| {
            const id = w.getString("id").?;
            const approved = outer: for (approvals[i..]) |ap| {
                for (ap.items) |got| if (std.mem.eql(u8, got, id)) break :outer true;
            } else false;
            if (approved) count += 1;
        }
        if (count < threshold) return .{
            .code = .witness_threshold_not_met,
            .version = i + 1,
            .message = try std.fmt.allocPrint(a, "entry {d} has {d} of {d} required witness approvals", .{ i + 1, count, threshold }),
        };
    }
    return null;
}

// ------------------------------------------------------------------ resolution

pub const Options = struct {
    version_id: ?[]const u8 = null,
    version_time: ?[]const u8 = null,
    version_number: ?u64 = null,
    min_copies: u64 = 1,
};

pub const CopyInput = struct {
    source: []const u8,
    /// Null when the copy could not be retrieved.
    log: ?[]const u8 = null,
    witness: WitnessInput = .absent,
    /// Reason the copy is unavailable.
    unavailable: ?[]const u8 = null,
};

pub const Request = struct {
    log: []const u8,
    witness: WitnessInput = .absent,
    /// Resolver's current time (seconds since the epoch).
    now: i64,
    options: Options = .{},
    copies: ?[]const CopyInput = null,
    retained_version_id: ?[]const u8 = null,
};

pub const CopyStatus = enum {
    current,
    behind,
    invalid,
    unavailable,
};

pub const CopyReport = struct {
    source: []const u8,
    version_id: ?[]const u8,
    status: CopyStatus,
};

pub const Warning = struct {
    code: []const u8,
    source: ?[]const u8 = null,
    message: []const u8,
};

pub const ForkCopy = struct {
    source: []const u8,
    version_id: []const u8,
};

pub const ErrorInfo = struct {
    code: ErrorCode,
    version: ?u64,
    message: []const u8,
    fork: ?struct { version: u64, copies: []const ForkCopy } = null,
};

pub const Metadata = struct {
    version_id: []const u8,
    version_time: []const u8,
    version_number: u64,
    created: []const u8,
    updated: []const u8,
    scid: []const u8,
    deactivated: bool,
    ttl: f64,
    /// Null when the active witness configuration is `{}`.
    witness: ?Value,
    watchers: Value,
    update_keys: []const []const u8,
    next_key_hashes: []const []const u8,
    copies: ?[]const CopyReport,
    warnings: []const Warning,
};

pub const Resolution = struct {
    arena: *std.heap.ArenaAllocator,
    valid: bool,
    state: ?Value = null,
    metadata: ?Metadata = null,
    first_invalid_version: ?u64 = null,
    err: ?ErrorInfo = null,

    pub fn deinit(self: Resolution) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }

    /// The driver-protocol JSON form of the result, allocated in `a`.
    pub fn toValue(self: Resolution, a: Allocator) Allocator.Error!Value {
        var b: ObjBuilder = .{ .a = a };
        try b.put("valid", .{ .bool = self.valid });
        if (self.valid) {
            try b.put("state", self.state.?);
            try b.put("metadata", try metadataValue(a, self.metadata.?));
            try b.put("firstInvalidVersion", optNumber(self.first_invalid_version));
        }
        try b.put("error", if (self.err) |e| try errorValue(a, e) else .null);
        return b.done();
    }
};

const ObjBuilder = struct {
    a: Allocator,
    members: std.ArrayList(Member) = .empty,

    fn put(b: *ObjBuilder, key: []const u8, value: Value) Allocator.Error!void {
        try b.members.append(b.a, .{ .key = key, .value = value });
    }

    fn done(b: *ObjBuilder) Allocator.Error!Value {
        return .{ .object = try b.members.toOwnedSlice(b.a) };
    }
};

fn optNumber(n: ?u64) Value {
    return if (n) |x| .{ .number = @floatFromInt(x) } else .null;
}

fn strings(a: Allocator, items: []const []const u8) Allocator.Error!Value {
    const out = try a.alloc(Value, items.len);
    for (items, out) |s, *o| o.* = .{ .string = s };
    return .{ .array = out };
}

fn errorValue(a: Allocator, e: ErrorInfo) Allocator.Error!Value {
    var b: ObjBuilder = .{ .a = a };
    try b.put("code", .{ .string = e.code.name() });
    try b.put("version", optNumber(e.version));
    try b.put("message", .{ .string = e.message });
    if (e.fork) |f| {
        var copies: std.ArrayList(Value) = .empty;
        for (f.copies) |c| {
            var cb: ObjBuilder = .{ .a = a };
            try cb.put("source", .{ .string = c.source });
            try cb.put("versionId", .{ .string = c.version_id });
            try copies.append(a, try cb.done());
        }
        var fb: ObjBuilder = .{ .a = a };
        try fb.put("version", .{ .number = @floatFromInt(f.version) });
        try fb.put("copies", .{ .array = copies.items });
        try b.put("fork", try fb.done());
    }
    return b.done();
}

fn metadataValue(a: Allocator, m: Metadata) Allocator.Error!Value {
    var b: ObjBuilder = .{ .a = a };
    try b.put("versionId", .{ .string = m.version_id });
    try b.put("versionTime", .{ .string = m.version_time });
    try b.put("versionNumber", .{ .number = @floatFromInt(m.version_number) });
    try b.put("created", .{ .string = m.created });
    try b.put("updated", .{ .string = m.updated });
    try b.put("scid", .{ .string = m.scid });
    try b.put("deactivated", .{ .bool = m.deactivated });
    try b.put("ttl", .{ .number = m.ttl });
    try b.put("witness", m.witness orelse .null);
    try b.put("watchers", m.watchers);
    try b.put("updateKeys", try strings(a, m.update_keys));
    try b.put("nextKeyHashes", try strings(a, m.next_key_hashes));
    if (m.copies) |copies| {
        var list: std.ArrayList(Value) = .empty;
        for (copies) |c| {
            var cb: ObjBuilder = .{ .a = a };
            try cb.put("source", .{ .string = c.source });
            if (c.version_id) |vid| try cb.put("versionId", .{ .string = vid });
            try cb.put("status", .{ .string = @tagName(c.status) });
            try list.append(a, try cb.done());
        }
        try b.put("copies", .{ .array = list.items });
    }
    var ws: std.ArrayList(Value) = .empty;
    for (m.warnings) |w| {
        var wb: ObjBuilder = .{ .a = a };
        try wb.put("code", .{ .string = w.code });
        if (w.source) |s| try wb.put("source", .{ .string = s });
        try wb.put("message", .{ .string = w.message });
        try ws.append(a, try wb.done());
    }
    try b.put("warnings", .{ .array = ws.items });
    return b.done();
}

pub const OptionsResult = union(enum) {
    ok: Options,
    invalid: []const u8,
};

/// Converts resolution options JSON into `Options` (unknown options and wrong
/// types are `invalid-option`).
pub fn optionsFromJson(v: ?Value) OptionsResult {
    var o: Options = .{};
    const val = v orelse return .{ .ok = o };
    if (val == .null) return .{ .ok = o };
    if (val != .object) return .{ .invalid = "options must be an object" };
    var selectors: usize = 0;
    for (val.object) |m| {
        if (std.mem.eql(u8, m.key, "versionId")) {
            if (m.value != .string) return .{ .invalid = "versionId must be a string" };
            o.version_id = m.value.string;
            selectors += 1;
        } else if (std.mem.eql(u8, m.key, "versionTime")) {
            if (m.value != .string or time.parse(m.value.string) == null) return .{ .invalid = "versionTime must be a UTC timestamp" };
            o.version_time = m.value.string;
            selectors += 1;
        } else if (std.mem.eql(u8, m.key, "versionNumber")) {
            o.version_number = positiveInt(m.value) orelse return .{ .invalid = "versionNumber must be a positive integer" };
            selectors += 1;
        } else if (std.mem.eql(u8, m.key, "minCopies")) {
            o.min_copies = positiveInt(m.value) orelse return .{ .invalid = "minCopies must be a positive integer" };
        } else return .{ .invalid = "unsupported resolution option" };
    }
    if (selectors > 1) return .{ .invalid = "at most one of versionId, versionTime and versionNumber may be given" };
    return .{ .ok = o };
}

fn positiveInt(v: Value) ?u64 {
    if (v != .number) return null;
    const x = v.number;
    if (x != @floor(x) or x < 1 or x > 9007199254740991.0) return null;
    return @intFromFloat(x);
}

const Candidate = struct {
    source: []const u8,
    input: CopyInput,
    lines: ?Lines = null,
    verification: ?Verification = null,
    status: ?CopyStatus = null,
    invalid_at: ?u64 = null,

    fn lastVersionId(c: Candidate) ?[]const u8 {
        const l = c.lines orelse return null;
        if (l.text.len == 0) return null;
        return l.versionId(l.text.len - 1);
    }
};

const Reference = struct {
    source: []const u8,
    verification: Verification,

    fn versionIdAt(r: Reference, n: usize) []const u8 {
        return r.verification.entries[n - 1].version_id;
    }
};

fn joinLines(a: Allocator, first: []const []const u8, rest: []const []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (first) |l| {
        try out.appendSlice(a, l);
        try out.append(a, '\n');
    }
    for (rest) |l| {
        try out.appendSlice(a, l);
        try out.append(a, '\n');
    }
    return out.items;
}

/// First version number at which two copies' versionIds differ.
fn firstDifference(ref: Reference, lines: Lines) u64 {
    const n = @min(ref.verification.entries.len, lines.text.len);
    for (0..n) |i| {
        const theirs = lines.versionId(i) orelse return i + 1;
        if (!std.mem.eql(u8, theirs, ref.verification.entries[i].version_id)) return i + 1;
    }
    return n + 1;
}

/// Resolves a log (profile §4). The result owns its memory.
pub fn resolve(gpa: Allocator, req: Request) Allocator.Error!Resolution {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    return resolveIn(arena, req);
}

fn cloneWitness(a: Allocator, w: WitnessInput) Allocator.Error!WitnessInput {
    return switch (w) {
        .absent => .absent,
        .present => |v| .{ .present = try json.clone(a, v) },
    };
}

fn fail(arena: *std.heap.ArenaAllocator, info: ErrorInfo) Resolution {
    return .{ .arena = arena, .valid = false, .err = info };
}

fn failCode(arena: *std.heap.ArenaAllocator, code: ErrorCode, version: ?u64, message: []const u8) Resolution {
    return fail(arena, .{ .code = code, .version = version, .message = message });
}

fn resolveIn(arena: *std.heap.ArenaAllocator, req_in: Request) Allocator.Error!Resolution {
    const a = arena.allocator();
    // The result references log text and witness values: own copies of them.
    var req = req_in;
    req.log = try a.dupe(u8, req_in.log);
    req.witness = try cloneWitness(a, req_in.witness);
    if (req_in.retained_version_id) |rv| req.retained_version_id = try a.dupe(u8, rv);
    if (req_in.copies) |cs| {
        const copies = try a.alloc(CopyInput, cs.len);
        for (cs, copies) |c, *o| o.* = .{
            .source = try a.dupe(u8, c.source),
            .log = if (c.log) |l| try a.dupe(u8, l) else null,
            .witness = try cloneWitness(a, c.witness),
            .unavailable = if (c.unavailable) |u| try a.dupe(u8, u) else null,
        };
        req.copies = copies;
    }
    const opts = req.options;
    {
        var selectors: usize = 0;
        if (opts.version_id != null) selectors += 1;
        if (opts.version_time != null) selectors += 1;
        if (opts.version_number != null) selectors += 1;
        if (selectors > 1) return failCode(arena, .invalid_option, null, "at most one version selector may be given");
    }
    var retained_number: ?u64 = null;
    if (req.retained_version_id) |rv| {
        retained_number = log.versionNumber(rv) orelse
            return failCode(arena, .invalid_option, null, "retainedVersionId is not a versionId");
    }

    var warnings: std.ArrayList(Warning) = .empty;
    var reports: ?[]CopyReport = null;
    var ref: Reference = undefined;

    if (req.copies) |copies| {
        // Comparing copies of a log: the primary is tried first as reference.
        const cands = try a.alloc(Candidate, copies.len + 1);
        cands[0] = .{ .source = "primary", .input = .{ .source = "primary", .log = req.log, .witness = req.witness } };
        for (copies, 1..) |c, i| cands[i] = .{ .source = c.source, .input = c };
        for (cands) |*c| {
            if (c.input.log) |text| c.lines = try splitLines(a, text) else c.status = .unavailable;
        }

        var ref_index: ?usize = null;
        for (cands, 0..) |*c, i| {
            if (c.status == .unavailable) continue;
            const ver = try verify(a, c.input.log.?, c.input.witness, req.now);
            c.verification = ver;
            if (ver.fullyValid()) {
                ref_index = i;
                break;
            }
            c.status = .invalid;
            c.invalid_at = if (ver.failure) |f| f.version else null;
        }
        const start: usize = if (ref_index) |ri| ri + 1 else 1;
        if (ref_index) |ri| {
            ref = .{ .source = cands[ri].source, .verification = cands[ri].verification.? };
            cands[ri].status = .current;
        } else {
            // No copy passes verification: fall back to the primary's valid prefix.
            ref = .{ .source = "primary", .verification = cands[0].verification orelse try verify(a, req.log, req.witness, req.now) };
        }

        for (cands[start..]) |*c| {
            if (c.status == .unavailable) continue;
            const lines = c.lines.?;
            const m = lines.text.len;
            const r = ref.verification.entries.len;
            if (m == 0 or r == 0) {
                c.status = .invalid;
                continue;
            }
            if (m <= r) {
                const theirs = lines.versionId(m - 1);
                if (theirs != null and std.mem.eql(u8, theirs.?, ref.versionIdAt(m))) {
                    c.status = .current; // settled against the final reference below
                    continue;
                }
            } else {
                const theirs = lines.versionId(r - 1);
                if (theirs != null and std.mem.eql(u8, theirs.?, ref.versionIdAt(r))) {
                    // Extends the reference: verify the additional entries from
                    // the state reached at the reference's last entry.
                    const combined = try joinLines(a, ref.verification.lines.text[0..r], lines.text[r..]);
                    const ver = try verify(a, combined, c.input.witness, req.now);
                    if (ver.fullyValid()) {
                        ref = .{ .source = c.source, .verification = ver };
                        c.status = .current;
                    } else {
                        c.status = .invalid;
                        c.invalid_at = if (ver.failure) |f| f.version else null;
                    }
                    continue;
                }
            }
            // Diverges: verify in full.
            const ver = try verify(a, c.input.log.?, c.input.witness, req.now);
            if (!ver.fullyValid()) {
                c.status = .invalid;
                c.invalid_at = if (ver.failure) |f| f.version else null;
                continue;
            }
            const k = firstDifference(ref, lines);
            const fork_copies = try a.alloc(ForkCopy, 2);
            fork_copies[0] = .{ .source = ref.source, .version_id = if (k <= r) ref.versionIdAt(k) else "" };
            fork_copies[1] = .{ .source = c.source, .version_id = lines.versionId(k - 1) orelse "" };
            return fail(arena, .{
                .code = .fork_detected,
                .version = k,
                .message = try std.fmt.allocPrint(a, "copies {s} and {s} both verify but diverge at entry {d}", .{ ref.source, c.source, k }),
                .fork = .{ .version = k, .copies = fork_copies },
            });
        }

        // Settle statuses against the final reference.
        const ref_last = if (ref.verification.entries.len > 0) ref.versionIdAt(ref.verification.entries.len) else "";
        const out = try a.alloc(CopyReport, cands.len);
        for (cands, out) |c, *o| {
            var status = c.status.?;
            if (status == .current) {
                const last = c.lastVersionId() orelse "";
                if (!std.mem.eql(u8, last, ref_last)) status = .behind;
            }
            o.* = .{ .source = c.source, .version_id = if (status == .unavailable) null else c.lastVersionId(), .status = status };
            switch (status) {
                .current => {},
                .behind => try warnings.append(a, .{
                    .code = "copy-behind",
                    .source = c.source,
                    .message = try std.fmt.allocPrint(a, "copy is {d} entries behind the reference copy", .{ref.verification.entries.len - c.lines.?.text.len}),
                }),
                .invalid => try warnings.append(a, .{
                    .code = "copy-invalid",
                    .source = c.source,
                    .message = if (c.invalid_at) |v|
                        try std.fmt.allocPrint(a, "copy failed verification at entry {d}", .{v})
                    else
                        "copy failed verification",
                }),
                .unavailable => try warnings.append(a, .{
                    .code = "copy-unavailable",
                    .source = c.source,
                    .message = try std.fmt.allocPrint(a, "copy could not be retrieved: {s}", .{c.input.unavailable orelse "unavailable"}),
                }),
            }
        }
        reports = out;
    } else {
        ref = .{ .source = "primary", .verification = try verify(a, req.log, req.witness, req.now) };
    }

    const ver = ref.verification;
    const entries = ver.entries;

    // A retained versionId from an earlier resolution.
    if (retained_number) |n| {
        const rv = req.retained_version_id.?;
        if (entries.len < n) {
            try warnings.append(a, .{
                .code = "retained-version-not-found",
                .message = try std.fmt.allocPrint(a, "the log has fewer entries than the retained version {d}", .{n}),
            });
        } else if (!std.mem.eql(u8, ref.versionIdAt(n), rv)) {
            const fork_copies = try a.alloc(ForkCopy, 2);
            fork_copies[0] = .{ .source = "retained", .version_id = rv };
            fork_copies[1] = .{ .source = ref.source, .version_id = ref.versionIdAt(n) };
            return fail(arena, .{
                .code = .fork_detected,
                .version = n,
                .message = try std.fmt.allocPrint(a, "the retained versionId differs from the log at entry {d}", .{n}),
                .fork = .{ .version = n, .copies = fork_copies },
            });
        }
    }

    if (entries.len == 0) {
        const f = ver.failure.?;
        return failCode(arena, f.code, f.version, f.message);
    }

    // minCopies (the reference retrieval counts).
    if (opts.min_copies > 1) {
        var count: u64 = 0;
        if (reports) |rs| {
            for (rs) |r| if (r.status == .current or r.status == .behind) {
                count += 1;
            };
        } else count = 1;
        if (count < opts.min_copies) return failCode(arena, .min_copies_not_met, null, try std.fmt.allocPrint(a, "{d} matching copies, {d} required", .{ count, opts.min_copies }));
    }

    // Select the target version.
    const target: *const Entry = blk: {
        const failure_err = if (ver.failure) |f| f else null;
        if (opts.version_id) |vid| {
            for (entries) |*e| if (std.mem.eql(u8, e.version_id, vid)) break :blk e;
            if (failure_err) |f| {
                for (entries.len..ver.lines.text.len) |i| {
                    if (ver.lines.versionId(i)) |lv| if (std.mem.eql(u8, lv, vid))
                        return failCode(arena, f.code, f.version, f.message);
                }
            }
            return failCode(arena, .not_found, null, "no entry has that versionId");
        } else if (opts.version_number) |n| {
            if (n <= entries.len) break :blk &entries[n - 1];
            if (failure_err) |f| if (n <= ver.lines.text.len) return failCode(arena, f.code, f.version, f.message);
            return failCode(arena, .not_found, null, "no entry has that version number");
        } else if (opts.version_time) |vt| {
            const t = time.parse(vt).?;
            if (failure_err) |f| if (f.version) |k| if (k - 1 < ver.line_times.len) if (ver.line_times[k - 1]) |kt| if (kt <= t)
                return failCode(arena, f.code, f.version, f.message);
            var found: ?*const Entry = null;
            for (entries) |*e| {
                if (e.time <= t) found = e;
            }
            break :blk found orelse return failCode(arena, .not_found, null, "no entry was active at that time");
        } else break :blk &entries[entries.len - 1];
    };

    const last = entries[entries.len - 1];
    if (ver.failure) |f| {
        try warnings.append(a, .{
            .code = "invalid-entries",
            .message = try std.fmt.allocPrint(a, "entries from {d} failed verification ({s}); using the last valid entry", .{ f.version orelse 0, f.code.name() }),
        });
    }
    return .{
        .arena = arena,
        .valid = true,
        .state = target.state,
        .first_invalid_version = if (ver.failure) |f| f.version else null,
        .err = if (ver.failure) |f| .{ .code = f.code, .version = f.version, .message = f.message } else null,
        .metadata = .{
            .version_id = target.version_id,
            .version_time = target.version_time,
            .version_number = target.version_number,
            .created = entries[0].version_time,
            .updated = last.version_time,
            .scid = ver.scid,
            .deactivated = ver.deactivated(),
            .ttl = last.params.ttl,
            .witness = if (last.params.witness.object.len == 0) null else last.params.witness,
            .watchers = last.params.watchers,
            .update_keys = target.params.update_keys,
            .next_key_hashes = target.params.next_key_hashes,
            .copies = reports,
            .warnings = warnings.items,
        },
    };
}
