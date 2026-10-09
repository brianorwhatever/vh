//! End-to-end tests and the shared vectors (../../vectors, relative to the
//! package root, which `zig build test` uses as the working directory).

const std = @import("std");
const json = @import("json.zig");
const codec = @import("codec.zig");
const proof = @import("proof.zig");
const log = @import("log.zig");
const resolver = @import("resolve.zig");
const ops = @import("ops.zig");
const Value = json.Value;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const vectors_dir = "../../vectors";

fn seedHex(hex: []const u8) [32]u8 {
    return codec.parseSeed(hex) catch unreachable;
}

const k1 = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa";
const k2 = "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6";
const w_a = "9bbc62934fb3ae67bb95142af8e2660a56576bdb6801d10ddbe9b31b1a87593e";
const now_2026_06: i64 = 1780272000; // 2026-06-01T00:00:00Z

// ------------------------------------------------------------------ end-to-end

test "create, update, resolve" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const mk1 = try proof.multikeyFromSeed(a, seedHex(k1));
    const mk2 = try proof.multikeyFromSeed(a, seedHex(k2));
    const params = (try json.parse(a, try std.fmt.allocPrint(a,
        \\{{"updateKeys":["{s}"],"nextKeyHashes":["{s}"]}}
    , .{ mk1, try codec.hashString(a, mk2) }))).value;
    const state = (try json.parse(a, "{\"id\":\"example:{SCID}\",\"n\":[1.0,1e21]}")).value;

    const created = try log.create(gpa, .{ .state = state, .parameters = params, .version_time = "2026-01-01T00:00:00Z", .signers = &.{seedHex(k1)} });
    defer created.deinit();
    try testing.expect(std.mem.startsWith(u8, created.scid, "Qm"));
    try testing.expect(std.mem.startsWith(u8, created.version_id, "1-Qm"));
    try testing.expect(std.mem.indexOf(u8, created.log, "{SCID}") == null);

    // Pre-rotation: entry 2 reveals k2 and is signed by it.
    const p2 = (try json.parse(a, try std.fmt.allocPrint(a, "{{\"updateKeys\":[\"{s}\"],\"nextKeyHashes\":[]}}", .{mk2}))).value;
    const s2 = (try json.parse(a, "{\"v\":2}")).value;
    const updated = try log.update(gpa, created.log, .{ .state = s2, .parameters = p2, .version_time = "2026-01-02T00:00:00Z", .signers = &.{seedHex(k2)} });
    defer updated.deinit();

    const res = try resolver.resolve(gpa, .{ .log = updated.log, .now = now_2026_06 });
    defer res.deinit();
    try testing.expect(res.valid);
    try testing.expect(res.err == null);
    try testing.expectEqualStrings(updated.version_id, res.metadata.?.version_id);
    try testing.expectEqual(@as(u64, 2), res.metadata.?.version_number);
    try testing.expect(json.eql(s2, res.state.?));
    try testing.expectEqualStrings(created.scid, res.metadata.?.scid);

    const vl = try resolver.verifyOwned(gpa, updated.log, .absent, now_2026_06);
    defer vl.deinit();
    try testing.expect(vl.verification.fullyValid());
    try testing.expectEqual(@as(usize, 2), vl.verification.entries.len);

    // Signing entry 2 with the old key under pre-rotation fails.
    const bad = try log.update(gpa, created.log, .{ .state = s2, .parameters = p2, .version_time = "2026-01-02T00:00:00Z", .signers = &.{seedHex(k1)} });
    defer bad.deinit();
    const r2 = try resolver.resolve(gpa, .{ .log = bad.log, .now = now_2026_06 });
    defer r2.deinit();
    try testing.expect(r2.valid);
    try testing.expectEqual(resolver.ErrorCode.unauthorized_key, r2.err.?.code);
    try testing.expectEqual(@as(?u64, 2), r2.first_invalid_version);

    // versionId doesn't cover proofs: the same content signed by another key
    // has the same versionId (spec-notes 14).
    try testing.expectEqualStrings(updated.version_id, bad.version_id);

    // A retained versionId that differs is a fork.
    const other = try log.update(gpa, created.log, .{ .state = state, .parameters = p2, .version_time = "2026-01-02T00:00:00Z", .signers = &.{seedHex(k2)} });
    defer other.deinit();
    const r3 = try resolver.resolve(gpa, .{ .log = updated.log, .now = now_2026_06, .retained_version_id = other.version_id });
    defer r3.deinit();
    try testing.expect(!r3.valid);
    try testing.expectEqual(resolver.ErrorCode.fork_detected, r3.err.?.code);

    // Copies: the primary is behind a longer, valid copy.
    const r4 = try resolver.resolve(gpa, .{
        .log = created.log,
        .now = now_2026_06,
        .copies = &.{.{ .source = "https://w.example", .log = updated.log }},
        .options = .{ .min_copies = 2 },
    });
    defer r4.deinit();
    try testing.expect(r4.valid);
    try testing.expectEqualStrings(updated.version_id, r4.metadata.?.version_id);
    try testing.expectEqual(resolver.CopyStatus.behind, r4.metadata.?.copies.?[0].status);
    try testing.expectEqual(resolver.CopyStatus.current, r4.metadata.?.copies.?[1].status);
}

test "witnessed genesis" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const mk1 = try proof.multikeyFromSeed(a, seedHex(k1));
    const mkw = try proof.multikeyFromSeed(a, seedHex(w_a));
    const params = (try json.parse(a, try std.fmt.allocPrint(a,
        \\{{"updateKeys":["{s}"],"witness":{{"threshold":1,"witnesses":[{{"id":"did:key:{s}"}}]}}}}
    , .{ mk1, mkw }))).value;
    const state = (try json.parse(a, "{\"id\":\"example:{SCID}\"}")).value;
    const created = try log.create(gpa, .{ .state = state, .parameters = params, .version_time = "2026-01-01T00:00:00Z", .signers = &.{seedHex(k1)} });
    defer created.deinit();

    const unwitnessed = try resolver.resolve(gpa, .{ .log = created.log, .now = now_2026_06 });
    defer unwitnessed.deinit();
    try testing.expect(!unwitnessed.valid);
    try testing.expectEqual(resolver.ErrorCode.witness_threshold_not_met, unwitnessed.err.?.code);

    const wp = try log.witnessProof(gpa, created.version_id, seedHex(w_a), null);
    defer wp.deinit();
    const file = try std.fmt.allocPrint(a, "[{{\"versionId\":\"{s}\",\"proof\":[{s}]}}]", .{ created.version_id, try json.stringify(a, wp.value) });
    const wf = try json.parse(a, file);
    const witnessed = try resolver.resolve(gpa, .{ .log = created.log, .now = now_2026_06, .witness = .{ .present = wf.value } });
    defer witnessed.deinit();
    try testing.expect(witnessed.valid);
    try testing.expect(witnessed.metadata.?.witness != null);
}

test "driver protocol" {
    const gpa = testing.allocator;
    const r = try ops.handle(gpa, "{\"id\":1,\"op\":\"jcs\",\"input\":{\"text\":\"{\\\"b\\\": 1, \\\"a\\\": [true, null]}\"}}");
    defer gpa.free(r);
    try testing.expectEqualStrings("{\"id\":1,\"ok\":true,\"result\":{\"output\":\"{\\\"a\\\":[true,null],\\\"b\\\":1}\"}}", r);
    const e = try ops.handle(gpa, "{\"id\":2,\"op\":\"nope\",\"input\":{}}");
    defer gpa.free(e);
    try testing.expect(std.mem.indexOf(u8, e, "\"ok\":false") != null);
    const g = try ops.handle(gpa, "not json");
    defer gpa.free(g);
    try testing.expect(std.mem.indexOf(u8, g, "\"ok\":false") != null);
}

test "error code names" {
    try testing.expectEqualStrings("invalid-log", resolver.ErrorCode.invalid_log.name());
    try testing.expectEqualStrings("witness-threshold-not-met", resolver.ErrorCode.witness_threshold_not_met.name());
}

// ------------------------------------------------------------------ vectors

fn readVector(a: Allocator, path: []const u8) !Value {
    const io = testing.io;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(16 << 20));
    return (try json.parse(a, text)).value;
}

/// Sends one request through the driver protocol and returns `result`.
fn call(a: Allocator, op: []const u8, input: Value) !Value {
    const line = try std.fmt.allocPrint(a, "{{\"id\":1,\"op\":\"{s}\",\"input\":{s}}}", .{ op, try json.stringify(a, input) });
    const owned = try ops.handle(testing.allocator, line);
    defer testing.allocator.free(owned);
    const resp_text = try a.dupe(u8, owned);
    const resp = (try json.parse(a, resp_text)).value;
    if (resp.get("ok").?.bool != true) {
        std.debug.print("driver error for {s}: {s}\n", .{ op, resp.getString("error").? });
        return error.DriverError;
    }
    return resp.get("result").?;
}

fn obj(a: Allocator, kvs: []const json.Member) !Value {
    return .{ .object = try a.dupe(json.Member, kvs) };
}

fn expectSame(want: Value, got: ?Value) !void {
    if (got == null or !json.eql(want, got.?)) return error.Mismatch;
}

test "vectors: primitives" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try readVector(a, vectors_dir ++ "/primitives.json");
    var count: usize = 0;

    for (v.get("jcs").?.array) |c| {
        const r = try call(a, "jcs", try obj(a, &.{.{ .key = "text", .value = c.get("text").? }}));
        try testing.expectEqualStrings(c.getString("output").?, r.getString("output").?);
        count += 1;
    }
    for (v.get("hash").?.array) |c| {
        const r = try call(a, "hash", try obj(a, &.{.{ .key = "data", .value = c.get("data").? }}));
        try testing.expectEqualStrings(c.getString("output").?, r.getString("output").?);
        count += 1;
    }
    for (v.get("multikey").?.array) |c| {
        const r = try call(a, "multikey", try obj(a, &.{.{ .key = "seed", .value = c.get("seed").? }}));
        try testing.expectEqualStrings(c.getString("multikey").?, r.getString("multikey").?);
        count += 1;
    }
    for (v.get("keyHash").?.array) |c| {
        const r = try call(a, "key-hash", try obj(a, &.{.{ .key = "multikey", .value = c.get("multikey").? }}));
        try testing.expectEqualStrings(c.getString("output").?, r.getString("output").?);
        count += 1;
    }
    for (v.get("scid").?.array) |c| {
        const r = try call(a, "scid", try obj(a, &.{.{ .key = "entry", .value = c.get("entry").? }}));
        try testing.expectEqualStrings(c.getString("scid").?, r.getString("scid").?);
        count += 1;
    }
    for (v.get("entryHash").?.array) |c| {
        const r = try call(a, "entry-hash", try obj(a, &.{
            .{ .key = "entry", .value = c.get("entry").? },
            .{ .key = "previousVersionId", .value = c.get("previousVersionId").? },
        }));
        try testing.expectEqualStrings(c.getString("hash").?, r.getString("hash").?);
        count += 1;
    }
    for (v.get("sign").?.array) |c| {
        var input = try json.without(a, c, "proof");
        input = try json.without(a, input, "description");
        const r = try call(a, "sign", input);
        try expectSame(c.get("proof").?, r.get("proof"));
        const ok = try call(a, "verify", try obj(a, &.{ .{ .key = "document", .value = c.get("document").? }, .{ .key = "proof", .value = c.get("proof").? } }));
        try testing.expect(ok.get("valid").?.bool);
        const tampered = try json.with(a, c.get("document").?, "extra", .{ .number = 1 });
        const no = try call(a, "verify", try obj(a, &.{ .{ .key = "document", .value = tampered }, .{ .key = "proof", .value = c.get("proof").? } }));
        try testing.expect(!no.get("valid").?.bool);
        count += 3;
    }
    try testing.expectEqual(@as(usize, 35), count);
}

fn checkResolution(a: Allocator, expect: Value, got: Value) ![]const u8 {
    const valid = expect.get("valid").?.bool;
    if (got.get("valid").?.bool != valid) return "valid differs";
    const err = got.get("error") orelse Value{ .null = {} };
    if (expect.get("error")) |ee| {
        if (err == .null) return "missing error";
        const code = err.getString("code").?;
        const codes: []const Value = if (ee.get("oneOf")) |o| o.array else &.{ee.get("code").?};
        const matched = for (codes) |cv| {
            if (std.mem.eql(u8, cv.string, code)) break true;
        } else false;
        if (!matched) return try std.fmt.allocPrint(a, "error code {s}", .{code});
        if (ee.get("version")) |want| if (!json.eql(want, err.get("version").?)) return "error version differs";
    } else if (err != .null) return try std.fmt.allocPrint(a, "unexpected error {s}", .{err.getString("code").?});
    if (valid) {
        if (!json.eql(expect.get("state").?, got.get("state").?)) return "state differs";
        const fiv_want = expect.get("firstInvalidVersion") orelse Value{ .null = {} };
        if (!json.eql(fiv_want, got.get("firstInvalidVersion").?)) return "firstInvalidVersion differs";
        const md = got.get("metadata").?;
        // Warning codes, sorted.
        var codes: std.ArrayList([]const u8) = .empty;
        for (md.get("warnings").?.array) |w| try codes.append(a, w.getString("code").?);
        std.mem.sort([]const u8, codes.items, {}, struct {
            fn lt(_: void, x: []const u8, y: []const u8) bool {
                return std.mem.order(u8, x, y) == .lt;
            }
        }.lt);
        const want_w = if (expect.get("warnings")) |w| w.array else &[_]Value{};
        if (want_w.len != codes.items.len) return "warnings differ";
        for (want_w, codes.items) |w, g| if (!std.mem.eql(u8, w.string, g)) return "warnings differ";
        if (expect.get("metadata")) |em| for (em.object) |m| {
            const g = md.get(m.key) orelse return try std.fmt.allocPrint(a, "metadata.{s} missing", .{m.key});
            if (!json.eql(m.value, g)) return try std.fmt.allocPrint(a, "metadata.{s} differs", .{m.key});
        };
    }
    return "";
}

test "vectors: resolution" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var dir = try std.Io.Dir.cwd().openDir(io, vectors_dir ++ "/resolution", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    var total: usize = 0;
    var failures: usize = 0;
    while (try it.next(io)) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
        const path = try std.fmt.allocPrint(a, "{s}/resolution/{s}", .{ vectors_dir, entry.name });
        const v = try readVector(a, path);
        for (v.get("cases").?.array) |c| {
            total += 1;
            const got = try call(a, "resolve", c.get("input").?);
            const problem = try checkResolution(a, c.get("expect").?, got);
            if (problem.len > 0) {
                failures += 1;
                std.debug.print("{s}/{s}: {s}\n", .{ entry.name, c.getString("name").?, problem });
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), failures);
    try testing.expectEqual(@as(usize, 158), total);
}

test "vectors: generation and cross-resolution" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try readVector(a, vectors_dir ++ "/generation.json");
    for (v.get("scenarios").?.array) |sc| {
        var log_text: []const u8 = "";
        var scid: []const u8 = "";
        var version_ids: std.ArrayList([]const u8) = .empty;
        for (sc.get("steps").?.array, 1..) |step, i| {
            const op = step.getString("op").?;
            var input = step.get("input").?;
            if (std.mem.eql(u8, op, "update")) {
                const text = try json.stringify(a, input);
                const replaced = try std.mem.replaceOwned(u8, a, text, "{SCID}", scid);
                input = try json.with(a, (try json.parse(a, replaced)).value, "log", .{ .string = log_text });
            }
            const r = try call(a, op, input);
            log_text = r.getString("log").?;
            if (std.mem.eql(u8, op, "create")) scid = r.getString("scid").?;
            const exp = step.get("expect").?;
            try testing.expectEqualStrings(exp.getString("versionId").?, r.getString("versionId").?);
            if (exp.getString("scid")) |s| try testing.expectEqualStrings(s, scid);
            const last = (try json.parse(a, log.lastLine(log_text).?)).value;
            try expectSame(exp.get("line").?, last);
            var n: usize = 0;
            var lines = std.mem.splitScalar(u8, log_text, '\n');
            while (lines.next()) |l| if (l.len > 0) {
                n += 1;
            };
            try testing.expectEqual(i, n);
            try version_ids.append(a, r.getString("versionId").?);
        }
        var witness: ?Value = null;
        if (sc.get("witness")) |ws| {
            var records: std.ArrayList(Value) = .empty;
            for (ws.array) |w| {
                const vid = version_ids.items[@intFromFloat(w.get("step").?.number - 1)];
                var proofs: std.ArrayList(Value) = .empty;
                for (w.get("seeds").?.array) |seed| {
                    const r = try call(a, "witness", try obj(a, &.{ .{ .key = "versionId", .value = .{ .string = vid } }, .{ .key = "seed", .value = seed } }));
                    try proofs.append(a, r.get("proof").?);
                }
                try records.append(a, try obj(a, &.{ .{ .key = "versionId", .value = .{ .string = vid } }, .{ .key = "proof", .value = .{ .array = proofs.items } } }));
            }
            witness = .{ .array = records.items };
            try expectSame(sc.get("witnessFile").?, witness);
        }
        // Resolve what we generated.
        const rs = sc.get("resolve").?;
        var members: std.ArrayList(json.Member) = .empty;
        try members.append(a, .{ .key = "log", .value = .{ .string = log_text } });
        try members.append(a, .{ .key = "now", .value = rs.get("now").? });
        if (witness) |w| try members.append(a, .{ .key = "witness", .value = w });
        const got = try call(a, "resolve", .{ .object = members.items });
        try testing.expect(got.get("valid").?.bool);
        try testing.expect(got.get("error").? == .null);
        try expectSame(rs.get("state").?, got.get("state"));
        try testing.expectEqualStrings(rs.getString("versionId").?, got.get("metadata").?.getString("versionId").?);
    }
}

test "vectors: didwebvh-ts external logs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    const base = vectors_dir ++ "/external/didwebvh-ts";
    const manifest = try readVector(a, base ++ "/manifest.json");
    for (manifest.get("scenarios").?.array) |sc| {
        const name = sc.getString("name").?;
        const text = try std.Io.Dir.cwd().readFileAlloc(io, try std.fmt.allocPrint(a, "{s}/{s}.jsonl", .{ base, name }), a, .limited(1 << 20));
        var entries: std.ArrayList(Value) = .empty;
        var it = std.mem.splitScalar(u8, std.mem.trim(u8, text, "\n"), '\n');
        while (it.next()) |l| try entries.append(a, (try json.parse(a, l)).value);
        const first_params = entries.items[0].get("parameters").?;
        const scid = first_params.getString("scid").?;
        for (entries.items, 0..) |entry, i| {
            const doc = try json.without(a, entry, "proof");
            if (i == 0) {
                const prelim_text = try std.mem.replaceOwned(u8, a, try json.stringify(a, try json.with(a, doc, "versionId", .{ .string = "{SCID}" })), scid, "{SCID}");
                const prelim = (try json.parse(a, prelim_text)).value;
                try testing.expectEqualStrings(scid, try log.scid(a, prelim));
            }
            const vid = entry.getString("versionId").?;
            const hash = vid[std.mem.indexOfScalar(u8, vid, '-').? + 1 ..];
            const prev = if (i == 0) scid else entries.items[i - 1].getString("versionId").?;
            try testing.expectEqualStrings(hash, try log.entryHash(a, doc, prev));
            for (entry.get("proof").?.array) |p| {
                try testing.expect(try proof.verify(a, doc, p));
                const tampered = try json.with(a, doc, "versionTime", .{ .string = "1999-01-01T00:00:00Z" });
                try testing.expect(!try proof.verify(a, tampered, p));
            }
            if (i > 0) {
                const committed = entries.items[i - 1].get("parameters").?.get("nextKeyHashes");
                if (committed) |cm| if (cm.array.len > 0) {
                    for (entry.get("parameters").?.get("updateKeys").?.array) |k| {
                        const h = try codec.hashString(a, k.string);
                        const found = for (cm.array) |c| {
                            if (std.mem.eql(u8, c.string, h)) break true;
                        } else false;
                        try testing.expect(found);
                    }
                };
            }
        }
        if (sc.get("witness").?.bool) {
            const wf = try readVector(a, try std.fmt.allocPrint(a, "{s}/{s}.witness.json", .{ base, name }));
            for (wf.array) |record| {
                const doc = try obj(a, &.{.{ .key = "versionId", .value = record.get("versionId").? }});
                for (record.get("proof").?.array) |p| try testing.expect(try proof.verify(a, doc, p));
            }
        }
    }
}
