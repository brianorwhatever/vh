//! The interop driver protocol (docs/interop-protocol.md): one JSON request
//! in, one JSON response out. Kept in the library so tests can drive it.

const std = @import("std");
const json = @import("json.zig");
const codec = @import("codec.zig");
const proof = @import("proof.zig");
const log = @import("log.zig");
const time = @import("time.zig");
const resolver = @import("resolve.zig");
const Allocator = std.mem.Allocator;
const Value = json.Value;
const Member = json.Member;

const OpError = error{BadRequest} || Allocator.Error;

const Ctx = struct {
    a: Allocator,
    message: []const u8 = "bad request",

    fn bad(c: *Ctx, comptime fmt: []const u8, args: anytype) OpError {
        c.message = std.fmt.allocPrint(c.a, fmt, args) catch "bad request";
        return error.BadRequest;
    }

    fn str(c: *Ctx, input: Value, key: []const u8) OpError![]const u8 {
        return input.getString(key) orelse c.bad("input.{s} must be a string", .{key});
    }

    fn optStr(c: *Ctx, input: Value, key: []const u8) OpError!?[]const u8 {
        const v = input.get(key) orelse return null;
        if (v == .null) return null;
        if (v != .string) return c.bad("input.{s} must be a string", .{key});
        return v.string;
    }

    fn obj(c: *Ctx, input: Value, key: []const u8) OpError!Value {
        const v = input.get(key) orelse return c.bad("input.{s} is required", .{key});
        if (v != .object) return c.bad("input.{s} must be an object", .{key});
        return v;
    }

    fn seed(c: *Ctx, hex: []const u8) OpError![32]u8 {
        return codec.parseSeed(hex) catch c.bad("seed must be 32 bytes of hex", .{});
    }

    fn signers(c: *Ctx, input: Value) OpError![]const [32]u8 {
        const v = input.get("signers") orelse return c.bad("input.signers is required", .{});
        if (v != .array) return c.bad("input.signers must be an array", .{});
        const out = try c.a.alloc([32]u8, v.array.len);
        for (v.array, out) |s, *o| {
            if (s != .string) return c.bad("signers must be hex strings", .{});
            o.* = try c.seed(s.string);
        }
        return out;
    }
};

fn single(a: Allocator, key: []const u8, value: Value) Allocator.Error!Value {
    const m = try a.alloc(Member, 1);
    m[0] = .{ .key = key, .value = value };
    return .{ .object = m };
}

fn str(s: []const u8) Value {
    return .{ .string = s };
}

fn mapStringify(c: *Ctx, err: json.StringifyError) OpError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.NonFinite => c.bad("non-finite number", .{}),
    };
}

fn mapLog(c: *Ctx, err: log.Error) OpError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => |e| c.bad("{s}", .{@errorName(e)}),
    };
}

fn witnessInput(v: Value, key: []const u8) resolver.WitnessInput {
    const w = v.get(key) orelse return .absent;
    return .{ .present = w };
}

fn dispatch(c: *Ctx, op: []const u8, input: Value) OpError!Value {
    const a = c.a;
    const eq = std.mem.eql;
    if (input != .object) return c.bad("input must be an object", .{});

    if (eq(u8, op, "jcs")) {
        const text = try c.str(input, "text");
        const parsed = json.parse(a, text) catch |err| return c.bad("invalid JSON: {s}", .{@errorName(err)});
        const out = json.canonicalize(a, parsed.value) catch |err| return mapStringify(c, err);
        return single(a, "output", str(out));
    }
    if (eq(u8, op, "hash")) {
        return single(a, "output", str(try codec.hashString(a, try c.str(input, "data"))));
    }
    if (eq(u8, op, "multikey")) {
        const mk = proof.multikeyFromSeed(a, try c.seed(try c.str(input, "seed"))) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidSeed => return c.bad("invalid seed", .{}),
        };
        return single(a, "multikey", str(mk));
    }
    if (eq(u8, op, "key-hash")) {
        return single(a, "output", str(try codec.hashString(a, try c.str(input, "multikey"))));
    }
    if (eq(u8, op, "scid")) {
        const s = log.scid(a, try c.obj(input, "entry")) catch |err| return mapStringify(c, err);
        return single(a, "scid", str(s));
    }
    if (eq(u8, op, "entry-hash")) {
        const h = log.entryHash(a, try c.obj(input, "entry"), try c.str(input, "previousVersionId")) catch |err| return mapStringify(c, err);
        return single(a, "hash", str(h));
    }
    if (eq(u8, op, "sign")) {
        const doc = try c.obj(input, "document");
        const p = proof.create(a, doc, try c.seed(try c.str(input, "seed")), .{
            .verification_method = try c.optStr(input, "verificationMethod"),
            .created = try c.optStr(input, "created"),
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return c.bad("{s}", .{@errorName(e)}),
        };
        return single(a, "proof", p);
    }
    if (eq(u8, op, "verify")) {
        const doc = try c.obj(input, "document");
        const p = input.get("proof") orelse return c.bad("input.proof is required", .{});
        return single(a, "valid", .{ .bool = try proof.verify(a, doc, p) });
    }
    if (eq(u8, op, "create")) {
        const r = log.create(a, .{
            .state = try c.obj(input, "state"),
            .parameters = try c.obj(input, "parameters"),
            .version_time = try c.str(input, "versionTime"),
            .signers = try c.signers(input),
        }) catch |err| return mapLog(c, err);
        const m = try a.alloc(Member, 3);
        m[0] = .{ .key = "log", .value = str(r.log) };
        m[1] = .{ .key = "scid", .value = str(r.scid) };
        m[2] = .{ .key = "versionId", .value = str(r.version_id) };
        return .{ .object = m };
    }
    if (eq(u8, op, "update")) {
        const r = log.update(a, try c.str(input, "log"), .{
            .state = try c.obj(input, "state"),
            .parameters = try c.obj(input, "parameters"),
            .version_time = try c.str(input, "versionTime"),
            .signers = try c.signers(input),
        }) catch |err| return mapLog(c, err);
        const m = try a.alloc(Member, 2);
        m[0] = .{ .key = "log", .value = str(r.log) };
        m[1] = .{ .key = "versionId", .value = str(r.version_id) };
        return .{ .object = m };
    }
    if (eq(u8, op, "witness")) {
        const r = log.witnessProof(a, try c.str(input, "versionId"), try c.seed(try c.str(input, "seed")), try c.optStr(input, "created")) catch |err| return mapLog(c, err);
        return single(a, "proof", r.value);
    }
    if (eq(u8, op, "resolve")) {
        return resolveOp(c, input);
    }
    return c.bad("unknown op {s}", .{op});
}

fn resolveOp(c: *Ctx, input: Value) OpError!Value {
    const a = c.a;
    const now_text = try c.str(input, "now");
    const now = time.parse(now_text) orelse return c.bad("input.now is not a valid timestamp", .{});
    var req: resolver.Request = .{
        .log = try c.str(input, "log"),
        .witness = witnessInput(input, "witness"),
        .now = now,
        .retained_version_id = try c.optStr(input, "retainedVersionId"),
    };
    switch (resolver.optionsFromJson(input.get("options"))) {
        .ok => |o| req.options = o,
        .invalid => |why| {
            const res: resolver.Resolution = .{
                .arena = undefined,
                .valid = false,
                .err = .{ .code = .invalid_option, .version = null, .message = why },
            };
            return res.toValue(a);
        },
    }
    if (input.get("copies")) |cv| if (cv != .null) {
        if (cv != .array) return c.bad("input.copies must be an array", .{});
        const copies = try a.alloc(resolver.CopyInput, cv.array.len);
        for (cv.array, copies) |item, *o| {
            if (item != .object) return c.bad("each copy must be an object", .{});
            o.* = .{ .source = try c.str(item, "source") };
            if (try c.optStr(item, "log")) |l| {
                o.log = l;
                o.witness = witnessInput(item, "witness");
            } else {
                o.unavailable = (try c.optStr(item, "unavailable")) orelse "unavailable";
            }
        }
        req.copies = copies;
    };
    const res = try resolver.resolve(a, req);
    return res.toValue(a);
}

/// Handles one request line and returns the response line (without the
/// trailing newline). Caller owns the result.
pub fn handle(gpa: Allocator, line: []const u8) Allocator.Error![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var c: Ctx = .{ .a = a };

    var id: Value = .null;
    const response: Value = blk: {
        const req = json.parse(a, line) catch break :blk try errorResponse(a, id, "request is not valid JSON");
        if (req.value != .object) break :blk try errorResponse(a, id, "request is not an object");
        id = req.value.get("id") orelse .null;
        const op = req.value.getString("op") orelse break :blk try errorResponse(a, id, "request has no op");
        const input = req.value.get("input") orelse Value{ .null = {} };
        const result = dispatch(&c, op, input) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadRequest => break :blk try errorResponse(a, id, c.message),
        };
        const m = try a.alloc(Member, 3);
        m[0] = .{ .key = "id", .value = id };
        m[1] = .{ .key = "ok", .value = .{ .bool = true } };
        m[2] = .{ .key = "result", .value = result };
        break :blk Value{ .object = m };
    };
    const text = json.stringify(a, response) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NonFinite => json.stringify(a, try errorResponse(a, id, "result contains a non-finite number")) catch return error.OutOfMemory,
    };
    return gpa.dupe(u8, text);
}

fn errorResponse(a: Allocator, id: Value, message: []const u8) Allocator.Error!Value {
    const m = try a.alloc(Member, 3);
    m[0] = .{ .key = "id", .value = id };
    m[1] = .{ .key = "ok", .value = .{ .bool = false } };
    m[2] = .{ .key = "error", .value = .{ .string = message } };
    return .{ .object = m };
}
