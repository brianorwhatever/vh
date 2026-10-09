//! A small JSON implementation with the control VH-Log needs:
//!
//! * numbers are IEEE-754 doubles (RFC 8785 / I-JSON); a number that overflows
//!   to infinity is rejected;
//! * duplicate object keys: the last value wins (it replaces the earlier value
//!   in place);
//! * strings are stored as WTF-8, so a lone surrogate escape such as "\ud800"
//!   survives parsing; the parser records that it saw one so callers that need
//!   I-JSON can reject it;
//! * object member order is preserved for ordinary serialisation, and
//!   `canonicalize` implements RFC 8785 (JCS), sorting keys by UTF-16 code units.

const std = @import("std");
const numfmt = @import("numfmt.zig");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

pub const Member = struct {
    key: []const u8,
    value: Value,
};

pub const Value = union(enum) {
    null,
    bool: bool,
    number: f64,
    string: []const u8,
    array: []Value,
    object: []Member,

    /// Looks up a member of an object. Returns null for non-objects.
    pub fn get(self: Value, key: []const u8) ?Value {
        if (self != .object) return null;
        for (self.object) |m| {
            if (std.mem.eql(u8, m.key, key)) return m.value;
        }
        return null;
    }

    pub fn getString(self: Value, key: []const u8) ?[]const u8 {
        const v = self.get(key) orelse return null;
        return if (v == .string) v.string else null;
    }

    pub fn isObject(self: Value) bool {
        return self == .object;
    }
};

pub const ParseError = error{
    /// Not valid JSON text (RFC 8259).
    InvalidJson,
    /// A number too large to be a finite double (e.g. 1e400).
    NumberOverflow,
    /// Nesting deeper than `max_depth`.
    TooDeep,
} || Allocator.Error;

pub const max_depth = 512;

pub const ParseResult = struct {
    value: Value,
    /// True if any string or key contained an unpaired surrogate escape.
    lone_surrogate: bool,
};

/// Parses `text` into values allocated with `allocator`. Use an arena: the
/// returned tree is not individually freeable.
pub fn parse(allocator: Allocator, text: []const u8) ParseError!ParseResult {
    var p: Parser = .{ .text = text, .alloc = allocator };
    p.skipWs();
    const v = try p.parseValue(0);
    p.skipWs();
    if (p.pos != text.len) return error.InvalidJson;
    return .{ .value = v, .lone_surrogate = p.lone_surrogate };
}

/// A parsed value that owns its memory.
pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    value: Value,
    lone_surrogate: bool,

    pub fn deinit(self: Parsed) void {
        const child = self.arena.child_allocator;
        self.arena.deinit();
        child.destroy(self.arena);
    }
};

pub fn parseOwned(gpa: Allocator, text: []const u8) ParseError!Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = .init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const r = try parse(arena.allocator(), text);
    return .{ .arena = arena, .value = r.value, .lone_surrogate = r.lone_surrogate };
}

const Parser = struct {
    text: []const u8,
    pos: usize = 0,
    alloc: Allocator,
    lone_surrogate: bool = false,

    fn skipWs(p: *Parser) void {
        while (p.pos < p.text.len) : (p.pos += 1) {
            switch (p.text[p.pos]) {
                ' ', '\t', '\n', '\r' => {},
                else => return,
            }
        }
    }

    fn literal(p: *Parser, word: []const u8) ParseError!void {
        if (!std.mem.startsWith(u8, p.text[p.pos..], word)) return error.InvalidJson;
        p.pos += word.len;
    }

    fn parseValue(p: *Parser, depth: usize) ParseError!Value {
        if (depth > max_depth) return error.TooDeep;
        if (p.pos >= p.text.len) return error.InvalidJson;
        switch (p.text[p.pos]) {
            'n' => {
                try p.literal("null");
                return .null;
            },
            't' => {
                try p.literal("true");
                return .{ .bool = true };
            },
            'f' => {
                try p.literal("false");
                return .{ .bool = false };
            },
            '"' => return .{ .string = try p.parseString() },
            '[' => return p.parseArray(depth),
            '{' => return p.parseObject(depth),
            '-', '0'...'9' => return .{ .number = try p.parseNumber() },
            else => return error.InvalidJson,
        }
    }

    fn parseArray(p: *Parser, depth: usize) ParseError!Value {
        p.pos += 1; // [
        var items: std.ArrayList(Value) = .empty;
        p.skipWs();
        if (p.pos < p.text.len and p.text[p.pos] == ']') {
            p.pos += 1;
            return .{ .array = try items.toOwnedSlice(p.alloc) };
        }
        while (true) {
            p.skipWs();
            try items.append(p.alloc, try p.parseValue(depth + 1));
            p.skipWs();
            if (p.pos >= p.text.len) return error.InvalidJson;
            const c = p.text[p.pos];
            p.pos += 1;
            if (c == ']') break;
            if (c != ',') return error.InvalidJson;
        }
        return .{ .array = try items.toOwnedSlice(p.alloc) };
    }

    fn parseObject(p: *Parser, depth: usize) ParseError!Value {
        p.pos += 1; // {
        var members: std.ArrayList(Member) = .empty;
        p.skipWs();
        if (p.pos < p.text.len and p.text[p.pos] == '}') {
            p.pos += 1;
            return .{ .object = try members.toOwnedSlice(p.alloc) };
        }
        while (true) {
            p.skipWs();
            if (p.pos >= p.text.len or p.text[p.pos] != '"') return error.InvalidJson;
            const key = try p.parseString();
            p.skipWs();
            if (p.pos >= p.text.len or p.text[p.pos] != ':') return error.InvalidJson;
            p.pos += 1;
            p.skipWs();
            const value = try p.parseValue(depth + 1);
            // Duplicate key: the last value wins.
            var replaced = false;
            for (members.items) |*m| {
                if (std.mem.eql(u8, m.key, key)) {
                    m.value = value;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) try members.append(p.alloc, .{ .key = key, .value = value });
            p.skipWs();
            if (p.pos >= p.text.len) return error.InvalidJson;
            const c = p.text[p.pos];
            p.pos += 1;
            if (c == '}') break;
            if (c != ',') return error.InvalidJson;
        }
        return .{ .object = try members.toOwnedSlice(p.alloc) };
    }

    fn parseNumber(p: *Parser) ParseError!f64 {
        const start = p.pos;
        const t = p.text;
        if (p.pos < t.len and t[p.pos] == '-') p.pos += 1;
        if (p.pos >= t.len) return error.InvalidJson;
        if (t[p.pos] == '0') {
            p.pos += 1;
        } else if (t[p.pos] >= '1' and t[p.pos] <= '9') {
            while (p.pos < t.len and std.ascii.isDigit(t[p.pos])) p.pos += 1;
        } else return error.InvalidJson;
        if (p.pos < t.len and t[p.pos] == '.') {
            p.pos += 1;
            const s = p.pos;
            while (p.pos < t.len and std.ascii.isDigit(t[p.pos])) p.pos += 1;
            if (p.pos == s) return error.InvalidJson;
        }
        if (p.pos < t.len and (t[p.pos] == 'e' or t[p.pos] == 'E')) {
            p.pos += 1;
            if (p.pos < t.len and (t[p.pos] == '+' or t[p.pos] == '-')) p.pos += 1;
            const s = p.pos;
            while (p.pos < t.len and std.ascii.isDigit(t[p.pos])) p.pos += 1;
            if (p.pos == s) return error.InvalidJson;
        }
        const x = std.fmt.parseFloat(f64, t[start..p.pos]) catch return error.InvalidJson;
        if (!std.math.isFinite(x)) return error.NumberOverflow;
        return x;
    }

    fn hex4(p: *Parser) ParseError!u16 {
        if (p.pos + 4 > p.text.len) return error.InvalidJson;
        const v = std.fmt.parseInt(u16, p.text[p.pos..][0..4], 16) catch return error.InvalidJson;
        // parseInt accepts a leading '+'; JSON does not.
        for (p.text[p.pos..][0..4]) |c| if (!std.ascii.isHex(c)) return error.InvalidJson;
        p.pos += 4;
        return v;
    }

    fn parseString(p: *Parser) ParseError![]const u8 {
        p.pos += 1; // opening quote
        const t = p.text;
        // Fast path: no escapes.
        var i = p.pos;
        while (i < t.len and t[i] != '"' and t[i] != '\\' and t[i] >= 0x20) i += 1;
        if (i < t.len and t[i] == '"') {
            const s = t[p.pos..i];
            if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidJson;
            p.pos = i + 1;
            return s;
        }
        var out: std.ArrayList(u8) = .empty;
        while (true) {
            if (p.pos >= t.len) return error.InvalidJson;
            const c = t[p.pos];
            if (c == '"') {
                p.pos += 1;
                break;
            }
            if (c < 0x20) return error.InvalidJson;
            if (c != '\\') {
                if (c < 0x80) {
                    try out.append(p.alloc, c);
                    p.pos += 1;
                } else {
                    const n = std.unicode.utf8ByteSequenceLength(c) catch return error.InvalidJson;
                    if (p.pos + n > t.len) return error.InvalidJson;
                    const seq = t[p.pos..][0..n];
                    _ = std.unicode.utf8Decode(seq) catch return error.InvalidJson;
                    try out.appendSlice(p.alloc, seq);
                    p.pos += n;
                }
                continue;
            }
            p.pos += 1;
            if (p.pos >= t.len) return error.InvalidJson;
            const e = t[p.pos];
            p.pos += 1;
            switch (e) {
                '"' => try out.append(p.alloc, '"'),
                '\\' => try out.append(p.alloc, '\\'),
                '/' => try out.append(p.alloc, '/'),
                'b' => try out.append(p.alloc, 0x08),
                'f' => try out.append(p.alloc, 0x0c),
                'n' => try out.append(p.alloc, '\n'),
                'r' => try out.append(p.alloc, '\r'),
                't' => try out.append(p.alloc, '\t'),
                'u' => {
                    const u = try p.hex4();
                    var cp: u21 = u;
                    if (u >= 0xD800 and u <= 0xDBFF) {
                        // High surrogate: pair with a following \uDC00-\uDFFF if present.
                        if (p.pos + 6 <= t.len and t[p.pos] == '\\' and t[p.pos + 1] == 'u') {
                            const save = p.pos;
                            p.pos += 2;
                            const lo = try p.hex4();
                            if (lo >= 0xDC00 and lo <= 0xDFFF) {
                                cp = 0x10000 + ((@as(u21, u) - 0xD800) << 10) + (lo - 0xDC00);
                            } else {
                                p.pos = save;
                                p.lone_surrogate = true;
                            }
                        } else p.lone_surrogate = true;
                    } else if (u >= 0xDC00 and u <= 0xDFFF) {
                        p.lone_surrogate = true;
                    }
                    var buf: [4]u8 = undefined;
                    const n = encodeWtf8(cp, &buf);
                    try out.appendSlice(p.alloc, buf[0..n]);
                },
                else => return error.InvalidJson,
            }
        }
        return out.toOwnedSlice(p.alloc);
    }
};

/// UTF-8 encoding that also encodes surrogate code points (WTF-8).
fn encodeWtf8(cp: u21, buf: *[4]u8) usize {
    if (cp < 0x80) {
        buf[0] = @intCast(cp);
        return 1;
    } else if (cp < 0x800) {
        buf[0] = @intCast(0xC0 | (cp >> 6));
        buf[1] = @intCast(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        buf[0] = @intCast(0xE0 | (cp >> 12));
        buf[1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = @intCast(0x80 | (cp & 0x3F));
        return 3;
    } else {
        buf[0] = @intCast(0xF0 | (cp >> 18));
        buf[1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
        buf[2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        buf[3] = @intCast(0x80 | (cp & 0x3F));
        return 4;
    }
}

/// Decodes one WTF-8 code point at `s[i]`, returning it and its byte length.
fn decodeWtf8(s: []const u8, i: usize) struct { cp: u21, len: usize } {
    const c = s[i];
    if (c < 0x80) return .{ .cp = c, .len = 1 };
    if (c < 0xE0) return .{ .cp = (@as(u21, c & 0x1F) << 6) | (s[i + 1] & 0x3F), .len = 2 };
    if (c < 0xF0) return .{
        .cp = (@as(u21, c & 0x0F) << 12) | (@as(u21, s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F),
        .len = 3,
    };
    return .{
        .cp = (@as(u21, c & 0x07) << 18) | (@as(u21, s[i + 1] & 0x3F) << 12) |
            (@as(u21, s[i + 2] & 0x3F) << 6) | (s[i + 3] & 0x3F),
        .len = 4,
    };
}

// ------------------------------------------------------------------ output

pub const WriteError = Writer.Error || numfmt.Error;

pub const Mode = enum {
    /// Members in their stored order (compact JSON).
    compact,
    /// RFC 8785: members sorted by UTF-16 code units.
    canonical,
};

/// Writes a JSON string literal using the ECMAScript JSON.stringify escaping
/// rules that RFC 8785 §3.2.2.2 adopts. Lone surrogates are written as \uXXXX
/// escapes (as well-formed JSON.stringify does).
pub fn writeString(w: *Writer, s: []const u8) Writer.Error!void {
    try w.writeByte('"');
    var i: usize = 0;
    var run: usize = 0;
    while (i < s.len) {
        const c = s[i];
        var esc: ?[]const u8 = null;
        var tmp: [6]u8 = undefined;
        var adv: usize = 1;
        switch (c) {
            '"' => esc = "\\\"",
            '\\' => esc = "\\\\",
            0x08 => esc = "\\b",
            0x0c => esc = "\\f",
            '\n' => esc = "\\n",
            '\r' => esc = "\\r",
            '\t' => esc = "\\t",
            0x00...0x07, 0x0b, 0x0e...0x1f => {
                esc = std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{c}) catch unreachable;
            },
            0xED => {
                // Possibly a WTF-8 encoded surrogate (ED A0..BF xx).
                if (i + 2 < s.len and s[i + 1] >= 0xA0) {
                    const d = decodeWtf8(s, i);
                    esc = std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{d.cp}) catch unreachable;
                    adv = 3;
                }
            },
            else => {},
        }
        if (esc) |e| {
            try w.writeAll(s[run..i]);
            try w.writeAll(e);
            i += adv;
            run = i;
        } else i += 1;
    }
    try w.writeAll(s[run..]);
    try w.writeByte('"');
}

pub fn writeNumber(w: *Writer, x: f64) WriteError!void {
    var buf: [numfmt.max_len]u8 = undefined;
    try w.writeAll(try numfmt.format(&buf, x));
}

/// Compares two WTF-8 strings by their UTF-16 code units (RFC 8785 §3.2.3).
pub fn lessThanUtf16(a: []const u8, b: []const u8) bool {
    var ia: usize = 0;
    var ib: usize = 0;
    var pend_a: ?u16 = null;
    var pend_b: ?u16 = null;
    while (true) {
        const ua = nextUnit(a, &ia, &pend_a);
        const ub = nextUnit(b, &ib, &pend_b);
        if (ua == null) return ub != null;
        if (ub == null) return false;
        if (ua.? != ub.?) return ua.? < ub.?;
    }
}

fn nextUnit(s: []const u8, i: *usize, pending: *?u16) ?u16 {
    if (pending.*) |u| {
        pending.* = null;
        return u;
    }
    if (i.* >= s.len) return null;
    const d = decodeWtf8(s, i.*);
    i.* += d.len;
    if (d.cp >= 0x10000) {
        const v = d.cp - 0x10000;
        pending.* = @intCast(0xDC00 + (v & 0x3FF));
        return @intCast(0xD800 + (v >> 10));
    }
    return @intCast(d.cp);
}

fn memberLess(_: void, a: Member, b: Member) bool {
    return lessThanUtf16(a.key, b.key);
}

/// Serialises `v`. In canonical mode a scratch allocator is needed to sort keys.
pub fn write(w: *Writer, v: Value, mode: Mode, scratch: Allocator) (WriteError || Allocator.Error)!void {
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .number => |x| try writeNumber(w, x),
        .string => |s| try writeString(w, s),
        .array => |items| {
            try w.writeByte('[');
            for (items, 0..) |item, i| {
                if (i > 0) try w.writeByte(',');
                try write(w, item, mode, scratch);
            }
            try w.writeByte(']');
        },
        .object => |members| {
            var ordered = members;
            var owned: ?[]Member = null;
            defer if (owned) |o| scratch.free(o);
            if (mode == .canonical and members.len > 1) {
                const copy = try scratch.dupe(Member, members);
                std.mem.sort(Member, copy, {}, memberLess);
                owned = copy;
                ordered = copy;
            }
            try w.writeByte('{');
            for (ordered, 0..) |m, i| {
                if (i > 0) try w.writeByte(',');
                try writeString(w, m.key);
                try w.writeByte(':');
                try write(w, m.value, mode, scratch);
            }
            try w.writeByte('}');
        },
    }
}

pub const StringifyError = numfmt.Error || Allocator.Error;

fn toString(allocator: Allocator, v: Value, mode: Mode) StringifyError![]u8 {
    var aw: Writer.Allocating = .init(allocator);
    defer aw.deinit();
    write(&aw.writer, v, mode, allocator) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => |e| return e,
    };
    return aw.toOwnedSlice();
}

/// RFC 8785 canonical form. Caller owns the result.
pub fn canonicalize(allocator: Allocator, v: Value) StringifyError![]u8 {
    return toString(allocator, v, .canonical);
}

/// Compact JSON with members in stored order. Caller owns the result.
pub fn stringify(allocator: Allocator, v: Value) StringifyError![]u8 {
    return toString(allocator, v, .compact);
}

/// Parses `text` and returns its canonical form. Caller owns the result.
pub fn canonicalizeText(gpa: Allocator, text: []const u8) (ParseError || StringifyError)![]u8 {
    const p = try parseOwned(gpa, text);
    defer p.deinit();
    return canonicalize(gpa, p.value);
}

// ------------------------------------------------------------------ building

/// Returns a copy of the object `v` without member `key` (shallow).
pub fn without(allocator: Allocator, v: Value, key: []const u8) Allocator.Error!Value {
    var out: std.ArrayList(Member) = .empty;
    for (v.object) |m| {
        if (!std.mem.eql(u8, m.key, key)) try out.append(allocator, m);
    }
    return .{ .object = try out.toOwnedSlice(allocator) };
}

/// Returns a copy of the object `v` with member `key` set to `value` (replaced
/// in place, or appended).
pub fn with(allocator: Allocator, v: Value, key: []const u8, value: Value) Allocator.Error!Value {
    var out: std.ArrayList(Member) = .empty;
    var found = false;
    for (v.object) |m| {
        if (std.mem.eql(u8, m.key, key)) {
            try out.append(allocator, .{ .key = key, .value = value });
            found = true;
        } else try out.append(allocator, m);
    }
    if (!found) try out.append(allocator, .{ .key = key, .value = value });
    return .{ .object = try out.toOwnedSlice(allocator) };
}

/// Deep copy into `allocator`.
pub fn clone(allocator: Allocator, v: Value) Allocator.Error!Value {
    return switch (v) {
        .null, .bool, .number => v,
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .array => |items| blk: {
            const out = try allocator.alloc(Value, items.len);
            for (items, out) |item, *o| o.* = try clone(allocator, item);
            break :blk .{ .array = out };
        },
        .object => |members| blk: {
            const out = try allocator.alloc(Member, members.len);
            for (members, out) |m, *o| o.* = .{ .key = try allocator.dupe(u8, m.key), .value = try clone(allocator, m.value) };
            break :blk .{ .object = out };
        },
    };
}

/// Structural equality (numbers compared as doubles, object members unordered).
pub fn eql(a: Value, b: Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .number => |x| x == b.number,
        .string => |s| std.mem.eql(u8, s, b.string),
        .array => |items| items.len == b.array.len and for (items, b.array) |x, y| {
            if (!eql(x, y)) break false;
        } else true,
        .object => |ms| ms.len == b.object.len and for (ms) |m| {
            const other = b.get(m.key) orelse break false;
            if (!eql(m.value, other)) break false;
        } else true,
    };
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn expectJcs(text: []const u8, want: []const u8) !void {
    const got = try canonicalizeText(testing.allocator, text);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "jcs basics" {
    try expectJcs("{\"b\": 1, \"a\": [true, null, false]}", "{\"a\":[true,null,false],\"b\":1}");
    try expectJcs("\"top\"", "\"top\"");
    try expectJcs(" [1,[2,[3]],{}] ", "[1,[2,[3]],{}]");
    try expectJcs("{\"a\":1,\"a\":2}", "{\"a\":2}");
    try expectJcs("{\"s\":\"\\u0001\\u001f\\b\\/\"}", "{\"s\":\"\\u0001\\u001f\\b/\"}");
}

test "jcs key order is by UTF-16 code units" {
    // U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16, after it by code point.
    try expectJcs("{\"\\ufb33\":1,\"\\ud83d\\ude00\":2}", "{\"\u{1F600}\":2,\"\u{FB33}\":1}");
}

test "parser rejects invalid JSON and flags I-JSON violations" {
    const a = testing.allocator;
    const bad = [_][]const u8{ "", "{", "[1,]", "01", "1.", "+1", "{\"a\" 1}", "\"\x01\"", "nul", "\"\\x\"", "1 2", "\"\\u12G4\"" };
    for (bad) |t| try testing.expectError(error.InvalidJson, parseOwned(a, t));
    try testing.expectError(error.NumberOverflow, parseOwned(a, "1e400"));
    const p = try parseOwned(a, "{\"\\ud800\":\"x\"}");
    defer p.deinit();
    try testing.expect(p.lone_surrogate);
    const q = try parseOwned(a, "\"\\ud83d\\ude00\"");
    defer q.deinit();
    try testing.expect(!q.lone_surrogate);
    try testing.expectEqualStrings("\u{1F600}", q.value.string);
}

test "lone surrogates round-trip as escapes" {
    try expectJcs("\"a\\udc00b\"", "\"a\\udc00b\"");
}
