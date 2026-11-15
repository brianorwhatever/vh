//! did:vh (docs/didvh-profile.md) on top of the VH-Log code: DIDs,
//! create/update, `srcLog`/`srcWitness` references, the `src` DID URL
//! parameter, DID URLs and offline resolution.
//!
//! Functions that take `a` allocate everything they return in it and never
//! free: pass an arena.

const std = @import("std");
const json = @import("json.zig");
const log = @import("log.zig");
const time = @import("time.zig");
const resolver = @import("resolve.zig");
const Allocator = std.mem.Allocator;
const Value = json.Value;
const Member = json.Member;

pub const prefix = "did:vh:";
pub const method_version = "did:vh:1.0";
const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ------------------------------------------------------------------ the DID (§2)

/// The SCID of a did:vh DID (`did:vh:` and 46 base58btc characters), or null.
pub fn parseDid(did: []const u8) ?[]const u8 {
    if (did.len != prefix.len + 46 or !std.mem.startsWith(u8, did, prefix)) return null;
    const scid = did[prefix.len..];
    for (scid) |c| if (std.mem.indexOfScalar(u8, base58_alphabet, c) == null) return null;
    return scid;
}

/// A non-negative decimal integer with no leading zeros.
fn decimal(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return s.len == 1 or s[0] != '0';
}

/// `did:vh:<major>.<minor>` (§1).
pub fn validMethod(v: []const u8) bool {
    if (!std.mem.startsWith(u8, v, prefix)) return false;
    const rest = v[prefix.len..];
    const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return false;
    return decimal(rest[0..dot]) and decimal(rest[dot + 1 ..]);
}

fn checkState(context: ?*const anyopaque, a: Allocator, state: Value, scid: []const u8) Allocator.Error!?[]const u8 {
    if (context) |ctx| {
        const did_scid: *const []const u8 = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, did_scid.*, scid))
            return try std.fmt.allocPrint(a, "the log's SCID {s} is not the DID's {s}", .{ scid, did_scid.* });
    }
    const want = try std.mem.concat(a, u8, &.{ prefix, scid });
    const id = state.getString("id") orelse "";
    if (!std.mem.eql(u8, id, want)) return try std.fmt.allocPrint(a, "state.id must be {s}", .{want});
    return null;
}

/// The did:vh specialisation of VH-Log (§1). With `did_scid`, which must
/// outlive the resolution, the log's SCID must also equal the DID's.
pub fn specialisation(did_scid: ?*const []const u8) resolver.Specialisation {
    return .{
        .version_parameter = "method",
        .versions = &.{method_version},
        .version_syntax = validMethod,
        .closed = true,
        .state_check = .{ .context = if (did_scid) |p| @ptrCast(p) else null, .func = checkState },
    };
}

// ------------------------------------------------------------------ create / update

pub const CreateInput = struct {
    /// The DID document, with `did:vh:{SCID}` for the DID.
    document: Value,
    parameters: Value,
    version_time: []const u8,
    signers: []const [32]u8,
};

pub const Created = struct {
    created: log.Created,
    did: []const u8,

    pub fn deinit(self: Created) void {
        self.created.deinit();
    }
};

/// Creates a did:vh DID: `method` and `scid` are added to the parameters
/// when absent.
pub fn create(gpa: Allocator, input: CreateInput) log.Error!Created {
    const c = try log.create(gpa, .{
        .state = input.document,
        .parameters = input.parameters,
        .version_time = input.version_time,
        .signers = input.signers,
        .version_parameter = "method",
        .version = method_version,
    });
    errdefer c.deinit();
    return .{ .created = c, .did = try std.mem.concat(c.arena.allocator(), u8, &.{ prefix, c.scid }) };
}

pub const UpdateInput = struct {
    document: Value,
    parameters: Value,
    version_time: []const u8,
    signers: []const [32]u8,
};

/// Appends a did:vh entry (an update, or a deactivation with
/// `{"deactivated": true}`).
pub fn update(gpa: Allocator, log_text: []const u8, input: UpdateInput) log.Error!log.Updated {
    return log.update(gpa, log_text, .{
        .state = input.document,
        .parameters = input.parameters,
        .version_time = input.version_time,
        .signers = input.signers,
    });
}

// ------------------------------------------------------------------ percent-decoding

/// Percent-decodes `s` once as UTF-8 (`+` stays `+`). Null for a malformed
/// escape or invalid UTF-8.
pub fn percentDecode(a: Allocator, s: []const u8) Allocator.Error!?[]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%') {
            if (i + 3 > s.len or !std.ascii.isHex(s[i + 1]) or !std.ascii.isHex(s[i + 2])) return null;
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch unreachable;
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch unreachable;
            try out.append(a, hi * 16 + lo);
            i += 3;
        } else {
            try out.append(a, s[i]);
            i += 1;
        }
    }
    if (!std.unicode.utf8ValidateSlice(out.items)) return null;
    return out.items;
}

// ------------------------------------------------------------------ references (§3)

fn printableAscii(s: []const u8) bool {
    for (s) |c| if (c < 0x21 or c > 0x7e) return false;
    return true;
}

const Scheme = struct {
    /// The scheme in lowercase.
    name: []const u8,
    /// Everything after the `:`.
    rest: []const u8,
};

/// `[A-Za-z][A-Za-z0-9+.-]*:`.
fn splitScheme(a: Allocator, s: []const u8) Allocator.Error!?Scheme {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    if (colon == 0 or !std.ascii.isAlphabetic(s[0])) return null;
    for (s[0..colon]) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '.' or c == '-')) return null;
    }
    return .{ .name = try std.ascii.allocLowerString(a, s[0..colon]), .rest = s[colon + 1 ..] };
}

/// An optional trailing dot, then 1–253 characters of LDH labels; the last
/// label is not all digits.
fn domainName(host_in: []const u8) bool {
    const host = if (std.mem.endsWith(u8, host_in, ".")) host_in[0 .. host_in.len - 1] else host_in;
    if (host.len < 1 or host.len > 253) return false;
    var last: []const u8 = "";
    var it = std.mem.splitScalar(u8, host, '.');
    while (it.next()) |label| {
        if (label.len < 1 or label.len > 63) return false;
        for (label) |c| if (!((c >= 'a' and c <= 'z') or std.ascii.isDigit(c) or c == '-')) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        last = label;
    }
    for (last) |c| if (!std.ascii.isDigit(c)) return true;
    return false;
}

fn loopbackHost(host: []const u8) bool {
    if (std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "[::1]")) return true;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, host, '.');
    while (it.next()) |octet| : (count += 1) {
        if (count == 4 or octet.len < 1 or octet.len > 3 or !decimal(octet)) return false;
        const n = std.fmt.parseInt(u16, octet, 10) catch return false;
        if (n > 255) return false;
        if (count == 0 and n != 127) return false;
    }
    return count == 4;
}

/// The lowercase host of an authority (`host[:port]` or `[literal][:port]`),
/// or null if it has userinfo or a bad port.
fn authorityHost(a: Allocator, authority: []const u8) Allocator.Error!?[]const u8 {
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return null;
    var host: []const u8 = authority;
    var port: ?[]const u8 = null;
    if (std.mem.startsWith(u8, authority, "[")) {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        host = authority[0 .. close + 1];
        const after = authority[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return null;
            port = after[1..];
        }
    } else if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = authority[colon + 1 ..];
    }
    if (port) |p| {
        if (p.len < 1 or p.len > 5) return null;
        for (p) |c| if (!std.ascii.isDigit(c)) return null;
        if ((std.fmt.parseInt(u32, p, 10) catch return null) > 65535) return null;
    }
    return try std.ascii.allocLowerString(a, host);
}

/// §3.1 step 4: a path segment, decoded, is not `.` or `..` and has no `/`,
/// `\` or NUL.
fn referenceSegment(a: Allocator, segment: []const u8) Allocator.Error!bool {
    const d = (try percentDecode(a, segment)) orelse return false;
    if (std.mem.eql(u8, d, ".") or std.mem.eql(u8, d, "..")) return false;
    return std.mem.indexOfAny(u8, d, "/\\\x00") == null;
}

/// Checks each segment of a path that starts with `/`.
fn referencePath(a: Allocator, path: []const u8) Allocator.Error!bool {
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |segment| if (!try referenceSegment(a, segment)) return false;
    return true;
}

pub const Kind = enum { web, loopback, file, other };

/// Checks a `srcLog` or `srcWitness` reference (§3.1): its kind, or null if
/// it is invalid (`invalidOptions`).
pub fn referenceKind(a: Allocator, ref: []const u8) Allocator.Error!?Kind {
    if (!printableAscii(ref) or std.mem.indexOfScalar(u8, ref, '#') != null) return null;
    const scheme = (try splitScheme(a, ref)) orelse return null;
    const eq = std.mem.eql;
    if (eq(u8, scheme.name, "https") or eq(u8, scheme.name, "http")) {
        if (!std.mem.startsWith(u8, scheme.rest, "//")) return null;
        const rest = scheme.rest[2..];
        const end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
        const host = (try authorityHost(a, rest[0..end])) orelse return null;
        const path = rest[end .. std.mem.indexOfScalar(u8, rest, '?') orelse rest.len];
        const web = eq(u8, scheme.name, "https");
        if (!(if (web) domainName(host) else loopbackHost(host))) return null;
        if (path.len == 0 or !try referencePath(a, path)) return null;
        return if (web) .web else .loopback;
    }
    if (eq(u8, scheme.name, "file")) {
        const rest = scheme.rest;
        if (std.mem.indexOfScalar(u8, rest, '?') != null) return null;
        var path: []const u8 = undefined;
        if (std.mem.startsWith(u8, rest, "//")) {
            const slash = std.mem.indexOfScalarPos(u8, rest, 2, '/') orelse return null;
            const host = rest[2..slash];
            if (host.len != 0 and !std.ascii.eqlIgnoreCase(host, "localhost")) return null;
            path = rest[slash..];
        } else if (std.mem.startsWith(u8, rest, "/")) {
            path = rest;
        } else return null;
        return if (try referencePath(a, path)) .file else null;
    }
    return if (scheme.rest.len > 0) .other else null;
}

fn whiteSpace(cp: u21) bool {
    return switch (cp) {
        0x09...0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

/// §3.2 step 5: a non-empty segment that passes §3.1's rules and doesn't
/// start or end with White_Space once decoded.
fn srcSegment(a: Allocator, segment: []const u8) Allocator.Error!bool {
    if (segment.len == 0 or !try referenceSegment(a, segment)) return false;
    const d = (try percentDecode(a, segment)).?;
    const first_len = std.unicode.utf8ByteSequenceLength(d[0]) catch return false;
    const first = std.unicode.utf8Decode(d[0..first_len]) catch return false;
    var start = d.len - 1;
    while (start > 0 and d[start] & 0xc0 == 0x80) start -= 1;
    const last = std.unicode.utf8Decode(d[start..]) catch return false;
    return !whiteSpace(first) and !whiteSpace(last);
}

pub const SrcReferences = struct {
    src_log: []const u8,
    src_witness: []const u8,
};

/// Derives `srcLog` and `srcWitness` from a percent-decoded `src` DID URL
/// parameter (§3.2), or null if it is invalid (`invalidDidUrl`).
pub fn srcReferences(a: Allocator, src: []const u8) Allocator.Error!?SrcReferences {
    if (!printableAscii(src) or std.mem.indexOfAny(u8, src, "?#") != null) return null;
    const scheme = (try splitScheme(a, src)) orelse return null;
    if (std.mem.eql(u8, scheme.name, "http") or std.mem.eql(u8, scheme.name, "file")) return null;
    if (!std.mem.startsWith(u8, scheme.rest, "//")) return null;
    const rest = if (std.mem.endsWith(u8, scheme.rest, "/")) scheme.rest[0 .. scheme.rest.len - 1] else scheme.rest;
    const slash = if (rest.len > 2) std.mem.indexOfScalarPos(u8, rest, 2, '/') else null;
    const end = slash orelse rest.len;
    if (end <= 2) return null; // empty authority
    if (std.mem.eql(u8, scheme.name, "https")) {
        const host = (try authorityHost(a, rest[2..end])) orelse return null;
        if (!domainName(host)) return null;
        if (end < rest.len) {
            var it = std.mem.splitScalar(u8, rest[end + 1 ..], '/');
            while (it.next()) |segment| if (!try srcSegment(a, segment)) return null;
        }
    }
    return .{
        .src_log = try std.mem.concat(a, u8, &.{ scheme.name, ":", rest, "/did.jsonl" }),
        .src_witness = try std.mem.concat(a, u8, &.{ scheme.name, ":", rest, "/did-witness.json" }),
    };
}

// ------------------------------------------------------------------ DID URLs (§4)

pub const DidUrl = struct {
    did: []const u8,
    /// Resolution options, a JSON object.
    options: Value,
    /// Null when the DID URL has no `#`.
    fragment: ?[]const u8,
};

const reserved_options = [_][]const u8{ "didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog" };
const used_parameters = [_][]const u8{ "src", "versionId", "versionTime", "versionNumber" };

fn member(list: []const []const u8, name: []const u8) bool {
    for (list) |item| if (std.mem.eql(u8, item, name)) return true;
    return false;
}

/// Dereferences a did:vh DID URL into a DID, resolution options and a
/// fragment (§4), or null if it is invalid (`invalidDidUrl`).
pub fn parseDidUrl(a: Allocator, url: []const u8) Allocator.Error!?DidUrl {
    const hash = std.mem.indexOfScalar(u8, url, '#');
    const before = url[0 .. hash orelse url.len];
    const question = std.mem.indexOfScalar(u8, before, '?');
    const did = before[0 .. question orelse before.len];
    if (parseDid(did) == null) return null;
    var options: Value = .{ .object = &.{} };
    if (question) |q| {
        var seen: [used_parameters.len]bool = @splat(false);
        var it = std.mem.splitScalar(u8, before[q + 1 ..], '&');
        while (it.next()) |part| {
            const eq = std.mem.indexOfScalar(u8, part, '=') orelse return null;
            const name = (try percentDecode(a, part[0..eq])) orelse return null;
            const value = (try percentDecode(a, part[eq + 1 ..])) orelse return null;
            if (member(&reserved_options, name)) return null;
            const index = for (used_parameters, 0..) |p, i| {
                if (std.mem.eql(u8, p, name)) break i;
            } else continue;
            if (seen[index]) return null;
            seen[index] = true;
            if (std.mem.eql(u8, name, "src")) {
                const refs = (try srcReferences(a, value)) orelse return null;
                options = try json.with(a, options, "srcLog", .{ .string = refs.src_log });
                options = try json.with(a, options, "srcWitness", .{ .string = refs.src_witness });
            } else if (std.mem.eql(u8, name, "versionNumber")) {
                if (value.len > 16 or value.len == 0 or value[0] == '0') return null;
                for (value) |c| if (!std.ascii.isDigit(c)) return null;
                const n = std.fmt.parseInt(u64, value, 10) catch return null;
                options = try json.with(a, options, "versionNumber", .{ .number = @floatFromInt(n) });
            } else {
                options = try json.with(a, options, name, .{ .string = value });
            }
        }
    }
    return .{ .did = did, .options = options, .fragment = if (hash) |h| url[h + 1 ..] else null };
}

// ------------------------------------------------------------------ resolution (§5)

pub const ResolveContext = struct {
    /// The resolver's current time (seconds since the epoch).
    now: i64,
    /// Whether the resolver serves other systems.
    remote: bool = false,
};

fn object(a: Allocator, members: []const Member) Allocator.Error!Value {
    return .{ .object = try a.dupe(Member, members) };
}

fn failure(a: Allocator, code: []const u8, detail: []const u8, vh_log: ?Value) Allocator.Error!Value {
    const problem = if (vh_log) |v|
        try object(a, &.{ .{ .key = "title", .value = .{ .string = code } }, .{ .key = "detail", .value = .{ .string = detail } }, .{ .key = "vhLog", .value = v } })
    else
        try object(a, &.{ .{ .key = "title", .value = .{ .string = code } }, .{ .key = "detail", .value = .{ .string = detail } } });
    return object(a, &.{
        .{ .key = "didResolutionMetadata", .value = try object(a, &.{ .{ .key = "error", .value = .{ .string = code } }, .{ .key = "problemDetails", .value = problem } }) },
        .{ .key = "didDocument", .value = .null },
        .{ .key = "didDocumentMetadata", .value = .{ .object = &.{} } },
    });
}

fn didErrorCode(code: resolver.ErrorCode) []const u8 {
    return switch (code) {
        .not_found => "notFound",
        .invalid_option => "invalidOptions",
        .unsupported_log_version => "featureNotSupported",
        .fork_detected => "logForked",
        .min_copies_not_met => "insufficientCopies",
        else => "invalidDid",
    };
}

fn integer(v: Value, min: f64) ?u64 {
    if (v != .number) return null;
    const x = v.number;
    if (x != @floor(x) or x < min or x > 9007199254740991.0) return null;
    return @intFromFloat(x);
}

/// True if some entry among `values` sets a non-empty witness list.
fn needsWitnessing(values: []const ?Value) bool {
    for (values) |line| {
        const v = line orelse continue;
        const params = v.get("parameters") orelse continue;
        const w = params.get("witness") orelse continue;
        if (w == .object and w.object.len > 0) return true;
    }
    return false;
}

fn extraWatcher(v: Value) bool {
    return v == .string and std.mem.startsWith(u8, v.string, "https://") and resolver.validWatcherUrl(v.string);
}

/// Resolves a did:vh DID offline (§5), with the log in the `didLog` option.
/// Returns `{didResolutionMetadata, didDocument, didDocumentMetadata}`.
pub fn resolve(a: Allocator, did_value: Value, options: Value, ctx: ResolveContext) Allocator.Error!Value {
    // 1. The DID.
    const did = if (did_value == .string) did_value.string else "";
    const scid_slot = try a.create([]const u8);
    scid_slot.* = parseDid(did) orelse return failure(a, "invalidDid", "not a did:vh DID", null);

    // 2. The options.
    if (options != .object) return failure(a, "invalidOptions", "the resolution options must be an object", null);
    const has = struct {
        fn f(o: Value, key: []const u8) bool {
            return o.get(key) != null;
        }
    }.f;
    const bad = "invalidOptions";
    if (has(options, "didLog") == has(options, "srcLog"))
        return failure(a, bad, "exactly one of didLog and srcLog is required", null);
    if (has(options, "didWitness") and has(options, "srcWitness"))
        return failure(a, bad, "at most one of didWitness and srcWitness", null);
    if (options.get("didLog")) |v| if (v != .string) return failure(a, bad, "didLog must be a string", null);
    if (options.get("didWitness")) |v| if (v != .array) return failure(a, bad, "didWitness must be an array", null);
    for ([_][]const u8{ "srcLog", "srcWitness" }) |key| if (options.get(key)) |v| {
        const kind = (if (v == .string) try referenceKind(a, v.string) else null) orelse
            return failure(a, bad, try std.fmt.allocPrint(a, "{s} is not a valid reference", .{key}), null);
        if (ctx.remote and (kind == .file or kind == .loopback))
            return failure(a, bad, try std.fmt.allocPrint(a, "{s} may not be a {s} reference for a remote resolver", .{ key, @tagName(kind) }), null);
    };
    var vh_options: resolver.Options = .{};
    var selectors: usize = 0;
    if (options.get("versionId")) |v| {
        if (v != .string) return failure(a, bad, "versionId must be a string", null);
        vh_options.version_id = v.string;
        selectors += 1;
    }
    if (options.get("versionTime")) |v| {
        if (v != .string or time.parse(v.string) == null) return failure(a, bad, "versionTime must be YYYY-MM-DDTHH:MM:SSZ", null);
        vh_options.version_time = v.string;
        selectors += 1;
    }
    if (options.get("versionNumber")) |v| {
        vh_options.version_number = integer(v, 1) orelse return failure(a, bad, "versionNumber must be a positive integer", null);
        selectors += 1;
    }
    if (selectors > 1) return failure(a, bad, "at most one of versionId, versionTime and versionNumber", null);
    if (options.get("checkWatchers")) |v| {
        const ok = (v == .string and std.mem.eql(u8, v.string, "all")) or integer(v, 0) != null;
        if (!ok) return failure(a, bad, "checkWatchers must be a non-negative integer or \"all\"", null);
    }
    if (options.get("extraWatchers")) |v| {
        const ok = v == .array and for (v.array) |u| {
            if (!extraWatcher(u)) break false;
        } else true;
        if (!ok) return failure(a, bad, "extraWatchers must be an array of https URLs", null);
    }
    if (options.get("minCopies")) |v| {
        vh_options.min_copies = integer(v, 1) orelse return failure(a, bad, "minCopies must be a positive integer", null);
    }
    if (options.get("includeDidLog")) |v| if (v != .bool) return failure(a, bad, "includeDidLog must be a boolean", null);

    // 3. What an offline resolver can't do.
    const unsupported = "featureNotSupported";
    if (has(options, "srcLog")) return failure(a, unsupported, "this resolver does not retrieve srcLog", null);
    if (options.get("checkWatchers")) |v| if (!(v == .number and v.number == 0))
        return failure(a, unsupported, "this resolver does not query watchers", null);
    if (options.get("extraWatchers")) |v| if (v.array.len > 0)
        return failure(a, unsupported, "this resolver does not query watchers", null);

    // 4. A srcWitness matters only if the log needs witnessing.
    const text = options.get("didLog").?.string;
    const lines = try resolver.splitLines(a, text);
    if (has(options, "srcWitness") and needsWitnessing(lines.values))
        return failure(a, unsupported, "this resolver does not retrieve srcWitness", null);

    // 5. VH-Log resolution with the did:vh specialisation.
    const res = try resolver.resolve(a, .{
        .log = text,
        .witness = if (options.get("didWitness")) |w| .{ .present = w } else .absent,
        .now = ctx.now,
        .options = vh_options,
        .specialisation = specialisation(scid_slot),
    });
    const rv = try res.toValue(a);
    if (!res.valid) return failure(a, didErrorCode(res.err.?.code), res.err.?.message, rv.get("error").?);

    // 6. An unsupported entry may change the document or its keys.
    if (selectors == 0) if (res.err) |e| if (e.code == .unsupported_log_version)
        return failure(a, unsupported, e.message, rv.get("error").?);

    const md = rv.get("metadata").?;
    const valid: usize = if (res.first_invalid_version) |f| @intCast(f - 1) else lines.text.len;
    const needs = needsWitnessing(lines.values[0..valid]);

    var meta: std.ArrayList(Member) = .empty;
    try meta.append(a, .{ .key = "contentType", .value = .{ .string = "application/did+json" } });
    const warnings = md.get("warnings").?;
    if (warnings.array.len > 0) try meta.append(a, .{ .key = "warnings", .value = warnings });
    if (options.get("includeDidLog")) |v| if (v.bool) {
        var did_log: std.ArrayList(u8) = .empty;
        for (lines.text[0..valid]) |l| {
            try did_log.appendSlice(a, l);
            try did_log.append(a, '\n');
        }
        try meta.append(a, .{ .key = "didLog", .value = .{ .string = did_log.items } });
        if (needs) try meta.append(a, .{ .key = "didWitness", .value = options.get("didWitness") orelse .{ .array = &.{} } });
    };

    var doc_meta: std.ArrayList(Member) = .empty;
    for ([_][]const u8{ "versionId", "versionTime", "created", "updated", "scid", "deactivated", "ttl" }) |key| {
        try doc_meta.append(a, .{ .key = key, .value = md.get(key).? });
    }
    const witness = md.get("witness").?;
    if (witness == .object) try doc_meta.append(a, .{ .key = "witness", .value = witness });
    try doc_meta.append(a, .{ .key = "watchers", .value = md.get("watchers").? });

    const deactivated = res.metadata.?.deactivated;
    const latest = res.metadata.?.version_number == valid;
    return object(a, &.{
        .{ .key = "didResolutionMetadata", .value = .{ .object = meta.items } },
        .{ .key = "didDocument", .value = if (deactivated and latest) .null else res.state.? },
        .{ .key = "didDocumentMetadata", .value = .{ .object = doc_meta.items } },
    });
}
