//! `versionTime` parsing (profile §4): `YYYY-MM-DDTHH:MM:SSZ` or
//! `YYYY-MM-DDTHH:MM:SS+00:00`, proleptic Gregorian, no fractions, no leap
//! seconds, any four-digit year.

const std = @import("std");

fn digits(s: []const u8) ?u32 {
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

fn isLeap(y: i64) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

fn daysInMonth(y: i64, m: u32) u32 {
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeap(y)) 29 else 28,
        else => 0,
    };
}

/// Days since 1970-01-01 (Howard Hinnant's days_from_civil).
fn daysFromCivil(y0: i64, m: u32, d: u32) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// Returns seconds since the Unix epoch, or null if `s` is not a valid
/// versionTime.
pub fn parse(s: []const u8) ?i64 {
    if (s.len != 20 and s.len != 25) return null;
    if (s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    if (s.len == 20) {
        if (s[19] != 'Z') return null;
    } else if (!std.mem.eql(u8, s[19..], "+00:00")) return null;
    const y = digits(s[0..4]) orelse return null;
    const mo = digits(s[5..7]) orelse return null;
    const d = digits(s[8..10]) orelse return null;
    const h = digits(s[11..13]) orelse return null;
    const mi = digits(s[14..16]) orelse return null;
    const se = digits(s[17..19]) orelse return null;
    if (mo < 1 or mo > 12) return null;
    if (d < 1 or d > daysInMonth(y, mo)) return null;
    if (h > 23 or mi > 59 or se > 59) return null;
    return daysFromCivil(y, mo, d) * 86400 + @as(i64, h) * 3600 + @as(i64, mi) * 60 + se;
}

test "versionTime parsing" {
    const t = std.testing;
    try t.expectEqual(@as(?i64, 0), parse("1970-01-01T00:00:00Z"));
    try t.expectEqual(@as(?i64, 1767225600), parse("2026-01-01T00:00:00Z"));
    try t.expectEqual(parse("2026-01-01T00:00:00Z"), parse("2026-01-01T00:00:00+00:00"));
    try t.expect(parse("2024-02-29T00:00:00Z") != null);
    try t.expect(parse("2000-02-29T00:00:00Z") != null);
    try t.expect(parse("0000-01-01T00:00:00Z") != null);
    try t.expect(parse("1900-02-29T00:00:00Z") == null);
    try t.expect(parse("2026-02-30T00:00:00Z") == null);
    try t.expect(parse("2026-01-01T24:00:00Z") == null);
    try t.expect(parse("2026-01-01T23:59:60Z") == null);
    try t.expect(parse("2026-01-01T00:00:00z") == null);
    try t.expect(parse("2026-01-01T00:00:00.5Z") == null);
    try t.expect(parse("2026-01-01T00:00:00") == null);
    try t.expect(parse("2026-01-01T00:00:00+02:00") == null);
}
