//! ECMAScript `Number::toString(10)` for finite IEEE-754 doubles, as required by
//! RFC 8785 §3.2.2.3.
//!
//! The shortest round-tripping digit string comes from the standard library's
//! Ryu implementation (`std.fmt.float`, scientific mode, full precision). Ryu
//! picks, among the shortest digit strings that round-trip, the one closest to
//! the exact binary value, which is what ECMA-262 Number::toString step 5
//! requires. This file only re-lays those digits out with the ECMAScript
//! notation rules.

const std = @import("std");

pub const Error = error{NonFinite};

/// Longest possible output: "-" + 17 digits + "e-324"-style exponent, or
/// "0.000000" + 17 digits, or 21 integer digits. 32 bytes is plenty.
pub const max_len = 32;

/// Formats `x` into `buf` and returns the written slice.
pub fn format(buf: *[max_len]u8, x: f64) Error![]const u8 {
    if (!std.math.isFinite(x)) return error.NonFinite;
    if (x == 0) {
        buf[0] = '0'; // both +0 and -0
        return buf[0..1];
    }
    var tmp: [std.fmt.float.min_buffer_size]u8 = undefined;
    const sci = std.fmt.float.render(&tmp, x, .{ .mode = .scientific }) catch unreachable;

    // `sci` is "[-]d[.ddd]e[-]N".
    var i: usize = 0;
    const negative = sci[0] == '-';
    if (negative) i = 1;
    var digits: [24]u8 = undefined;
    var k: usize = 0;
    while (i < sci.len and sci[i] != 'e') : (i += 1) {
        if (sci[i] == '.') continue;
        digits[k] = sci[i];
        k += 1;
    }
    // Ryu may emit trailing zeros only for exact integers like "1e21"; strip any.
    while (k > 1 and digits[k - 1] == '0') k -= 1;
    std.debug.assert(i < sci.len and sci[i] == 'e');
    const exp10 = std.fmt.parseInt(i32, sci[i + 1 ..], 10) catch unreachable;
    // ECMAScript: value = 0.d1d2..dk × 10^n, i.e. n = exp10 + 1.
    const n: i32 = exp10 + 1;
    const kk: i32 = @intCast(k);

    var w: usize = 0;
    if (negative) {
        buf[w] = '-';
        w += 1;
    }
    if (kk <= n and n <= 21) {
        // Integer: digits followed by n-k zeros.
        @memcpy(buf[w..][0..k], digits[0..k]);
        w += k;
        var z: i32 = n - kk;
        while (z > 0) : (z -= 1) {
            buf[w] = '0';
            w += 1;
        }
    } else if (0 < n and n <= 21) {
        const un: usize = @intCast(n);
        @memcpy(buf[w..][0..un], digits[0..un]);
        w += un;
        buf[w] = '.';
        w += 1;
        @memcpy(buf[w..][0 .. k - un], digits[un..k]);
        w += k - un;
    } else if (-6 < n and n <= 0) {
        buf[w] = '0';
        buf[w + 1] = '.';
        w += 2;
        var z: i32 = -n;
        while (z > 0) : (z -= 1) {
            buf[w] = '0';
            w += 1;
        }
        @memcpy(buf[w..][0..k], digits[0..k]);
        w += k;
    } else {
        buf[w] = digits[0];
        w += 1;
        if (k > 1) {
            buf[w] = '.';
            w += 1;
            @memcpy(buf[w..][0 .. k - 1], digits[1..k]);
            w += k - 1;
        }
        buf[w] = 'e';
        w += 1;
        const e = n - 1;
        buf[w] = if (e < 0) '-' else '+';
        w += 1;
        const s = std.fmt.bufPrint(buf[w..], "{d}", .{@abs(e)}) catch unreachable;
        w += s.len;
    }
    return buf[0..w];
}

fn expectFmt(x: f64, want: []const u8) !void {
    var buf: [max_len]u8 = undefined;
    try std.testing.expectEqualStrings(want, try format(&buf, x));
}

test "ECMAScript number formatting" {
    try expectFmt(0.0, "0");
    try expectFmt(-0.0, "0");
    try expectFmt(1.0, "1");
    try expectFmt(100, "100");
    try expectFmt(4.5, "4.5");
    try expectFmt(0.002, "0.002");
    try expectFmt(1e-27, "1e-27");
    try expectFmt(1e21, "1e+21");
    try expectFmt(1e20, "100000000000000000000");
    try expectFmt(1e-7, "1e-7");
    try expectFmt(1e-6, "0.000001");
    try expectFmt(0.000001234, "0.000001234");
    try expectFmt(5e-324, "5e-324");
    try expectFmt(1.7976931348623157e308, "1.7976931348623157e+308");
    try expectFmt(333333333.33333329, "333333333.3333333");
    try expectFmt(896365914996807.2, "896365914996807.2");
    try expectFmt(0.30000000000000004, "0.30000000000000004");
    try expectFmt(9.999999999999999e22, "1e+23");
    try expectFmt(123456789012345678.0, "123456789012345680");
    try expectFmt(295147905179352830000.0, "295147905179352830000");
    try expectFmt(-1.5e-9, "-1.5e-9");
    try expectFmt(2.2250738585072014e-308, "2.2250738585072014e-308");
    try std.testing.expectError(error.NonFinite, format(undefined, std.math.inf(f64)));
}
