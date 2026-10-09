package org.vhlog

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode

/** RFC 8785 JSON Canonicalization Scheme. */
object Jcs {
    /** Canonical JSON text of [value]. Throws [IllegalArgumentException] for a non-finite number. */
    @JvmStatic
    fun canonicalize(value: JsonValue): String = StringBuilder().also { write(value, it) }.toString()

    /** Parses [text] with [Json.parse] and canonicalises it. */
    @JvmStatic
    fun canonicalize(text: String): String = canonicalize(Json.parse(text))

    private fun write(value: JsonValue, out: StringBuilder) {
        when (value) {
            is JsonArray -> {
                out.append('[')
                value.items.forEachIndexed { i, item ->
                    if (i > 0) out.append(',')
                    write(item, out)
                }
                out.append(']')
            }
            is JsonObject -> {
                out.append('{')
                // String.compareTo compares UTF-16 code units, which is the order RFC 8785 requires.
                value.members.keys.sorted().forEachIndexed { i, key ->
                    if (i > 0) out.append(',')
                    Json.writeString(key, out)
                    out.append(':')
                    write(value.members.getValue(key), out)
                }
                out.append('}')
            }
            else -> Json.write(value, out)
        }
    }

    private const val TWO_53 = 9007199254740992.0

    /**
     * Formats a finite double as ECMAScript `Number::toString` does (RFC 8785 §3.2.2.3):
     * the shortest digit string that round-trips, in plain notation for exponents
     * -7 < e < 21 and in `d.ddde±x` notation otherwise. `-0` is written `0`.
     */
    @JvmStatic
    fun formatNumber(d: Double): String {
        require(d.isFinite()) { "JCS: non-finite number" }
        if (d == 0.0) return "0"
        // Integers below 2^53 are exact, so their decimal form is already the shortest.
        if (Math.abs(d) < TWO_53 && d == Math.rint(d)) return d.toLong().toString()

        val negative = d < 0
        val exact = BigDecimal(Math.abs(d))
        var digits = ""
        var exponent = 0 // value = 0.digits × 10^exponent, i.e. ECMAScript's n
        for (precision in 1..17) {
            val rounded = exact.round(MathContext(precision, RoundingMode.HALF_EVEN))
            if (java.lang.Double.parseDouble(rounded.toString()) == Math.abs(d)) {
                val stripped = rounded.stripTrailingZeros()
                digits = stripped.unscaledValue().toString()
                exponent = digits.length - stripped.scale()
                break
            }
        }
        check(digits.isNotEmpty()) { "no round-trip representation for $d" }

        val k = digits.length
        val n = exponent
        val body = when {
            n in k..21 -> digits + "0".repeat(n - k)
            n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
            n in -5..0 -> "0." + "0".repeat(-n) + digits
            else -> {
                val e = n - 1
                val sign = if (e >= 0) "+" else "-"
                val mantissa = if (k == 1) digits else digits[0] + "." + digits.substring(1)
                mantissa + "e" + sign + Math.abs(e)
            }
        }
        return if (negative) "-$body" else body
    }
}
