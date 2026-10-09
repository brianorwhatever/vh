package org.vhlog

/**
 * A JSON value, modelled the way RFC 8785 (JCS) sees it: every number is an
 * IEEE-754 double, object members keep their insertion order and a duplicated
 * key keeps the position of its first occurrence with the value of its last
 * (as `JSON.parse` does).
 *
 * Strings may contain lone surrogates; [isIJsonSafe] reports whether a value
 * avoids them (and non-finite numbers).
 */
sealed class JsonValue {
    /** Compact JSON text (members in insertion order, ECMAScript number formatting). */
    fun toJson(): String = StringBuilder().also { Json.write(this, it) }.toString()

    override fun toString(): String = toJson()
}

/** The JSON `null` literal. */
object JsonNull : JsonValue()

/** `true` or `false`. */
data class JsonBool(val value: Boolean) : JsonValue() {
    companion object {
        @JvmField val TRUE = JsonBool(true)
        @JvmField val FALSE = JsonBool(false)

        @JvmStatic fun of(value: Boolean): JsonBool = if (value) TRUE else FALSE
    }

    override fun toString(): String = toJson()
}

/** A JSON number. May be non-finite when parsed from text such as `1e400`. */
data class JsonNumber(val value: Double) : JsonValue() {
    constructor(value: Long) : this(value.toDouble())
    constructor(value: Int) : this(value.toDouble())

    /** True when the number is finite and has no fractional part (`Number.isInteger`). */
    val isInteger: Boolean get() = value.isFinite() && value == Math.floor(value)

    override fun toString(): String = toJson()
}

/** A JSON string. */
data class JsonString(val value: String) : JsonValue() {
    override fun toString(): String = toJson()
}

/** A JSON array. */
data class JsonArray(val items: List<JsonValue>) : JsonValue(), List<JsonValue> by items {
    constructor(vararg items: JsonValue) : this(items.toList())

    override fun toString(): String = toJson()
}

/** A JSON object; iteration follows insertion order. */
data class JsonObject(val members: Map<String, JsonValue>) : JsonValue(), Map<String, JsonValue> by members {
    constructor(vararg members: Pair<String, JsonValue>) : this(linkedMapOf(*members))

    /** The string member [key], or null if it is absent or not a string. */
    fun string(key: String): String? = (members[key] as? JsonString)?.value

    /** The object member [key], or null if it is absent or not an object. */
    fun obj(key: String): JsonObject? = members[key] as? JsonObject

    /** The array member [key], or null if it is absent or not an array. */
    fun array(key: String): JsonArray? = members[key] as? JsonArray

    /** A copy without [key]. */
    fun without(key: String): JsonObject = JsonObject(LinkedHashMap(members).apply { remove(key) })

    /** A copy with [key] set to [value] (kept in place if it already exists, else appended). */
    fun with(key: String, value: JsonValue): JsonObject = JsonObject(LinkedHashMap(members).apply { put(key, value) })

    override fun toString(): String = toJson()
}

/** Thrown for text that is not valid JSON. */
class JsonParseException(message: String) : RuntimeException(message)

/** JSON parsing and compact serialisation, with no dependencies. */
object Json {
    /** Parses [text] strictly as `JSON.parse` does (RFC 8259 grammar, last duplicate key wins). */
    @JvmStatic
    fun parse(text: String): JsonValue = Parser(text).parseDocument()

    /** Parses [text], returning null if it is not valid JSON. */
    @JvmStatic
    fun parseOrNull(text: String): JsonValue? = try {
        parse(text)
    } catch (e: JsonParseException) {
        null
    }

    /** Compact serialisation of [value], as `JSON.stringify` would produce it. */
    @JvmStatic
    fun stringify(value: JsonValue): String = value.toJson()

    internal fun write(value: JsonValue, out: StringBuilder) {
        when (value) {
            JsonNull -> out.append("null")
            is JsonBool -> out.append(if (value.value) "true" else "false")
            is JsonNumber -> {
                require(value.value.isFinite()) { "cannot serialise a non-finite number" }
                out.append(Jcs.formatNumber(value.value))
            }
            is JsonString -> writeString(value.value, out)
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
                var first = true
                for ((k, v) in value.members) {
                    if (!first) out.append(',')
                    first = false
                    writeString(k, out)
                    out.append(':')
                    write(v, out)
                }
                out.append('}')
            }
        }
    }

    /** Writes a string literal with the escaping of ECMAScript `JSON.stringify` (and RFC 8785). */
    internal fun writeString(s: String, out: StringBuilder) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\b' -> out.append("\\b")
                c == '\u000c' -> out.append("\\f")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> appendUnicodeEscape(c, out)
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                    out.append(c).append(s[i + 1])
                    i++
                }
                Character.isSurrogate(c) -> appendUnicodeEscape(c, out)
                else -> out.append(c)
            }
            i++
        }
        out.append('"')
    }

    private fun appendUnicodeEscape(c: Char, out: StringBuilder) {
        out.append("\\u")
        val hex = Integer.toHexString(c.code)
        repeat(4 - hex.length) { out.append('0') }
        out.append(hex)
    }

    private class Parser(private val s: String) {
        private var pos = 0

        fun parseDocument(): JsonValue {
            skipWhitespace()
            val value = parseValue()
            skipWhitespace()
            if (pos != s.length) fail("unexpected trailing text")
            return value
        }

        private fun fail(message: String): Nothing = throw JsonParseException("$message at offset $pos")

        private fun skipWhitespace() {
            while (pos < s.length) {
                when (s[pos]) {
                    ' ', '\t', '\n', '\r' -> pos++
                    else -> return
                }
            }
        }

        private fun parseValue(): JsonValue {
            if (pos >= s.length) fail("unexpected end of input")
            return when (val c = s[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonString(parseString())
                't' -> literal("true", JsonBool.TRUE)
                'f' -> literal("false", JsonBool.FALSE)
                'n' -> literal("null", JsonNull)
                else -> if (c == '-' || c in '0'..'9') parseNumber() else fail("unexpected character '$c'")
            }
        }

        private fun literal(word: String, value: JsonValue): JsonValue {
            if (!s.startsWith(word, pos)) fail("invalid literal")
            pos += word.length
            return value
        }

        private fun parseObject(): JsonObject {
            pos++ // '{'
            val members = LinkedHashMap<String, JsonValue>()
            skipWhitespace()
            if (pos < s.length && s[pos] == '}') {
                pos++
                return JsonObject(members)
            }
            while (true) {
                skipWhitespace()
                if (pos >= s.length || s[pos] != '"') fail("expected a string key")
                val key = parseString()
                skipWhitespace()
                if (pos >= s.length || s[pos] != ':') fail("expected ':'")
                pos++
                skipWhitespace()
                members[key] = parseValue()
                skipWhitespace()
                if (pos >= s.length) fail("unterminated object")
                when (s[pos++]) {
                    ',' -> continue
                    '}' -> return JsonObject(members)
                    else -> {
                        pos--
                        fail("expected ',' or '}'")
                    }
                }
            }
        }

        private fun parseArray(): JsonArray {
            pos++ // '['
            val items = ArrayList<JsonValue>()
            skipWhitespace()
            if (pos < s.length && s[pos] == ']') {
                pos++
                return JsonArray(items)
            }
            while (true) {
                skipWhitespace()
                items.add(parseValue())
                skipWhitespace()
                if (pos >= s.length) fail("unterminated array")
                when (s[pos++]) {
                    ',' -> continue
                    ']' -> return JsonArray(items)
                    else -> {
                        pos--
                        fail("expected ',' or ']'")
                    }
                }
            }
        }

        private fun parseString(): String {
            pos++ // opening quote
            val sb = StringBuilder()
            while (true) {
                if (pos >= s.length) fail("unterminated string")
                val c = s[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (pos >= s.length) fail("unterminated escape")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) fail("truncated \\u escape")
                                var code = 0
                                repeat(4) {
                                    val d = Character.digit(s[pos], 16)
                                    if (d < 0 || s[pos] > 'f') fail("invalid \\u escape")
                                    code = code * 16 + d
                                    pos++
                                }
                                sb.append(code.toChar())
                            }
                            else -> fail("invalid escape '\\$e'")
                        }
                    }
                    c < ' ' -> fail("control character in string")
                    else -> sb.append(c)
                }
            }
        }

        private fun parseNumber(): JsonNumber {
            val start = pos
            if (s[pos] == '-') pos++
            if (pos >= s.length) fail("invalid number")
            if (s[pos] == '0') {
                pos++
            } else if (s[pos] in '1'..'9') {
                while (pos < s.length && s[pos] in '0'..'9') pos++
            } else {
                fail("invalid number")
            }
            if (pos < s.length && s[pos] == '.') {
                pos++
                val digits = pos
                while (pos < s.length && s[pos] in '0'..'9') pos++
                if (pos == digits) fail("invalid number")
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                val digits = pos
                while (pos < s.length && s[pos] in '0'..'9') pos++
                if (pos == digits) fail("invalid number")
            }
            // Double.parseDouble rounds correctly and yields ±Infinity on overflow, like JSON.parse.
            return JsonNumber(java.lang.Double.parseDouble(s.substring(start, pos)))
        }
    }
}

/** Whether [value] is I-JSON-safe: finite numbers, and no lone surrogates in strings or keys (profile §4). */
fun isIJsonSafe(value: JsonValue): Boolean = when (value) {
    is JsonNumber -> value.value.isFinite()
    is JsonString -> isWellFormed(value.value)
    is JsonArray -> value.items.all(::isIJsonSafe)
    is JsonObject -> value.members.all { (k, v) -> isWellFormed(k) && isIJsonSafe(v) }
    else -> true
}

/** True when [s] contains no lone surrogate code units (`String.prototype.isWellFormed`). */
fun isWellFormed(s: String): Boolean {
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c)) {
            if (i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])) return false
            i += 2
            continue
        }
        if (Character.isLowSurrogate(c)) return false
        i++
    }
    return true
}

/** UTF-8 encoding that, like Node.js, replaces a lone surrogate with U+FFFD (Java would write `?`). */
fun utf8(s: String): ByteArray {
    if (isWellFormed(s)) return s.toByteArray(Charsets.UTF_8)
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
            sb.append(c).append(s[i + 1])
            i += 2
            continue
        }
        sb.append(if (Character.isSurrogate(c)) '�' else c)
        i++
    }
    return sb.toString().toByteArray(Charsets.UTF_8)
}
