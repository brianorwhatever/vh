package org.vhlog

import java.security.MessageDigest

/** base58btc with the Bitcoin alphabet and no multibase prefix (profile §1). */
object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val INDEX = IntArray(128) { -1 }.also { table -> ALPHABET.forEachIndexed { i, c -> table[c.code] = i } }

    @JvmStatic
    fun encode(bytes: ByteArray): String {
        var zeros = 0
        while (zeros < bytes.size && bytes[zeros].toInt() == 0) zeros++
        val digits = IntArray(bytes.size * 138 / 100 + 1)
        var length = 0
        for (i in zeros until bytes.size) {
            var carry = bytes[i].toInt() and 0xff
            for (j in 0 until length) {
                carry += digits[j] shl 8
                digits[j] = carry % 58
                carry /= 58
            }
            while (carry > 0) {
                digits[length++] = carry % 58
                carry /= 58
            }
        }
        val sb = StringBuilder(zeros + length)
        repeat(zeros) { sb.append('1') }
        for (i in length - 1 downTo 0) sb.append(ALPHABET[digits[i]])
        return sb.toString()
    }

    /** Decodes [s], or returns null if it contains a character outside the alphabet. */
    @JvmStatic
    fun decodeOrNull(s: String): ByteArray? {
        var zeros = 0
        while (zeros < s.length && s[zeros] == '1') zeros++
        val bytes = IntArray(s.length)
        var length = 0
        for (i in zeros until s.length) {
            val c = s[i].code
            val value = if (c < 128) INDEX[c] else -1
            if (value < 0) return null
            var carry = value
            for (j in 0 until length) {
                carry += bytes[j] * 58
                bytes[j] = carry and 0xff
                carry = carry ushr 8
            }
            while (carry > 0) {
                bytes[length++] = carry and 0xff
                carry = carry ushr 8
            }
        }
        val out = ByteArray(zeros + length)
        for (i in 0 until length) out[out.size - 1 - i] = bytes[i].toByte()
        return out
    }
}

/** Lower-case hexadecimal. */
object Hex {
    @JvmStatic
    fun decode(hex: String): ByteArray {
        require(hex.length % 2 == 0 && hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { "invalid hex: $hex" }
        return ByteArray(hex.length / 2) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }

    @JvmStatic
    fun encode(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/** Ed25519 multikeys: `"z" + base58btc(0xed 0x01 ‖ publicKey)` (profile §1). */
object Multikey {
    private const val PREFIX_0: Byte = 0xed.toByte()
    private const val PREFIX_1: Byte = 0x01

    @JvmStatic
    fun fromPublicKey(publicKey: ByteArray): String {
        require(publicKey.size == 32) { "Ed25519 public keys are 32 bytes" }
        return "z" + Base58.encode(byteArrayOf(PREFIX_0, PREFIX_1) + publicKey)
    }

    /** The raw public key, or null if [multikey] is not an Ed25519 multikey. */
    @JvmStatic
    fun publicKeyOrNull(multikey: String): ByteArray? {
        if (!multikey.startsWith("z")) return null
        val bytes = Base58.decodeOrNull(multikey.substring(1)) ?: return null
        if (bytes.size != 34 || bytes[0] != PREFIX_0 || bytes[1] != PREFIX_1) return null
        return bytes.copyOfRange(2, 34)
    }

    @JvmStatic
    fun isValid(multikey: String): Boolean = publicKeyOrNull(multikey) != null
}

/** Result of checking that a base58btc string is a SHA-256 multihash. */
enum class MultihashCheck { OK, NOT_BASE58, UNSUPPORTED_ALGORITHM }

/** SHA-256 multihashes, the only hash `vh-log:1.0` permits. */
object Hashes {
    private const val SHA256_CODE = 0x12
    private const val SHA256_LENGTH = 32

    @JvmStatic
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** SHA-256 of the UTF-8 encoding of [data] (lone surrogates become U+FFFD). */
    @JvmStatic
    fun sha256(data: String): ByteArray = sha256(utf8(data))

    /** `base58btc(multihash(data))` — the encoding of SCIDs, entry hashes and key hashes. */
    @JvmStatic
    fun hashB58(data: ByteArray): String =
        Base58.encode(byteArrayOf(SHA256_CODE.toByte(), SHA256_LENGTH.toByte()) + sha256(data))

    @JvmStatic
    fun hashB58(data: String): String = hashB58(utf8(data))

    /** Pre-rotation key hash: the multikey string itself is hashed. */
    @JvmStatic
    fun keyHash(multikey: String): String = hashB58(multikey)

    @JvmStatic
    fun checkSha256Multihash(value: String): MultihashCheck {
        val bytes = Base58.decodeOrNull(value)
        if (bytes == null || bytes.isEmpty()) return MultihashCheck.NOT_BASE58
        if (bytes.size != 2 + SHA256_LENGTH || bytes[0].toInt() != SHA256_CODE || bytes[1].toInt() != SHA256_LENGTH) {
            return MultihashCheck.UNSUPPORTED_ALGORITHM
        }
        return MultihashCheck.OK
    }
}
