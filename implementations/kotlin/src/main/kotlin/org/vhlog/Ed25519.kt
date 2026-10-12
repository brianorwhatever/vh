package org.vhlog

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.EdECPublicKey
import java.security.spec.EdECPoint
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec

/** An Ed25519 key pair derived from a 32-byte seed (RFC 8032 §5.1.5), using the JDK's provider. */
class Ed25519Signer private constructor(private val privateKey: PrivateKey, publicKey: ByteArray) {
    /** The raw 32-byte public key. */
    val publicKey: ByteArray = publicKey.copyOf()
        get() = field.copyOf()

    /** The public key as an Ed25519 multikey (`z6Mk…`). */
    val multikey: String = Multikey.fromPublicKey(publicKey)

    /** Signs [data] (pure Ed25519) and returns the 64-byte signature. */
    fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").run {
            initSign(privateKey)
            update(data)
            sign()
        }

    companion object {
        /** A signer for the hex-encoded 32-byte [seedHex]. */
        @JvmStatic
        fun fromSeedHex(seedHex: String): Ed25519Signer = fromSeed(Hex.decode(seedHex))

        /** A signer for the 32-byte [seed]. */
        @JvmStatic
        fun fromSeed(seed: ByteArray): Ed25519Signer {
            require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
            // The JDK's Ed25519 key pair generator draws exactly the 32-byte seed from its
            // SecureRandom, so feeding it the seed derives the matching public key.
            val generator = KeyPairGenerator.getInstance("Ed25519")
            generator.initialize(NamedParameterSpec.ED25519, FixedRandom(seed))
            val pair = generator.generateKeyPair()
            return Ed25519Signer(pair.private, encodePoint((pair.public as EdECPublicKey).point))
        }

        /** Verifies an Ed25519 [signature]; false for malformed keys or signatures. */
        @JvmStatic
        fun verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
            if (publicKey.size != 32 || signature.size != 64) return false
            if (!admissiblePoint(publicKey) || !admissiblePoint(signature.copyOfRange(0, 32))) return false
            return try {
                val key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(EdECPublicKeySpec(NamedParameterSpec.ED25519, decodePoint(publicKey)))
                Signature.getInstance("Ed25519").run {
                    initVerify(key)
                    update(data)
                    verify(signature)
                }
            } catch (e: Exception) {
                false
            }
        }

        // Profile §2; JCA checks curve membership and the equation.
        private fun admissiblePoint(encoded: ByteArray): Boolean {
            val y = encoded.copyOf()
            y[31] = (y[31].toInt() and 127).toByte()
            val n = BigInteger(1, y.reversedArray())
            return n < BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949") && n !in setOf(BigInteger("0"), BigInteger("1"), BigInteger("2707385501144840649318225287225658788936804267575313519463743609750303402022"), BigInteger("55188659117513257062467267217118295137698188065244968500265048394206261417927"), BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819948"))
        }

        private fun encodePoint(point: EdECPoint): ByteArray {
            val big = point.y.toByteArray() // big-endian, possibly with a sign byte
            val out = ByteArray(32)
            for (i in 0 until minOf(32, big.size)) out[i] = big[big.size - 1 - i]
            if (point.isXOdd) out[31] = (out[31].toInt() or 0x80).toByte()
            return out
        }

        private fun decodePoint(encoded: ByteArray): EdECPoint {
            val xOdd = (encoded[31].toInt() and 0x80) != 0
            val bigEndian = ByteArray(32) { i -> encoded[31 - i] }
            bigEndian[0] = (bigEndian[0].toInt() and 0x7f).toByte()
            return EdECPoint(xOdd, BigInteger(1, bigEndian))
        }
    }

    private class FixedRandom(private val seed: ByteArray) : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) {
            check(bytes.size == seed.size) { "unexpected random request of ${bytes.size} bytes" }
            seed.copyInto(bytes)
        }
    }
}
