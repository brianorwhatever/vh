package org.vhlog

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PrimitivesTest {
    @Test
    fun `numbers format like ECMAScript Number toString`() {
        val cases = mapOf(
            1e21 to "1e+21",
            1e20 to "100000000000000000000",
            1e-7 to "1e-7",
            1e-6 to "0.000001",
            -0.0 to "0",
            123456789012345678.0 to "123456789012345680",
            896365914996807.2 to "896365914996807.2",
            0.1 to "0.1",
            0.30000000000000004 to "0.30000000000000004",
            5e-324 to "5e-324",
            1.7976931348623157e308 to "1.7976931348623157e+308",
            9.999999999999999e22 to "1e+23",
            123e-20 to "1.23e-18",
            4.5 to "4.5",
            -1.5 to "-1.5",
            9007199254740993.0 to "9007199254740992",
            333333333.33333329 to "333333333.3333333",
        )
        for ((d, text) in cases) assertEquals(text, Jcs.formatNumber(d), "formatting $d")
        assertFailsWith<IllegalArgumentException> { Jcs.formatNumber(Double.POSITIVE_INFINITY) }
    }

    @Test
    fun `canonicalisation sorts keys by UTF-16 code units and escapes like JSON stringify`() {
        assertEquals("""{"a":[true,null],"b":1}""", Jcs.canonicalize("""{"b": 1, "a": [true, null]}"""))
        assertEquals("{\"\\r\":1,\"1\":2,\"\u00f6\":3,\"\uD83D\uDE00\":4,\"\uFB33\":5}",
            Jcs.canonicalize("{\"\\ufb33\":5,\"\\ud83d\\ude00\":4,\"\\u00f6\":3,\"1\":2,\"\\r\":1}"))
        assertEquals("\"\\u000f\\n\\\"\\\\/\u007f\u2028\"", Jcs.canonicalize("\"\\u000F\\n\\\"\\\\\\/\\u007f\\u2028\""))
        assertEquals("\"\\ud800\"", Jcs.canonicalize("\"\\ud800\""))
    }

    @Test
    fun `parser keeps the last duplicate key in the first position`() {
        val obj = Json.parse("""{"a":1,"b":2,"a":3}""") as JsonObject
        assertEquals(listOf("a", "b"), obj.keys.toList())
        assertEquals(JsonNumber(3), obj["a"])
    }

    @Test
    fun `parser accepts unsafe values that verification rejects`() {
        val big = Json.parse("[1e400]") as JsonArray
        assertEquals(Double.POSITIVE_INFINITY, (big[0] as JsonNumber).value)
        assertFalse(isIJsonSafe(big))
        assertFalse(isIJsonSafe(Json.parse("{\"\\udc00\":1}")))
        assertTrue(isIJsonSafe(Json.parse("{\"\\ud83d\\ude00\":1e308}")))
    }

    @Test
    fun `parser rejects invalid JSON`() {
        for (text in listOf("", "{", "[1,]", "{\"a\" 1}", "01", "1.", "-", "1e", "tru", "\"\u0001\"", "\"\\x\"", "{} x", "NaN", "'a'")) {
            assertFailsWith<JsonParseException>("parsing <$text>") { Json.parse(text) }
        }
        assertEquals(JsonNumber(-0.0), Json.parse(" -0 "))
    }

    @Test
    fun `base58btc round-trips and keeps leading zeros`() {
        val bytes = byteArrayOf(0, 0, 1, 2, 3, -1)
        assertContentEquals(bytes, Base58.decodeOrNull(Base58.encode(bytes)))
        assertEquals("11", Base58.encode(byteArrayOf(0, 0)))
        assertEquals("", Base58.encode(ByteArray(0)))
        assertNull(Base58.decodeOrNull("0OIl"))
    }

    @Test
    fun `multikey and key hash follow the profile`() {
        val signer = Ed25519Signer.fromSeedHex("90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa")
        assertEquals("z6MkwTAY3aCT7UL96ddvxWr1upj2VFQDMPFFRYxM1fRneSrv", signer.multikey)
        assertContentEquals(signer.publicKey, Multikey.publicKeyOrNull(signer.multikey))
        assertEquals("QmchKW5rynK1kqB1CAUt9B7NEP7TYnnMKRrGQDMXpRV4QG", Hashes.keyHash(signer.multikey))
        assertNull(Multikey.publicKeyOrNull("z" + Base58.encode(ByteArray(34))))
    }

    @Test
    fun `hashing encodes lone surrogates as U+FFFD like Node`() {
        assertEquals(Hashes.hashB58("\uFFFD"), Hashes.hashB58("\uD800"))
        assertTrue(Hashes.hashB58("hello").startsWith("Qm"))
        assertEquals(MultihashCheck.OK, Hashes.checkSha256Multihash(Hashes.hashB58("x")))
        assertEquals(MultihashCheck.NOT_BASE58, Hashes.checkSha256Multihash(""))
        assertEquals(MultihashCheck.UNSUPPORTED_ALGORITHM, Hashes.checkSha256Multihash(Base58.encode(ByteArray(34) { 0x13 })))
    }

    @Test
    fun `proofs verify and reject tampering`() {
        val seed = "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6"
        val doc = JsonObject("hello" to JsonString("world"))
        val proof = Proofs.create(doc, seed, ProofOptions(created = "2026-01-01T00:00:00Z"))
        assertTrue(Proofs.verify(doc, proof))
        assertFalse(Proofs.verify(doc.with("extra", JsonNumber(1)), proof))
        assertFalse(Proofs.verify(doc, proof.with("proofPurpose", JsonString("authentication"))))
        assertFalse(Proofs.verify(doc, proof.with("proofValue", JsonString("zzz"))))
        assertFalse(Proofs.verify(doc, proof.with("created", JsonString("2026-01-02T00:00:00Z"))))
    }

    @Test
    fun `version times follow the profile`() {
        assertEquals(0L, Verifier.parseVersionTime("1970-01-01T00:00:00Z"))
        assertEquals(0L, Verifier.parseVersionTime("1970-01-01T00:00:00+00:00"))
        assertEquals(951782400L, Verifier.parseVersionTime("2000-02-29T00:00:00Z"))
        assertTrue(Verifier.parseVersionTime("0000-01-01T00:00:00Z")!! < 0)
        for (bad in listOf("1900-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00.0Z", "2026-01-01T00:00:00+01:00", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00Z\n")) {
            assertNull(Verifier.parseVersionTime(bad), bad)
        }
    }

    @Test
    fun `watcher URLs follow the profile`() {
        assertTrue(Verifier.isWatcherUrl("https://w.example/path"))
        assertTrue(Verifier.isWatcherUrl("http://x"))
        for (bad in listOf("https://", "https:///x", "ftp://x", "https://a b", "https://ä.example", "HTTPS://x")) {
            assertFalse(Verifier.isWatcherUrl(bad), bad)
        }
    }
}
