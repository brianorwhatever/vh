package org.vhlog

import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** did:vh library tests: every did:vh vector, and the specialisation hook keeping VH-Log and did:vh logs apart. */
class DidVhTest {
    private val root = File(System.getProperty("vhlog.vectors") ?: "../../vectors", "didvh")
    private val seed = "11".repeat(32)
    private val now = "2026-06-01T00:00:00Z"

    private fun load(file: File): JsonObject = Json.parse(file.readText()) as JsonObject

    private fun cases(file: File): List<JsonObject> = load(file).array("cases")!!.map { it as JsonObject }

    private fun same(a: JsonValue?, b: JsonValue?) = Jcs.canonicalize(a ?: JsonNull) == Jcs.canonicalize(b ?: JsonNull)

    @TestFactory
    fun resolutionVectors(): List<DynamicTest> =
        File(root, "resolution").listFiles { f -> f.name.endsWith(".json") }!!.sorted().flatMap { file ->
            cases(file).map { c ->
                DynamicTest.dynamicTest("${file.name}/${c.string("name")}") {
                    val input = c.obj("input")!!
                    val expect = c.obj("expect")!!
                    val context = ResolverContext(input.string("now"), input["remote"] == JsonBool.TRUE)
                    val got = DidVh.resolve(input.string("did") ?: "", input["options"] ?: JsonObject(), context).toJson()
                    val meta = got.obj("didResolutionMetadata")!!
                    if ("error" in expect) {
                        assertTrue(same(expect["error"], meta["error"]), "error ${meta["error"]}")
                        expect["vhLogError"]?.let { code ->
                            assertTrue(same(code, meta.obj("problemDetails")?.obj("vhLog")?.get("code")), "vhLog")
                        }
                    } else {
                        assertNull(meta["error"], "unexpected error $meta")
                        for (key in listOf("didDocument", "didDocumentMetadata")) {
                            assertTrue(same(expect[key], got[key]), "$key: ${got[key]?.toJson()}")
                        }
                        for (key in listOf("didLog", "didWitness")) assertTrue(same(expect[key], meta[key]), key)
                    }
                }
            }
        }

    private fun outcome(body: () -> JsonValue): JsonValue = try {
        body()
    } catch (e: DidVhException) {
        JsonObject("valid" to JsonBool.FALSE, "error" to JsonString(e.code.code))
    }

    @TestFactory
    fun referenceSrcAndDidUrlVectors(): List<DynamicTest> {
        val tests = ArrayList<DynamicTest>()
        for (c in cases(File(root, "ref.json"))) {
            tests += DynamicTest.dynamicTest("ref/${c.string("name")}") {
                val got = outcome {
                    val ref = c.string("ref") ?: throw DidVhException(DidVhErrorCode.INVALID_OPTIONS, "not a string")
                    JsonObject("valid" to JsonBool.TRUE, "kind" to JsonString(DidVh.checkRef(ref).wire))
                }
                assertTrue(same(c["expect"], got), got.toJson())
            }
        }
        for (c in cases(File(root, "src.json"))) {
            tests += DynamicTest.dynamicTest("src/${c.string("name")}") {
                val got = outcome {
                    val (srcLog, srcWitness) = DidVh.srcReferences(c.string("src")!!)
                    JsonObject("valid" to JsonBool.TRUE, "srcLog" to JsonString(srcLog), "srcWitness" to JsonString(srcWitness))
                }
                assertTrue(same(c["expect"], got), got.toJson())
            }
        }
        for (c in cases(File(root, "did-url.json"))) {
            tests += DynamicTest.dynamicTest("did-url/${c.string("name")}") {
                val got = outcome {
                    val url = c.string("didUrl") ?: throw DidVhException(DidVhErrorCode.INVALID_DID_URL, "not a string")
                    val u = DidVh.parseDidUrl(url)
                    val out = linkedMapOf<String, JsonValue>("valid" to JsonBool.TRUE, "did" to JsonString(u.did), "options" to u.options)
                    if (u.fragment != null) out["fragment"] = JsonString(u.fragment)
                    JsonObject(out)
                }
                assertTrue(same(c["expect"], got), got.toJson())
            }
        }
        return tests
    }

    private fun updateKeys() = JsonObject("updateKeys" to JsonArray(listOf(JsonString(Ed25519Signer.fromSeedHex(seed).multikey))))

    @Test
    fun createUpdateAndResolve() {
        val document = JsonObject("id" to JsonString("did:vh:{SCID}"), "controller" to JsonString("did:vh:{SCID}"))
        val created = DidVh.createDid(document, updateKeys(), "2026-01-01T00:00:00Z", listOf(seed))
        assertEquals(created.scid, DidVh.parseDid(created.did))
        val line = Json.parse(created.log) as JsonObject
        assertEquals(DidVh.METHOD, line.obj("parameters")!!.string("method"))
        assertFalse("logVersion" in line.obj("parameters")!!)
        assertEquals(created.did, line.obj("state")!!.string("controller"))

        val next = JsonObject("id" to JsonString(created.did), "v" to JsonNumber(2))
        val updated = DidVh.updateDid(created.log, next, "2026-01-02T00:00:00Z", listOf(seed))
        val r = DidVh.resolve(created.did, JsonObject("didLog" to JsonString(updated.log)), ResolverContext(now))
        if (r !is DidResolution.Resolved) fail("did not resolve: ${r.toJson().toJson()}")
        assertTrue(same(next, r.document))
        assertEquals(updated.versionId, r.metadata.versionId)
    }

    @Test
    fun vhLogAndDidVhLogsAreNotInterchangeable() {
        val vh = LogController.createLog(JsonObject("id" to JsonString("did:vh:{SCID}")), updateKeys(), "2026-01-01T00:00:00Z", listOf(seed))
        val asDid = DidVh.resolve("did:vh:${vh.scid}", JsonObject("didLog" to JsonString(vh.log)), ResolverContext(now))
        assertEquals(DidVhErrorCode.INVALID_DID, (asDid as? DidResolution.Failed)?.code)

        val did = DidVh.createDid(JsonObject("id" to JsonString("did:vh:{SCID}")), updateKeys(), "2026-01-01T00:00:00Z", listOf(seed))
        val asLog = Resolver.resolve(ResolveRequest(did.log, now))
        assertEquals(ErrorCode.UNSUPPORTED_LOG_VERSION, (asLog as? ResolveResult.Failed)?.error?.code)
    }
}
