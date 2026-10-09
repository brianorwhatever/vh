package org.vhlog

import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** Runs the shared vectors in ../../vectors through the library, comparing as the harness does. */
class VectorsTest {
    private val root = File(System.getProperty("vhlog.vectors") ?: "../../vectors")

    private fun load(path: String): JsonObject = Json.parse(File(root, path).readText()) as JsonObject

    private fun same(a: JsonValue?, b: JsonValue?) = a != null && b != null && Jcs.canonicalize(a) == Jcs.canonicalize(b)

    private fun JsonObject.list(key: String): List<JsonObject> = array(key)!!.map { it as JsonObject }

    @TestFactory
    fun primitives(): List<DynamicTest> {
        val v = load("primitives.json")
        val tests = ArrayList<DynamicTest>()
        v.list("jcs").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("jcs[$i]") { assertEquals(c.string("output"), Jcs.canonicalize(c.string("text")!!)) }
        }
        v.list("hash").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("hash[$i]") { assertEquals(c.string("output"), Hashes.hashB58(c.string("data")!!)) }
        }
        v.list("multikey").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("multikey[$i]") {
                assertEquals(c.string("multikey"), Ed25519Signer.fromSeedHex(c.string("seed")!!).multikey)
            }
        }
        v.list("keyHash").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("keyHash[$i]") { assertEquals(c.string("output"), Hashes.keyHash(c.string("multikey")!!)) }
        }
        v.list("scid").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("scid[$i]") { assertEquals(c.string("scid"), LogController.computeScid(c.obj("entry")!!)) }
        }
        v.list("entryHash").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("entryHash[$i]") {
                assertEquals(c.string("hash"), LogController.computeEntryHash(c.obj("entry")!!, c.string("previousVersionId")!!))
            }
        }
        v.list("sign").forEachIndexed { i, c ->
            tests += DynamicTest.dynamicTest("sign[$i]") {
                val proof = Proofs.create(c["document"]!!, c.string("seed")!!, ProofOptions(created = c.string("created")))
                assertTrue(same(c["proof"], proof), "proof $proof")
                assertTrue(Proofs.verify(c["document"]!!, c["proof"]!!))
                assertTrue(!Proofs.verify(c.obj("document")!!.with("extra", JsonNumber(1)), c["proof"]!!))
            }
        }
        return tests
    }

    @TestFactory
    fun generation(): List<DynamicTest> = load("generation.json").list("scenarios").map { sc ->
        DynamicTest.dynamicTest(sc.string("name")!!) {
            var log = ""
            var scid = ""
            val versionIds = ArrayList<String>()
            for (step in sc.list("steps")) {
                val expect = step.obj("expect")!!
                val versionId: String
                if (step.string("op") == "create") {
                    val i = step.obj("input")!!
                    val r = LogController.createLog(i.obj("state")!!, i.obj("parameters")!!, i.string("versionTime")!!,
                        i.array("signers")!!.map { (it as JsonString).value })
                    log = r.log
                    scid = r.scid
                    versionId = r.versionId
                    assertEquals(expect.string("scid"), scid)
                } else {
                    val i = Json.parse(step.obj("input")!!.toJson().replace("{SCID}", scid)) as JsonObject
                    val r = LogController.updateLog(log, i.obj("state")!!, i.string("versionTime")!!,
                        i.array("signers")!!.map { (it as JsonString).value }, i.obj("parameters") ?: JsonObject())
                    log = r.log
                    versionId = r.versionId
                }
                versionIds += versionId
                assertEquals(expect.string("versionId"), versionId)
                assertTrue(same(expect["line"], Json.parse(log.trimEnd().substringAfterLast('\n'))), "line for $versionId")
            }
            var witnessFile: JsonValue? = null
            sc.array("witness")?.let { spec ->
                witnessFile = JsonArray(spec.map { w ->
                    val o = w as JsonObject
                    val vid = versionIds[(o["step"] as JsonNumber).value.toInt() - 1]
                    JsonObject("versionId" to JsonString(vid),
                        "proof" to JsonArray(o.array("seeds")!!.map { LogController.witnessProof(vid, (it as JsonString).value) }))
                })
                assertTrue(same(sc["witnessFile"], witnessFile), "witness file")
            }
            val expect = sc.obj("resolve")!!
            val r = Resolver.resolve(ResolveRequest(log, expect.string("now")!!, witnessFile))
            if (r !is ResolveResult.Resolved || r.error != null) fail("did not verify: ${r.error}")
            assertTrue(same(expect["state"], r.state))
            assertEquals(expect.string("versionId"), r.metadata.versionId)
        }
    }

    @TestFactory
    fun resolution(): List<DynamicTest> =
        File(root, "resolution").listFiles { f -> f.name.endsWith(".json") }!!.sortedBy { it.name }.flatMap { file ->
            val group = file.name.removeSuffix(".json")
            load("resolution/${file.name}").list("cases").map { c ->
                DynamicTest.dynamicTest("$group/${c.string("name")}") {
                    val problems = compare(c.obj("expect")!!, Resolver.resolve(c.obj("input")!!).toJson())
                    if (problems.isNotEmpty()) fail(problems.joinToString("\n"))
                }
            }
        }

    /** Mirrors compareResolution in harness/run.ts. */
    private fun compare(expect: JsonObject, got: JsonObject): List<String> {
        val problems = ArrayList<String>()
        if (got["valid"] != expect["valid"]) problems += "valid: expected ${expect["valid"]}, got ${got["valid"]}"
        val err = got["error"] as? JsonObject
        val expectError = expect.obj("error")
        if (expectError != null) {
            val codes = expectError.array("oneOf")?.map { (it as JsonString).value } ?: listOf(expectError.string("code"))
            if (err == null || err.string("code") !in codes) problems += "error.code: expected $codes, got ${err?.string("code")}"
            if ("version" in expectError && err != null && !same(err["version"], expectError["version"])) {
                problems += "error.version: expected ${expectError["version"]}, got ${err["version"]}"
            }
        } else if (err != null) {
            problems += "unexpected error $err"
        }
        if (expect["valid"] == JsonBool.TRUE && got["valid"] == JsonBool.TRUE) {
            if (!same(expect["state"], got["state"])) problems += "state: expected ${expect["state"]}, got ${got["state"]}"
            if (!same(expect["firstInvalidVersion"] ?: JsonNull, got["firstInvalidVersion"] ?: JsonNull)) {
                problems += "firstInvalidVersion: expected ${expect["firstInvalidVersion"]}, got ${got["firstInvalidVersion"]}"
            }
            val metadata = got.obj("metadata")!!
            val warnings = metadata.array("warnings")!!.map { (it as JsonObject).string("code")!! }.sorted()
            val expectedWarnings = expect.array("warnings")?.map { (it as JsonString).value } ?: emptyList()
            if (warnings != expectedWarnings) problems += "warnings: expected $expectedWarnings, got $warnings"
            for ((k, v) in expect.obj("metadata") ?: JsonObject()) {
                if (!same(v, metadata[k])) problems += "metadata.$k: expected $v, got ${metadata[k]}"
            }
        }
        return problems
    }
}
