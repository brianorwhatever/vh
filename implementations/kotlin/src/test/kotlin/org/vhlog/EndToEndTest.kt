package org.vhlog

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EndToEndTest {
    private val k1 = "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa"
    private val k2 = "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6"
    private val w1 = "b2f56f12a0b0513455e61f01bb11b5af580fdf1bd4ea1b560bc4bf96ee1e0162"
    private val mk1 = Ed25519Signer.fromSeedHex(k1).multikey
    private val mk2 = Ed25519Signer.fromSeedHex(k2).multikey
    private val now = "2026-06-01T00:00:00Z"

    private fun strings(vararg s: String) = JsonArray(s.map(::JsonString))
    private fun state(name: String) = JsonObject("id" to JsonString("example:{SCID}"), "name" to JsonString(name))

    @Test
    fun `create, update, rotate and deactivate`() {
        val created = VHLog.createLog(state("one"), JsonObject("updateKeys" to strings(mk1)), "2026-01-01T00:00:00Z", listOf(k1))
        assertTrue(created.versionId.startsWith("1-Qm"))
        assertTrue(created.log.endsWith("\n"))
        val first = Json.parse(created.log.trim()) as JsonObject
        assertEquals("example:${created.scid}", first.obj("state")!!.string("id"))

        val rotated = VHLog.updateLog(created.log, state("two"), "2026-01-02T00:00:00Z", listOf(k1),
            JsonObject("updateKeys" to strings(mk2)))
        val updated = VHLog.updateLog(rotated.log, state("three"), "2026-01-03T00:00:00Z", listOf(k2))
        val resolved = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(updated.log, now)))
        assertEquals(updated.versionId, resolved.metadata.versionId)
        assertEquals(3, resolved.metadata.versionNumber)
        assertEquals(listOf(mk2), resolved.metadata.updateKeys)
        assertEquals(created.scid, resolved.metadata.scid)
        assertNull(resolved.firstInvalidVersion)

        val v1 = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(updated.log, now, options = ResolveOptions(versionNumber = 1))))
        assertEquals("one", v1.state.string("name"))

        val deactivated = VHLog.updateLog(updated.log, state("gone"), "2026-01-04T00:00:00Z", listOf(k2),
            JsonObject("deactivated" to JsonBool.TRUE))
        val afterDeactivation = VHLog.updateLog(deactivated.log, state("zombie"), "2026-01-05T00:00:00Z", listOf(k2))
        val r = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(afterDeactivation.log, now)))
        assertTrue(r.metadata.deactivated)
        assertEquals(5, r.firstInvalidVersion)
        assertEquals(ErrorCode.ENTRY_AFTER_DEACTIVATION, r.error!!.code)
        assertEquals(listOf("invalid-entries"), r.metadata.warnings.map { it.code })
    }

    @Test
    fun `an unauthorised key invalidates the entry`() {
        val created = VHLog.createLog(state("one"), JsonObject("updateKeys" to strings(mk1)), "2026-01-01T00:00:00Z", listOf(k1))
        val bad = VHLog.updateLog(created.log, state("two"), "2026-01-02T00:00:00Z", listOf(k2))
        val r = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(bad.log, now)))
        assertEquals(2, r.firstInvalidVersion)
        assertEquals(ErrorCode.UNAUTHORIZED_KEY, r.error!!.code)
        val target = VHLog.resolve(ResolveRequest(bad.log, now, options = ResolveOptions(versionNumber = 2)))
        assertEquals(ErrorCode.UNAUTHORIZED_KEY, assertIs<ResolveResult.Failed>(target).error.code)
    }

    @Test
    fun `pre-rotation requires committed keys`() {
        val params = JsonObject("updateKeys" to strings(mk1), "nextKeyHashes" to strings(Hashes.keyHash(mk2)))
        val created = VHLog.createLog(state("one"), params, "2026-01-01T00:00:00Z", listOf(k1))
        val ok = VHLog.updateLog(created.log, state("two"), "2026-01-02T00:00:00Z", listOf(k2),
            JsonObject("updateKeys" to strings(mk2), "nextKeyHashes" to JsonArray()))
        assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(ok.log, now))).also { assertNull(it.error) }

        val bad = VHLog.updateLog(created.log, state("two"), "2026-01-02T00:00:00Z", listOf(k1),
            JsonObject("updateKeys" to strings(mk1), "nextKeyHashes" to JsonArray()))
        val r = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(bad.log, now)))
        assertEquals(ErrorCode.PREROTATION_VIOLATION, r.error!!.code)
    }

    @Test
    fun `witnessing applies from the entry that enables it`() {
        val witnessId = "did:key:" + Ed25519Signer.fromSeedHex(w1).multikey
        val witness = JsonObject("threshold" to JsonNumber(1), "witnesses" to JsonArray(JsonObject("id" to JsonString(witnessId))))
        val created = VHLog.createLog(state("one"), JsonObject("updateKeys" to strings(mk1), "witness" to witness),
            "2026-01-01T00:00:00Z", listOf(k1))
        val updated = VHLog.updateLog(created.log, state("two"), "2026-01-02T00:00:00Z", listOf(k1))

        val none = VHLog.resolve(ResolveRequest(updated.log, now))
        assertEquals(ErrorCode.WITNESS_THRESHOLD_NOT_MET, assertIs<ResolveResult.Failed>(none).error.code)

        // A proof for version 2 also approves version 1.
        val file = JsonArray(JsonObject("versionId" to JsonString(updated.versionId),
            "proof" to JsonArray(VHLog.witnessProof(updated.versionId, w1))))
        val r = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(updated.log, now, witness = file)))
        assertNull(r.error)
        assertEquals(witness.toJson(), r.metadata.witness!!.toJson().toJson())

        val malformed = VHLog.resolve(ResolveRequest(updated.log, now, witness = JsonNull))
        assertEquals(ErrorCode.INVALID_WITNESS_FILE, assertIs<ResolveResult.Failed>(malformed).error.code)
    }

    @Test
    fun `copies that diverge are a fork`() {
        val created = VHLog.createLog(state("one"), JsonObject("updateKeys" to strings(mk1)), "2026-01-01T00:00:00Z", listOf(k1))
        val a = VHLog.updateLog(created.log, state("a"), "2026-01-02T00:00:00Z", listOf(k1))
        val b = VHLog.updateLog(created.log, state("b"), "2026-01-02T00:00:00Z", listOf(k1))

        val behind = VHLog.resolve(ResolveRequest(a.log, now, copies = listOf(
            CopyInput.Available("https://w1.example", created.log),
            CopyInput.Unavailable("https://w2.example", "timeout"),
        )))
        val r = assertIs<ResolveResult.Resolved>(behind)
        assertEquals(listOf(CopyStatus.CURRENT, CopyStatus.BEHIND, CopyStatus.UNAVAILABLE), r.metadata.copies!!.map { it.status })

        val fork = VHLog.resolve(ResolveRequest(a.log, now, copies = listOf(CopyInput.Available("https://w1.example", b.log))))
        val error = assertIs<ResolveResult.Failed>(fork).error
        assertEquals(ErrorCode.FORK_DETECTED, error.code)
        assertEquals(2, error.fork!!.version)

        val retained = VHLog.resolve(ResolveRequest(a.log, now, retainedVersionId = b.versionId))
        assertEquals(ErrorCode.FORK_DETECTED, assertIs<ResolveResult.Failed>(retained).error.code)
    }

    @Test
    fun `invalid options are reported, not thrown`() {
        val created = VHLog.createLog(state("one"), JsonObject("updateKeys" to strings(mk1)), "2026-01-01T00:00:00Z", listOf(k1))
        val request = Json.parse("""{"log":${Json.stringify(JsonString(created.log))},"now":"$now","options":{"versionNumber":1,"versionId":"x"}}""")
        assertEquals(ErrorCode.INVALID_OPTION, assertIs<ResolveResult.Failed>(VHLog.resolve(request as JsonObject)).error.code)
        val unknown = request.with("options", JsonObject("colour" to JsonString("red")))
        assertEquals(ErrorCode.INVALID_OPTION, assertIs<ResolveResult.Failed>(VHLog.resolve(unknown)).error.code)
    }

    @Test
    fun `the README example works`() {
        val seed = "01".repeat(32)
        val key = Ed25519Signer.fromSeedHex(seed)
        val created = VHLog.createLog(
            state = JsonObject("id" to JsonString("example:{SCID}")),
            parameters = JsonObject("updateKeys" to JsonArray(JsonString(key.multikey))),
            versionTime = "2026-01-01T00:00:00Z",
            signers = listOf(seed),
        )
        val updated = VHLog.updateLog(
            created.log,
            JsonObject("id" to JsonString("example:${created.scid}"), "name" to JsonString("updated")),
            "2026-01-02T00:00:00Z",
            listOf(seed),
        )
        val r = assertIs<ResolveResult.Resolved>(VHLog.resolve(ResolveRequest(updated.log, now = "2026-06-01T00:00:00Z")))
        assertEquals("updated", r.state.string("name"))
        assertEquals(updated.versionId, r.metadata.versionId)
    }
}
