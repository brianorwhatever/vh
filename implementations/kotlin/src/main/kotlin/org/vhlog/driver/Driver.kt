// Interop driver: JSON Lines requests on stdin, responses on stdout (docs/interop-protocol.md).
package org.vhlog.driver

import org.vhlog.Ed25519Signer
import org.vhlog.Hashes
import org.vhlog.Jcs
import org.vhlog.Json
import org.vhlog.JsonBool
import org.vhlog.JsonNull
import org.vhlog.JsonObject
import org.vhlog.JsonString
import org.vhlog.JsonValue
import org.vhlog.LogController
import org.vhlog.ProofOptions
import org.vhlog.Proofs
import org.vhlog.Resolver
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.InputStream

private fun JsonObject.str(key: String): String =
    string(key) ?: throw IllegalArgumentException("$key must be a string")

private fun JsonObject.objOf(key: String): JsonObject =
    obj(key) ?: throw IllegalArgumentException("$key must be an object")

private fun JsonObject.value(key: String): JsonValue =
    this[key] ?: throw IllegalArgumentException("$key is required")

private fun JsonObject.strings(key: String): List<String> =
    (array(key) ?: throw IllegalArgumentException("$key must be an array")).map {
        (it as? JsonString)?.value ?: throw IllegalArgumentException("$key must contain strings")
    }

private fun result(vararg members: Pair<String, JsonValue>) = JsonObject(*members)

private val ops: Map<String, (JsonObject) -> JsonValue> = mapOf(
    "jcs" to { i -> result("output" to JsonString(Jcs.canonicalize(Json.parse(i.str("text"))))) },
    "hash" to { i -> result("output" to JsonString(Hashes.hashB58(i.str("data")))) },
    "multikey" to { i -> result("multikey" to JsonString(Ed25519Signer.fromSeedHex(i.str("seed")).multikey)) },
    "key-hash" to { i -> result("output" to JsonString(Hashes.keyHash(i.str("multikey")))) },
    "scid" to { i -> result("scid" to JsonString(LogController.computeScid(i.objOf("entry")))) },
    "entry-hash" to { i ->
        result("hash" to JsonString(LogController.computeEntryHash(i.objOf("entry"), i.str("previousVersionId"))))
    },
    "sign" to { i ->
        val options = ProofOptions(verificationMethod = i.string("verificationMethod"), created = i.string("created"))
        result("proof" to Proofs.create(i.value("document"), i.str("seed"), options))
    },
    "verify" to { i -> result("valid" to JsonBool.of(Proofs.verify(i.value("document"), i.value("proof")))) },
    "create" to { i ->
        val r = LogController.createLog(i.objOf("state"), i.objOf("parameters"), i.str("versionTime"), i.strings("signers"))
        result("log" to JsonString(r.log), "scid" to JsonString(r.scid), "versionId" to JsonString(r.versionId))
    },
    "update" to { i ->
        val r = LogController.updateLog(
            i.str("log"), i.objOf("state"), i.str("versionTime"), i.strings("signers"), i.obj("parameters") ?: JsonObject(),
        )
        result("log" to JsonString(r.log), "versionId" to JsonString(r.versionId))
    },
    "witness" to { i -> result("proof" to LogController.witnessProof(i.str("versionId"), i.str("seed"), i.string("created"))) },
    "resolve" to { i -> Resolver.resolve(i).toJson() },
)

/** Handles one request line and returns the response object. */
fun handle(line: String): JsonObject {
    var id: JsonValue = JsonNull
    return try {
        val request = Json.parse(line) as? JsonObject ?: throw IllegalArgumentException("request must be an object")
        id = request["id"] ?: JsonNull
        val opName = request.string("op")
        val op = ops[opName] ?: throw IllegalArgumentException("unknown op $opName")
        val input = when (val raw = request["input"]) {
            null, JsonNull -> JsonObject()
            is JsonObject -> raw
            else -> throw IllegalArgumentException("input must be an object")
        }
        JsonObject("id" to id, "ok" to JsonBool.TRUE, "result" to op(input))
    } catch (e: Exception) {
        JsonObject("id" to id, "ok" to JsonBool.FALSE, "error" to JsonString(e.message ?: e.toString()))
    } catch (e: StackOverflowError) {
        JsonObject("id" to id, "ok" to JsonBool.FALSE, "error" to JsonString("input nested too deeply"))
    }
}

/** Yields `\n`-terminated lines decoded as UTF-8; `\r`, U+2028 and U+2029 are not separators. */
private fun lines(input: InputStream): Sequence<String> = sequence {
    val buffer = ByteArrayOutputStream()
    val stream = BufferedInputStream(input, 1 shl 16)
    while (true) {
        val b = stream.read()
        if (b == -1) break
        if (b == '\n'.code) {
            yield(buffer.toString(Charsets.UTF_8))
            buffer.reset()
        } else {
            buffer.write(b)
        }
    }
    if (buffer.size() > 0) yield(buffer.toString(Charsets.UTF_8))
}

fun main() {
    val out = BufferedOutputStream(FileOutputStream(FileDescriptor.out), 1 shl 16)
    for (line in lines(System.`in`)) {
        if (line.isBlank()) continue
        out.write((handle(line).toJson() + "\n").toByteArray(Charsets.UTF_8))
        out.flush()
    }
    out.flush()
}
