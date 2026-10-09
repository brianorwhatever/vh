// Interop driver: JSON Lines requests on stdin, responses on stdout (docs/interop-protocol.md).
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import VHLog

struct DriverError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

extension JSONValue {
    func string(_ key: String) throws -> String {
        guard let s = self[key]?.stringValue else { throw DriverError("input.\(key) must be a string") }
        return s
    }

    func object(_ key: String) throws -> JSONObject {
        guard let o = self[key]?.objectValue else { throw DriverError("input.\(key) must be an object") }
        return o
    }

    func signers(_ key: String) throws -> [Ed25519Signer] {
        guard let seeds = self[key]?.stringArrayValue else { throw DriverError("input.\(key) must be an array of hex seeds") }
        return try seeds.map { try Ed25519Signer(seedHex: $0) }
    }
}

func handle(_ op: String, _ i: JSONValue) throws -> JSONValue {
    switch op {
    case "jcs":
        return ["output": .string(try JCS.canonicalize(text: try i.string("text")))]
    case "hash":
        return ["output": .string(Multihash.hashB58(try i.string("data")))]
    case "multikey":
        return ["multikey": .string(try Ed25519Signer(seedHex: try i.string("seed")).multikey)]
    case "key-hash":
        return ["output": .string(Multihash.keyHash(try i.string("multikey")))]
    case "scid":
        return ["scid": .string(try computeScid(try i.object("entry")))]
    case "entry-hash":
        return ["hash": .string(try computeEntryHash(try i.object("entry"), previousVersionId: try i.string("previousVersionId")))]
    case "sign":
        var options = DataIntegrity.ProofOptions(verificationMethod: i["verificationMethod"]?.stringValue)
        options.created = i["created"]
        let signer = try Ed25519Signer(seedHex: try i.string("seed"))
        let proof = try DataIntegrity.createProof(document: i["document"] ?? .null, signer: signer, options: options)
        return ["proof": .object(proof)]
    case "verify":
        return ["valid": .bool(DataIntegrity.verifyProof(document: i["document"] ?? .null, proof: i["proof"] ?? .null))]
    case "create":
        let r = try createLog(state: i["state"] ?? .object([:]), parameters: i["parameters"]?.objectValue ?? [:],
                              versionTime: try i.string("versionTime"), signers: try i.signers("signers"))
        return ["log": .string(r.log), "scid": .string(r.scid), "versionId": .string(r.versionId)]
    case "update":
        let r = try updateLog(log: try i.string("log"), state: i["state"] ?? .object([:]),
                              parameters: i["parameters"]?.objectValue ?? [:], versionTime: try i.string("versionTime"),
                              signers: try i.signers("signers"))
        return ["log": .string(r.log), "versionId": .string(r.versionId)]
    case "witness":
        let proof = try witnessProof(versionId: try i.string("versionId"), signer: try Ed25519Signer(seedHex: try i.string("seed")),
                                     created: i["created"]?.stringValue)
        return ["proof": .object(proof)]
    case "resolve":
        return try resolve(request: i).json
    default:
        throw DriverError("unknown op \(op)")
    }
}

func respond(_ line: String) -> String {
    var id: JSONValue = .null
    var response: JSONValue
    do {
        let request = try JSONValue.parse(line)
        id = request["id"] ?? .null
        let op = request["op"]?.stringValue ?? "\(request["op"].map { (try? $0.serialized()) ?? "?" } ?? "undefined")"
        let input = request["input"].flatMap { $0.isNull ? nil : $0 } ?? .object([:])
        response = ["id": id, "ok": true, "result": try handle(op, input)]
    } catch {
        response = ["id": id, "ok": false, "error": .string(String(describing: error))]
    }
    return (try? response.serialized()) ?? #"{"id":null,"ok":false,"error":"unserialisable response"}"#
}

/// Unbuffered write(2) to fd 1, so every response is flushed immediately (and
/// without touching libc's `stdout` global, which Swift 6 flags on Linux).
func writeToStdout(_ text: String) {
    var bytes = Array(text.utf8)
    var offset = 0
    while offset < bytes.count {
        let n = bytes.withUnsafeMutableBytes { write(1, $0.baseAddress! + offset, $0.count - offset) }
        if n < 0 {
            if errno == EINTR { continue }
            exit(1)
        }
        offset += n
    }
}

while let raw = readLine(strippingNewline: false) {
    var bytes = Array(raw.utf8)
    if bytes.last == UInt8(ascii: "\n") { bytes.removeLast() }
    if bytes.allSatisfy({ [0x20, 0x09, 0x0D, 0x0B, 0x0C].contains($0) }) { continue }
    let line = String(decoding: bytes, as: UTF8.self)
    writeToStdout(respond(line) + "\n")
}
exit(0)
