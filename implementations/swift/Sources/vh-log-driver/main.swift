// Interop driver: JSON Lines requests on stdin, responses on stdout (docs/interop-protocol.md).
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
import VHLog
import VHLogDeterministicSigning

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

    func signers(_ key: String) throws -> [DeterministicEd25519Signer] {
        guard let seeds = self[key]?.stringArrayValue else { throw DriverError("input.\(key) must be an array of hex seeds") }
        return try seeds.map { try DeterministicEd25519Signer(seedHex: $0) }
    }
}

func handle(_ op: String, _ i: JSONValue) throws -> JSONValue {
    switch op {
    case "jcs":
        return ["output": .string(try JCS.canonicalize(text: try i.string("text")))]
    case "hash":
        return ["output": .string(Multihash.hashB58(try i.string("data")))]
    case "multikey":
        return ["multikey": .string(try DeterministicEd25519Signer(seedHex: try i.string("seed")).multikey)]
    case "key-hash":
        return ["output": .string(Multihash.keyHash(try i.string("multikey")))]
    case "scid":
        return ["scid": .string(try computeScid(try i.object("entry")))]
    case "entry-hash":
        return ["hash": .string(try computeEntryHash(try i.object("entry"), previousVersionId: try i.string("previousVersionId")))]
    case "sign":
        var options = DataIntegrity.ProofOptions(verificationMethod: i["verificationMethod"]?.stringValue)
        options.created = i["created"]
        let signer = try DeterministicEd25519Signer(seedHex: try i.string("seed"))
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
        let proof = try witnessProof(versionId: try i.string("versionId"), signer: try DeterministicEd25519Signer(seedHex: try i.string("seed")),
                                     created: i["created"]?.stringValue)
        return ["proof": .object(proof)]
    case "resolve":
        return try resolve(request: i).json
    // did:vh (docs/interop-protocol.md, "did:vh operations")
    case "didvh-create":
        let r = try DidVh.createDid(document: i["document"] ?? .object([:]), parameters: i["parameters"]?.objectValue ?? [:],
                                    versionTime: try i.string("versionTime"), signers: try i.signers("signers"))
        return ["log": .string(r.log), "did": .string(r.did), "scid": .string(r.scid), "versionId": .string(r.versionId)]
    case "didvh-update":
        let r = try DidVh.updateDid(log: try i.string("log"), document: i["document"] ?? .object([:]),
                                    parameters: i["parameters"]?.objectValue ?? [:], versionTime: try i.string("versionTime"),
                                    signers: try i.signers("signers"))
        return ["log": .string(r.log), "versionId": .string(r.versionId)]
    case "didvh-resolve":
        let context = DidVh.ResolverContext(now: i["now"].map { $0.stringValue ?? "" }, remote: i["remote"]?.boolValue ?? false)
        return DidVh.resolve(did: i["did"]?.stringValue ?? "", options: i["options"] ?? .object([:]), context: context).json
    case "didvh-ref":
        return rejected { () throws(DidVhError) in
            guard let ref = i["ref"]?.stringValue else { throw DidVhError(.invalidOptions, "ref must be a string") }
            return ["valid": true, "kind": .string(try DidVh.checkRef(ref).rawValue)]
        }
    case "didvh-src":
        return rejected { () throws(DidVhError) in
            guard let src = i["src"]?.stringValue else { throw DidVhError(.invalidDidUrl, "src must be a string") }
            let refs = try DidVh.srcReferences(src)
            return ["valid": true, "srcLog": .string(refs.srcLog), "srcWitness": .string(refs.srcWitness)]
        }
    case "didvh-did-url":
        return rejected { () throws(DidVhError) in
            guard let didURL = i["didUrl"]?.stringValue else { throw DidVhError(.invalidDidUrl, "didUrl must be a string") }
            let u = try DidVh.parseDidURL(didURL)
            var out: JSONObject = ["valid": true, "did": .string(u.did), "options": .object(u.options)]
            if let fragment = u.fragment { out["fragment"] = .string(fragment) }
            return .object(out)
        }
    default:
        throw DriverError("unknown op \(op)")
    }
}

/// Runs `body`, turning a did:vh error into `{"valid": false, "error": code}`.
func rejected(_ body: () throws(DidVhError) -> JSONValue) -> JSONValue {
    do throws(DidVhError) {
        return try body()
    } catch {
        return ["valid": false, "error": .string(error.code.rawValue)]
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
