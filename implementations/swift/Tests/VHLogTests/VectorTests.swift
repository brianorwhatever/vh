import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif
@testable import VHLog
import VHLogDeterministicSigning

/// Runs the shared vectors in `../../vectors` (the same checks as harness/run.ts).
/// Files are read with libc, so the tests don't depend on Foundation.
enum Vectors {
    static let root: String = {
        var parts = "\(#filePath)".split(separator: "/", omittingEmptySubsequences: false)
        parts.removeLast(3)  // Tests/VHLogTests/VectorTests.swift
        return parts.joined(separator: "/") + "/../../vectors"
    }()

    static func read(_ path: String) throws -> String {
        guard let file = fopen(root + "/" + path, "rb") else { throw VHLogInputError.invalidInput("cannot open \(path)") }
        defer { fclose(file) }
        var bytes: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = fread(&buffer, 1, buffer.count, file)
            if n <= 0 { break }
            bytes.append(contentsOf: buffer[0..<n])
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    static func load(_ path: String) throws -> JSONValue { try JSONValue.parse(read(path)) }

    static var resolutionFiles: [String] {
        guard let dir = opendir(root + "/resolution") else { return [] }
        defer { closedir(dir) }
        var names: [String] = []
        while let entry = readdir(dir) {
            let name = withUnsafeBytes(of: entry.pointee.d_name) { raw in
                String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
            }
            if name.hasSuffix(".json") { names.append(name) }
        }
        return names.sorted()
    }
}

@Suite struct PrimitiveVectorTests {
    let v: JSONValue
    init() throws { v = try Vectors.load("primitives.json") }

    @Test func jcs() throws {
        for c in v["jcs"]?.arrayValue ?? [] {
            #expect(try JCS.canonicalize(text: c["text"]!.stringValue!) == c["output"]!.stringValue!)
        }
    }

    @Test func hashesAndKeys() throws {
        for c in v["hash"]?.arrayValue ?? [] {
            #expect(Multihash.hashB58(c["data"]!.stringValue!) == c["output"]!.stringValue!)
        }
        for c in v["multikey"]?.arrayValue ?? [] {
            #expect(try DeterministicEd25519Signer(seedHex: c["seed"]!.stringValue!).multikey == c["multikey"]!.stringValue!)
        }
        for c in v["keyHash"]?.arrayValue ?? [] {
            #expect(Multihash.keyHash(c["multikey"]!.stringValue!) == c["output"]!.stringValue!)
        }
        for c in v["scid"]?.arrayValue ?? [] {
            #expect(try computeScid(c["entry"]!.objectValue!) == c["scid"]!.stringValue!)
        }
        for c in v["entryHash"]?.arrayValue ?? [] {
            #expect(try computeEntryHash(c["entry"]!.objectValue!, previousVersionId: c["previousVersionId"]!.stringValue!)
                == c["hash"]!.stringValue!)
        }
    }

    @Test func signAndVerify() throws {
        for c in v["sign"]?.arrayValue ?? [] {
            let document = c["document"]!
            let signer = try DeterministicEd25519Signer(seedHex: c["seed"]!.stringValue!)
            let proof = try DataIntegrity.createProof(document: document, signer: signer,
                                                      options: .init(created: c["created"]?.stringValue))
            #expect(JSONValue.object(proof) == c["proof"]!)
            #expect(DataIntegrity.verifyProof(document: document, proof: c["proof"]!))
            let tampered = JSONValue.object(document.objectValue!.setting("extra", 1))
            #expect(!DataIntegrity.verifyProof(document: tampered, proof: c["proof"]!))
        }
    }
}

@Suite struct ResolutionVectorTests {
    static func compare(expect: JSONValue, got: JSONValue) -> [String] {
        var problems: [String] = []
        if got["valid"] != expect["valid"] { problems.append("valid") }
        let error = got["error"].flatMap { $0.isNull ? nil : $0 }
        if let want = expect["error"], !want.isNull {
            let codes = want["oneOf"]?.arrayValue ?? [want["code"]!]
            if error == nil || !codes.contains(error!["code"]!) {
                problems.append("error.code: expected \(codes), got \(String(describing: error?["code"]))")
            }
            if let version = want["version"], let error, error["version"] != version {
                problems.append("error.version: expected \(version), got \(String(describing: error["version"]))")
            }
        } else if let error {
            problems.append("unexpected error \(error)")
        }
        if expect["valid"] == true, got["valid"] == true {
            if expect["state"] != got["state"] { problems.append("state") }
            if (got["firstInvalidVersion"] ?? .null) != (expect["firstInvalidVersion"] ?? .null) {
                problems.append("firstInvalidVersion")
            }
            let warnings = (got["metadata"]?["warnings"]?.arrayValue ?? []).compactMap { $0["code"]?.stringValue }.sorted()
            let expected = (expect["warnings"]?.arrayValue ?? []).compactMap(\.stringValue)
            if warnings != expected { problems.append("warnings: expected \(expected), got \(warnings)") }
            for m in expect["metadata"]?.objectValue?.members ?? [] where got["metadata"]?[m.key] != m.value {
                problems.append("metadata.\(m.key)")
            }
        }
        return problems
    }

    @Test(arguments: Vectors.resolutionFiles)
    func group(file: String) throws {
        let cases = try Vectors.load("resolution/\(file)")["cases"]?.arrayValue ?? []
        #expect(!cases.isEmpty)
        for c in cases {
            let result = try resolve(request: c["input"]!)
            let problems = Self.compare(expect: c["expect"]!, got: result.json)
            #expect(problems.isEmpty, "\(file) \(c["name"]!.stringValue!): \(problems)")
        }
    }
}

@Suite struct GenerationVectorTests {
    @Test func scenarios() throws {
        let scenarios = try Vectors.load("generation.json")["scenarios"]?.arrayValue ?? []
        #expect(!scenarios.isEmpty)
        for sc in scenarios {
            let name = sc["name"]!.stringValue!
            var log = "", scid = ""
            var versionIds: [String] = []
            for step in sc["steps"]!.arrayValue! {
                var input = step["input"]!
                if !scid.isEmpty {
                    input = try JSONValue.parse(replacingBytes(in: input.serialized(), scidPlaceholder, with: scid))
                }
                let signers = try input["signers"]!.stringArrayValue!.map { try DeterministicEd25519Signer(seedHex: $0) }
                let versionId: String
                if step["op"] == "create" {
                    let r = try createLog(state: input["state"]!, parameters: input["parameters"]!.objectValue!,
                                          versionTime: input["versionTime"]!.stringValue!, signers: signers)
                    (log, scid, versionId) = (r.log, r.scid, r.versionId)
                    #expect(r.scid == step["expect"]!["scid"]!.stringValue!, "\(name)")
                } else {
                    let r = try updateLog(log: log, state: input["state"]!, parameters: input["parameters"]!.objectValue!,
                                          versionTime: input["versionTime"]!.stringValue!, signers: signers)
                    (log, versionId) = (r.log, r.versionId)
                }
                versionIds.append(versionId)
                #expect(versionId == step["expect"]!["versionId"]!.stringValue!, "\(name)")
                #expect(try JSONValue.parse(parseLogLines(log).last!) == step["expect"]!["line"]!, "\(name)")
            }
            var witnessFile: JSONValue?
            if let witness = sc["witness"]?.arrayValue {
                var records: [JSONValue] = []
                for w in witness {
                    let versionId = versionIds[Int(w["step"]!.numberValue!) - 1]
                    let proofs = try w["seeds"]!.stringArrayValue!.map {
                        JSONValue.object(try witnessProof(versionId: versionId, signer: DeterministicEd25519Signer(seedHex: $0)))
                    }
                    records.append(["versionId": .string(versionId), "proof": .array(proofs)])
                }
                witnessFile = .array(records)
                #expect(witnessFile == sc["witnessFile"]!, "\(name) witness file")
            }
            let expected = sc["resolve"]!
            let result = resolve(ResolveInput(log: log, witness: witnessFile, now: expected["now"]!.stringValue!))
            guard case .resolved(let r) = result else {
                Issue.record("\(name) did not resolve: \(result.json)")
                continue
            }
            #expect(r.error == nil)
            #expect(r.state == expected["state"]!, "\(name)")
            #expect(r.metadata.versionId == expected["versionId"]!.stringValue!, "\(name)")
        }
    }
}

@Suite struct ExternalVectorTests {
    /// didwebvh-ts logs: SCID, entry hashes, proofs and witness proofs (not resolved as VH-Logs).
    @Test func didwebvhTS() throws {
        let dir = "external/didwebvh-ts"
        let scenarios = try Vectors.load("\(dir)/manifest.json")["scenarios"]?.arrayValue ?? []
        #expect(!scenarios.isEmpty)
        for sc in scenarios {
            let name = sc["name"]!.stringValue!
            let text = try Vectors.read("\(dir)/\(name).jsonl")
            let entries = try parseLogLines(text).map { try JSONValue.parse($0).objectValue! }
            let scid = entries[0]["parameters"]!["scid"]!.stringValue!
            for (i, entry) in entries.enumerated() {
                let document = entry.removing("proof")
                if i == 0 {
                    let preliminary = try replacingText(in: document.setting("versionId", .string(scidPlaceholder)), scid,
                                                        with: scidPlaceholder)
                    #expect(try computeScid(preliminary) == scid)
                }
                let versionId = entry["versionId"]!.stringValue!
                let hash = String(versionId.split(separator: "-")[1])
                let previous = i == 0 ? scid : entries[i - 1]["versionId"]!.stringValue!
                #expect(try computeEntryHash(document, previousVersionId: previous) == hash, "\(name) #\(i + 1)")
                for proof in entry["proof"]!.arrayValue! {
                    #expect(DataIntegrity.verifyProof(document: .object(document), proof: proof))
                }
            }
            if let w = sc["witness"], w != .null, w != false {
                let file = try Vectors.load("\(dir)/\(name).witness.json")
                for record in file.arrayValue! {
                    for proof in record["proof"]!.arrayValue! {
                        #expect(DataIntegrity.verifyProof(document: ["versionId": record["versionId"]!], proof: proof))
                    }
                }
            }
        }
    }
}
