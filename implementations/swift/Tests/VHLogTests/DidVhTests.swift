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

/// did:vh library tests: every did:vh vector, and the specialisation hook
/// keeping VH-Log and did:vh logs apart.
@Suite struct DidVhTests {
    static let now = "2026-06-01T00:00:00Z"

    static var resolutionFiles: [String] {
        guard let dir = opendir(Vectors.root + "/didvh/resolution") else { return [] }
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

    func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        (try? JCS.canonicalize(a ?? .null)) == (try? JCS.canonicalize(b ?? .null))
    }

    func signer() throws -> DeterministicEd25519Signer { try DeterministicEd25519Signer(seedHex: String(repeating: "11", count: 32)) }

    @Test func resolutionVectors() throws {
        let files = Self.resolutionFiles
        #expect(!files.isEmpty)
        for file in files {
            for c in try Vectors.load("didvh/resolution/" + file)["cases"]?.arrayValue ?? [] {
                let name = "\(file)/\(c["name"]?.stringValue ?? "?")"
                let input = c["input"]!, expect = c["expect"]!
                let context = DidVh.ResolverContext(now: input["now"]?.stringValue, remote: input["remote"]?.boolValue ?? false)
                let got = DidVh.resolve(did: input["did"]?.stringValue ?? "", options: input["options"] ?? .object([:]),
                                        context: context).json
                let meta = got["didResolutionMetadata"]
                if let error = expect["error"] {
                    #expect(same(meta?["error"], error), "\(name)")
                    if let code = expect["vhLogError"] {
                        #expect(same(meta?["problemDetails"]?["vhLog"]?["code"], code), "\(name)")
                    }
                    continue
                }
                #expect(meta?["error"] == nil, "\(name)")
                #expect(same(got["didDocument"], expect["didDocument"]), "\(name)")
                #expect(same(got["didDocumentMetadata"], expect["didDocumentMetadata"]), "\(name)")
                #expect(same(meta?["didLog"], expect["didLog"]), "\(name)")
                #expect(same(meta?["didWitness"], expect["didWitness"]), "\(name)")
            }
        }
    }

    func outcome(_ body: () throws(DidVhError) -> JSONValue) -> JSONValue {
        do throws(DidVhError) {
            return try body()
        } catch {
            return ["valid": false, "error": .string(error.code.rawValue)]
        }
    }

    @Test func referenceSrcAndDidURLVectors() throws {
        for c in try Vectors.load("didvh/ref.json")["cases"]?.arrayValue ?? [] {
            let got = outcome { () throws(DidVhError) in
                guard let ref = c["ref"]?.stringValue else { throw DidVhError(.invalidOptions, "not a string") }
                return ["valid": true, "kind": .string(try DidVh.checkRef(ref).rawValue)]
            }
            #expect(same(got, c["expect"]), "ref/\(c["name"]?.stringValue ?? "?")")
        }
        for c in try Vectors.load("didvh/src.json")["cases"]?.arrayValue ?? [] {
            let got = outcome { () throws(DidVhError) in
                let refs = try DidVh.srcReferences(c["src"]?.stringValue ?? "")
                return ["valid": true, "srcLog": .string(refs.srcLog), "srcWitness": .string(refs.srcWitness)]
            }
            #expect(same(got, c["expect"]), "src/\(c["name"]?.stringValue ?? "?")")
        }
        for c in try Vectors.load("didvh/did-url.json")["cases"]?.arrayValue ?? [] {
            let got = outcome { () throws(DidVhError) in
                guard let url = c["didUrl"]?.stringValue else { throw DidVhError(.invalidDidUrl, "not a string") }
                let u = try DidVh.parseDidURL(url)
                var out: JSONObject = ["valid": true, "did": .string(u.did), "options": .object(u.options)]
                if let fragment = u.fragment { out["fragment"] = .string(fragment) }
                return .object(out)
            }
            #expect(same(got, c["expect"]), "did-url/\(c["name"]?.stringValue ?? "?")")
        }
    }

    @Test func createUpdateAndResolve() throws {
        let key = try signer()
        let created = try DidVh.createDid(document: ["id": "did:vh:{SCID}", "controller": "did:vh:{SCID}"],
                                          parameters: ["updateKeys": [.string(key.multikey)]],
                                          versionTime: "2026-01-01T00:00:00Z", signers: [key])
        #expect(DidVh.parseDid(created.did) == created.scid)
        let line = try JSONValue.parse(created.log)
        #expect(line["parameters"]?["method"]?.stringValue == DidVh.method)
        #expect(line["parameters"]?["logVersion"] == nil)
        #expect(line["state"]?["controller"]?.stringValue == created.did)

        let updated = try DidVh.updateDid(log: created.log, document: ["id": .string(created.did), "v": 2],
                                          versionTime: "2026-01-02T00:00:00Z", signers: [key])
        guard case .resolved(let document, let metadata, _, _, _) =
            DidVh.resolve(did: created.did, options: ["didLog": .string(updated.log)], context: .init(now: Self.now))
        else { Issue.record("did not resolve"); return }
        #expect(same(document.map { .object($0) }, ["id": .string(created.did), "v": 2]))
        #expect(metadata.versionId == updated.versionId)
    }

    @Test func vhLogAndDidVhLogsAreNotInterchangeable() throws {
        let key = try signer()
        let params: JSONObject = ["updateKeys": [.string(key.multikey)]]
        let vh = try createLog(state: ["id": "did:vh:{SCID}"], parameters: params, versionTime: "2026-01-01T00:00:00Z",
                               signers: [key])
        guard case .failed(let e) = DidVh.resolve(did: "did:vh:" + vh.scid, options: ["didLog": .string(vh.log)],
                                                  context: .init(now: Self.now))
        else { Issue.record("a VH-Log log resolved as did:vh"); return }
        #expect(e.code == .invalidDid)

        let did = try DidVh.createDid(document: ["id": "did:vh:{SCID}"], parameters: params,
                                      versionTime: "2026-01-01T00:00:00Z", signers: [key])
        guard case .failed(let f) = resolve(ResolveInput(log: did.log, now: Self.now)) else {
            Issue.record("a did:vh log resolved as VH-Log"); return
        }
        #expect(f.code == .unsupportedLogVersion)
    }
}
