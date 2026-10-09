import Testing
@testable import VHLog

@Suite struct EndToEndTests {
    let k1 = try! Ed25519Signer(seedHex: "90930409d492fb6cd7b50542c97fc6003fcedd59012b47ac114417373796eaaa")
    let k2 = try! Ed25519Signer(seedHex: "e0203d7f35f898d2c66bbc45b1d5ed23410af56e775d3601a1f4ee3f22987ea6")
    let w1 = try! Ed25519Signer(seedHex: "b2f56f12a0b0513455e61f01bb11b5af580fdf1bd4ea1b560bc4bf96ee1e0162")
    let now = "2026-06-01T00:00:00Z"

    func resolved(_ result: ResolveResult) throws -> Resolution {
        guard case .resolved(let r) = result else {
            Issue.record("expected a resolution, got \(result.json)")
            throw VHLogInputError.invalidInput("not resolved")
        }
        return r
    }

    @Test func createUpdateResolve() throws {
        let created = try createLog(state: ["id": "example:{SCID}"],
                                    parameters: ["updateKeys": [.string(k1.multikey)]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        #expect(created.versionId.hasPrefix("1-Qm"))
        let updated = try updateLog(log: created.log, state: ["id": .string("example:\(created.scid)"), "n": 2],
                                    versionTime: "2026-01-02T00:00:00Z", signers: [k1])
        #expect(updated.versionId.hasPrefix("2-Qm"))

        let latest = try resolved(resolve(ResolveInput(log: updated.log, now: now)))
        #expect(latest.state == ["id": .string("example:\(created.scid)"), "n": 2])
        #expect(latest.metadata.versionNumber == 2)
        #expect(latest.metadata.scid == created.scid)
        #expect(latest.metadata.created == "2026-01-01T00:00:00Z")
        #expect(latest.metadata.updated == "2026-01-02T00:00:00Z")
        #expect(latest.firstInvalidVersion == nil)

        let first = try resolved(resolve(ResolveInput(log: updated.log, now: now, options: .init(versionNumber: 1))))
        #expect(first.metadata.versionId == created.versionId)
        let byTime = try resolved(resolve(ResolveInput(log: updated.log, now: now,
                                                       options: .init(versionTime: "2026-01-01T12:00:00Z"))))
        #expect(byTime.metadata.versionNumber == 1)
        guard case .failed(let e) = resolve(ResolveInput(log: updated.log, now: now, options: .init(versionNumber: 3))) else {
            Issue.record("expected not-found"); return
        }
        #expect(e.code == .notFound)
    }

    @Test func unauthorizedUpdateInvalidatesTheTail() throws {
        let created = try createLog(state: [:], parameters: ["updateKeys": [.string(k1.multikey)]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        let bad = try updateLog(log: created.log, state: ["x": 1], versionTime: "2026-01-02T00:00:00Z", signers: [k2])
        let r = try resolved(resolve(ResolveInput(log: bad.log, now: now)))
        #expect(r.firstInvalidVersion == 2)
        #expect(r.error?.code == .unauthorizedKey)
        #expect(r.metadata.warnings.map(\.code) == ["invalid-entries"])
        guard case .failed(let e) = resolve(ResolveInput(log: bad.log, now: now, options: .init(versionNumber: 2))) else {
            Issue.record("expected failure"); return
        }
        #expect(e.code == .unauthorizedKey)
        #expect(e.version == 2)
    }

    @Test func preRotation() throws {
        let created = try createLog(state: [:], parameters: ["updateKeys": [.string(k1.multikey)],
                                                             "nextKeyHashes": [.string(Multihash.keyHash(k2.multikey))]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        let rotated = try updateLog(log: created.log, state: [:],
                                    parameters: ["updateKeys": [.string(k2.multikey)], "nextKeyHashes": []],
                                    versionTime: "2026-01-02T00:00:00Z", signers: [k2])
        #expect(try resolved(resolve(ResolveInput(log: rotated.log, now: now))).metadata.updateKeys == [k2.multikey])
        let implicit = try updateLog(log: created.log, state: [:], versionTime: "2026-01-02T00:00:00Z", signers: [k1])
        #expect(try resolved(resolve(ResolveInput(log: implicit.log, now: now))).error?.code == .prerotationViolation)
    }

    @Test func witnessing() throws {
        let witnessId = "did:key:\(w1.multikey)"
        let created = try createLog(state: [:], parameters: ["updateKeys": [.string(k1.multikey)],
                                                             "witness": ["threshold": 1, "witnesses": [["id": .string(witnessId)]]]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        let unwitnessed = resolve(ResolveInput(log: created.log, now: now))
        guard case .failed(let e) = unwitnessed else { Issue.record("expected failure"); return }
        #expect(e.code == .witnessThresholdNotMet)

        let proof = try witnessProof(versionId: created.versionId, signer: w1)
        let file: JSONValue = [["versionId": .string(created.versionId), "proof": [.object(proof)]]]
        let r = try resolved(resolve(ResolveInput(log: created.log, witness: file, now: now)))
        #expect(r.metadata.witness?.threshold == 1)
        #expect(r.metadata.witness?.ids == [witnessId])
        guard case .failed(let malformed) = resolve(ResolveInput(log: created.log, witness: .null, now: now)) else {
            Issue.record("expected failure"); return
        }
        #expect(malformed.code == .invalidWitnessFile)
    }

    @Test func deactivationAndCopies() throws {
        let created = try createLog(state: [:], parameters: ["updateKeys": [.string(k1.multikey)]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        let deactivated = try updateLog(log: created.log, state: [:], parameters: ["deactivated": true],
                                        versionTime: "2026-01-02T00:00:00Z", signers: [k1])
        let r = try resolved(resolve(ResolveInput(
            log: deactivated.log, now: now,
            copies: [.available(source: "https://w1.example", log: created.log, witness: nil),
                     .unavailable(source: "https://w2.example", reason: "timeout")])))
        #expect(r.metadata.deactivated)
        #expect(r.metadata.copies?.map(\.status) == [.current, .behind, .unavailable])
        #expect(Set(r.metadata.warnings.map(\.code)) == ["copy-behind", "copy-unavailable"])

        let fork = try updateLog(log: created.log, state: ["other": true], versionTime: "2026-01-02T00:00:00Z", signers: [k1])
        guard case .failed(let e) = resolve(ResolveInput(
            log: deactivated.log, now: now, copies: [.available(source: "https://w1.example", log: fork.log, witness: nil)]))
        else { Issue.record("expected fork"); return }
        #expect(e.code == .forkDetected)
        #expect(e.fork?.version == 2)
        guard case .failed(let retained) = resolve(ResolveInput(log: deactivated.log, now: now, retainedVersionId: fork.versionId))
        else { Issue.record("expected fork"); return }
        #expect(retained.code == .forkDetected)
        #expect(retained.fork?.copies.first?.source == "retained")
    }

    @Test func scidReplacementUsesExactCodeUnits() throws {
        // "{SCID}" followed by a combining mark is one Swift Character but must still be replaced.
        let created = try createLog(state: ["id": "x:{SCID}\u{301}", "{SCID}": "key"],
                                    parameters: ["updateKeys": [.string(k1.multikey)]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        let line = try JSONValue.parse(parseLogLines(created.log)[0])
        #expect(line["state"]?["id"] == .string("x:\(created.scid)\u{301}"))
        #expect(line["state"]?[created.scid] == "key")
        #expect(try resolved(resolve(ResolveInput(log: created.log, now: now))).error == nil)
    }

    @Test func invalidLines() throws {
        let created = try createLog(state: [:], parameters: ["updateKeys": [.string(k1.multikey)]],
                                    versionTime: "2026-01-01T00:00:00Z", signers: [k1])
        for tail in [#"{"a":"\ud800"}"#, #"{"a":1e400}"#, "[1]", "not json"] {
            let r = try resolved(resolve(ResolveInput(log: created.log + tail + "\n", now: now)))
            #expect(r.error?.code == .invalidLog, "\(tail)")
            #expect(r.firstInvalidVersion == 2)
        }
        guard case .failed(let e) = resolve(ResolveInput(log: "", now: now)) else { Issue.record("expected failure"); return }
        #expect(e.code == .invalidLog)
        guard case .failed(let o) = resolve(ResolveInput(log: created.log, now: now, options: .init(versionId: "x", versionNumber: 1)))
        else { Issue.record("expected failure"); return }
        #expect(o.code == .invalidOption)
        #expect(throws: VHLogError(.invalidOption, "unsupported option foo")) {
            try ResolveOptions(json: ["foo": 1])
        }
    }
}
