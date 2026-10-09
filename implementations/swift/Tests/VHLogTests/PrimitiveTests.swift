import Testing
@testable import VHLog

@Suite struct JCSTests {
    @Test(arguments: [
        (1e21, "1e+21"), (1e-7, "1e-7"), (-0.0, "0"), (123456789012345678.0, "123456789012345680"),
        (896365914996807.2, "896365914996807.2"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
        (100.0, "100"), (0.000001, "0.000001"), (1e20, "100000000000000000000"), (-1e-7, "-1e-7"),
        (0.30000000000000004, "0.30000000000000004"), (1.5e-9, "1.5e-9"), (333333333.33333329, "333333333.3333333"),
        (9.999999999999999e22, "1e+23"), (4.35, "4.35"), (1234.5678, "1234.5678"), (1e-6, "0.000001"), (1.0e-6 / 10, "1e-7"),
    ])
    func numbers(value: Double, expected: String) {
        #expect(formatECMAScriptNumber(value) == expected)
    }

    @Test func sortsKeysByUTF16CodeUnits() throws {
        // U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16 but after it by code point.
        let text = #"{"\ufb33":1,"\ud83d\ude00":2,"a":3,"\u0080":4}"#
        #expect(try JCS.canonicalize(text: text) == "{\"a\":3,\"\u{80}\":4,\"😀\":2,\"דּ\":1}")
    }

    @Test func keepsCanonicallyEquivalentKeysDistinct() throws {
        let value = try JSONValue.parse(#"{"\u00e9":1,"e\u0301":2}"#)
        #expect(value.objectValue?.count == 2)
        #expect(try JCS.canonicalize(value) == "{\"e\u{301}\":2,\"\u{e9}\":1}")
        #expect(value != (try JSONValue.parse(#"{"\u00e9":1,"\u00e9":2}"#)))
    }

    @Test func duplicateKeysLastValueFirstPosition() throws {
        let value = try JSONValue.parse(#"{"a":1,"b":2,"a":3}"#)
        #expect(try value.serialized() == #"{"a":3,"b":2}"#)
    }

    @Test func rejectsLoneSurrogatesAndAllowsPairs() throws {
        #expect(throws: JSONParseError.self) { try JSONValue.parse(#"["\ud800"]"#) }
        #expect(throws: JSONParseError.self) { try JSONValue.parse(#"{"\udc00":1}"#) }
        #expect(try JSONValue.parse(#""\ud83d\ude00""#) == .string("😀"))
        #expect(try JSONValue.parse(#""\ud800x""#, replacingLoneSurrogates: true) == .string("\u{FFFD}x"))
    }

    @Test func nonFiniteNumbersAreNotIJSON() throws {
        let value = try JSONValue.parse(#"{"a":[1e400]}"#)
        #expect(!value.isIJSONSafe)
        #expect(throws: JSONSerializationError.nonFiniteNumber) { try JCS.canonicalize(value) }
    }

    @Test func rejectsInvalidJSON() {
        for text in ["", "01", "1.", "[1,]", "{\"a\" 1}", "tru", "\"\u{1}\"", "[1] x", "+1", ".5", "\"\\x\""] {
            #expect(throws: JSONParseError.self, "\(text)") { try JSONValue.parse(text) }
        }
    }

    @Test func stringEscaping() throws {
        #expect(try JCS.canonicalize(.string("\u{8}\t\n\u{c}\r\"\\\u{1f}\u{7f}\u{2028}/")) == "\"\\b\\t\\n\\f\\r\\\"\\\\\\u001f\u{7f}\u{2028}/\"")
    }
}

@Suite struct EncodingTests {
    @Test func base58RoundTrip() {
        let samples: [[UInt8]] = [[], [0], [0, 0, 1], [0xFF, 0xEE], Array(0..<64)]
        for bytes in samples {
            #expect(Base58.decode(Base58.encode(bytes)) == bytes)
        }
        #expect(Base58.encode(Array("hello world".utf8)) == "StV1DL6CwTryKyV")
        #expect(Base58.decode("0OIl") == nil)
        #expect(Base58.decode("é") == nil)
    }

    @Test func multihashCheck() {
        #expect(Multihash.check(Multihash.hashB58("x")) == .ok)
        #expect(Multihash.check("") == .notBase58)
        #expect(Multihash.check("Qm0") == .notBase58)
        #expect(Multihash.check(Base58.encode([0x13, 0x20] + [UInt8](repeating: 1, count: 32))) == .unsupportedAlgorithm)
    }

    @Test func verificationMethod() {
        let mk = "z6MkwTAY3aCT7UL96ddvxWr1upj2VFQDMPFFRYxM1fRneSrv"
        #expect(Multikey.fromVerificationMethod("did:key:\(mk)#\(mk)") == mk)
        #expect(Multikey.fromVerificationMethod("did:key:\(mk)#\(mk)x") == nil)
        #expect(Multikey.fromVerificationMethod("did:key:\(mk)") == nil)
        #expect(Multikey.fromVerificationMethod("did:key:z6Mk#z6Mk") == nil)
    }

    @Test func versionTime() {
        #expect(VersionTime.parse("1970-01-01T00:00:00Z") == 0)
        #expect(VersionTime.parse("2026-01-01T00:00:00+00:00") == 1_767_225_600)
        #expect(VersionTime.parse("0000-01-01T00:00:00Z") == -62_167_219_200)
        #expect(VersionTime.parse("2024-02-29T23:59:59Z") != nil)
        for bad in ["2023-02-29T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:00:60Z", "2026-13-01T00:00:00Z",
                    "2026-01-01T00:00:00.0Z", "2026-01-01T00:00:00+01:00", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00z",
                    "٢٠٢٦-01-01T00:00:00Z"] {
            #expect(VersionTime.parse(bad) == nil, "\(bad)")
        }
    }

    @Test func watcherURLs() {
        #expect(isWatcherURL("https://w.example/path?q#f"))
        #expect(isWatcherURL("http://x"))
        #expect(!isWatcherURL("https://"))
        #expect(!isWatcherURL("https:///x"))
        #expect(!isWatcherURL("ftp://x"))
        #expect(!isWatcherURL("https://exa mple"))
        #expect(!isWatcherURL("https://bücher.example"))
    }
}

@Suite struct Ed25519Tests {
    /// RFC 8032 §7.1, TEST 1 and TEST 3.
    @Test func rfc8032Vectors() throws {
        let s1 = try Ed25519Signer(seedHex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        #expect(Hex.encode(s1.publicKey) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        #expect(Hex.encode(s1.sign([])) ==
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        let s3 = try Ed25519Signer(seedHex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        #expect(Hex.encode(s3.sign([0xAF, 0x82])) ==
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
    }

    @Test func signaturesVerifyWithSwiftCrypto() throws {
        for b in UInt8(0)..<8 {
            let signer = try Ed25519Signer(seed: [UInt8](repeating: b &* 37, count: 32))
            let message = [UInt8](repeating: b, count: Int(b) * 13)
            let sig = signer.sign(message)
            #expect(Ed25519Signer.verify(publicKey: signer.publicKey, message: message, signature: sig))
            #expect(!Ed25519Signer.verify(publicKey: signer.publicKey, message: message + [1], signature: sig))
        }
    }

    @Test func rejectsBadSeeds() {
        #expect(throws: VHLogInputError.self) { try Ed25519Signer(seedHex: "zz") }
        #expect(throws: VHLogInputError.self) { try Ed25519Signer(seed: [1, 2, 3]) }
    }
}
