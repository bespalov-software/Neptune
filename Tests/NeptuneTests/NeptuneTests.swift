import Testing
@testable import Neptune

@Test func example() async throws {
    exampleECDSA()
    try exampleECDSAWithNeptune()
    try exampleRecoverableSignature()
}

// when error used in a string, it has a descriptive message
@Test func errorDescription() {
    for errorCase in SECP256K1.SECPError.allCases {
        #expect(!errorCase.description.isEmpty)
    }
}

@Test func whenDeserializingSecretKeyFromInvalidBytesThenThrowsError() throws {
    // From tests.c
    var bytes: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    ]
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.invalidSecretKey) {
        let _ = try ctx.secretKey(bytes: bytes)
    }

    bytes = [UInt8](repeating: 0, count: 32)
    #expect(throws: SECP256K1.SECPError.invalidSecretKey) {
        let _ = try ctx.secretKey(bytes: bytes)
    }

    bytes = [UInt8](repeating: 0, count: 255)
    #expect(throws: SECP256K1.SECPError.invalidSecretKey) {
        let _ = try ctx.secretKey(bytes: bytes)
    }
}

@Test func whenDeserializingPublicKeyFromInvalidBytesThenThrowsError() throws {
    let bytes: [UInt8] = [UInt8](repeating: 0, count: 65)
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.publicKeyParseFailed) {
        let _ = try ctx.publicKey(bytes: bytes)
    }
}

@Test func whenDeserializingSignatureFromBytesWithCompactThrowsError() throws {
    let bytes: [UInt8] = [UInt8](repeating: 255, count: 64)
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.signatureParsingFailed) {
        let _ = try ctx.signature(normal: bytes, format: .compact)
    }
}

// deserializing signature from bytes with .der throws error
@Test func whenDeserializingSignatureFromBytesWithDERThrowsError() throws {
    let bytes: [UInt8] = [UInt8](repeating: 255, count: 72)
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.signatureParsingFailed) {
        let _ = try ctx.signature(normal: bytes, format: .der)
    }
}

// deserializing recoverable signature from bytes throws error
@Test func whenDeserializingRecoverableSignatureFromBytesThrowsError() throws {
    let bytes: [UInt8] = [UInt8](repeating: 255, count: 65)
    let ctx = try SECP256K1()

    for recid in [-1, 4, 0] as [Int32] {
        #expect(throws: SECP256K1.SECPError.signatureParsingFailed) {
            let _ = try ctx.recoverableSignature(recoverable: bytes, recid: recid)
        }
    }
}
