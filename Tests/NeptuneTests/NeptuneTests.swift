import Foundation
@testable import Neptune
import Testing

@Test
func example() async throws {
    exampleECDSA()
    try exampleECDSAWithNeptune()
    try exampleRecoverableSignature()
}

// when error used in a string, it has a descriptive message
@Test
func errorDescription() {
    for errorCase in SECP256K1.SECPError.allCases {
        #expect(!errorCase.description.isEmpty)
    }
}

@Test
func whenDeserializingSecretKeyFromInvalidBytesThenThrowsError() throws {
    // From tests.c
    var bytes: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.invalidSecretKey) {
        _ = try ctx.secretKey(bytes: bytes)
    }

    bytes = [UInt8](repeating: 0, count: 32)
    #expect(throws: SECP256K1.SECPError.invalidSecretKey) {
        _ = try ctx.secretKey(bytes: bytes)
    }

    bytes = [UInt8](repeating: 0, count: 255)
    #expect(throws: SECP256K1.SECPError.invalidSecretKey) {
        _ = try ctx.secretKey(bytes: bytes)
    }
}

@Test
func whenDeserializingPublicKeyFromInvalidBytesThenThrowsError() throws {
    let bytes = [UInt8](repeating: 0, count: 65)
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.publicKeyParseFailed) {
        _ = try ctx.publicKey(bytes: bytes)
    }
}

@Test
func whenDeserializingSignatureFromBytesWithCompactThrowsError() throws {
    let bytes = [UInt8](repeating: 255, count: 64)
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.signatureParsingFailed) {
        _ = try ctx.signature(normal: bytes, format: .compact)
    }
}

// deserializing signature from bytes with .der throws error
@Test
func whenDeserializingSignatureFromBytesWithDERThrowsError() throws {
    let bytes = [UInt8](repeating: 255, count: 72)
    let ctx = try SECP256K1()
    #expect(throws: SECP256K1.SECPError.signatureParsingFailed) {
        _ = try ctx.signature(normal: bytes, format: .der)
    }
}

// deserializing recoverable signature from bytes throws error
@Test
func whenDeserializingRecoverableSignatureFromBytesThrowsError() throws {
    let bytes = [UInt8](repeating: 255, count: 65)
    let ctx = try SECP256K1()

    for recid in [-1, 4, 0] as [Int32] {
        #expect(throws: SECP256K1.SECPError.signatureParsingFailed) {
            _ = try ctx.recoverableSignature(recoverable: bytes, recid: recid)
        }
    }
}

@Test
func testHexadec() async throws {
    let data: [UInt8] = [0x00, 0x12, 0x34]
    let hex = hexadec(data: data)
    #expect(hex == "0x001234")
}
