import Neptune

func exampleECDSAWithNeptune() {
    // Create context and keys
    let ctx = SECP256K1()
    let secretKey = ctx.secretKey()
    let publicKey = ctx.publicKey(secretKey: secretKey)
    let serializedPublicKey = publicKey.serialize(format: .compressed)

    // Message to sign
    let msg_hash: [UInt8] = [
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    ]

    // Sign and serialize
    let signature = secretKey.sign(messageHash: msg_hash)
    let serializedSignature = signature.serialize(format: .compact)

    // Verify signature
    let deserializedSignature = ctx.signature(normal: serializedSignature, format: .compact)
    let deserializedPublicKey = ctx.publicKey(bytes: serializedPublicKey)
    let isSignatureValid = deserializedPublicKey.verify(signature: deserializedSignature, messageHash: msg_hash)

    // Print results
    print("Is the signature valid? \(isSignatureValid ? "true" : "false")")
    print("Secret Key: \(hexadec(data: secretKey.serialize()))")
    print("Public Key: \(hexadec(data: serializedPublicKey))")
    print("Signature: \(hexadec(data: serializedSignature))")

    // Verify with static context for comparison
    let isValid2 = SECP256K1
        .limitedContext
        .publicKey(bytes: serializedPublicKey)
        .verify(signature: deserializedSignature, messageHash: msg_hash)

    print("Is the signature valid? \(isValid2 ? "true" : "false")")

    guard isValid2 == isSignatureValid else {
        fatalError("Signature verification mismatch between context and static context")
    }
}

func exampleRecoverableSignature() {
    // Create context and keys
    let ctx = SECP256K1()
    let secretKey = ctx.secretKey()
    let publicKey = ctx.publicKey(secretKey: secretKey)
    let serializedPublicKey = publicKey.serialize(format: .compressed)

    // Message to sign
    let msg_hash: [UInt8] = [
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    ]

    // Create and serialize signatures
    let recoverableSignature = secretKey.signRecoverable(messageHash: msg_hash)
    let serializedRecoverableSignature = recoverableSignature.serialize()
    let serializedSignature = recoverableSignature.convert().serialize()

    // Recover public key from signature
    let deserializedRecoverableSignature = ctx.recoverableSignature(recoverable: serializedRecoverableSignature.bytes, recid: serializedRecoverableSignature.recid)
    let recoveredPubKey = SECP256K1.PubKey.recover(signature: deserializedRecoverableSignature, messageHash: msg_hash)
    guard let recoveredPublicKey = recoveredPubKey else {
        fatalError("Failed to recover public key")
    }

    // Print results
    print("Recovered Public Key: \(hexadec(data: recoveredPublicKey.serialize(format: .compressed)))")
    print("Secret Key: \(hexadec(data: secretKey.serialize()))")
    print("Public Key: \(hexadec(data: serializedPublicKey))")
    print("Recoverable Signature: \(hexadec(data: serializedRecoverableSignature.bytes)) recid: \(serializedRecoverableSignature.recid)")
    print("Signature: \(hexadec(data: serializedSignature))")
}
