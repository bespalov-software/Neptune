import Neptune

func exampleECDSAWithNeptune() throws {
    // Create context and keys
    let ctx = try SECP256K1()
    let secretKey = try ctx.secretKey()
    let publicKey = try ctx.publicKey(secretKey: secretKey)
    let serializedPublicKey = try publicKey.serialize(format: .compressed)

    // Message to sign
    let msg_hash: [UInt8] = [
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    ]

    // Sign and serialize
    let signature = try secretKey.sign(messageHash: msg_hash)
    let serializedSignature = try signature.serialize(format: .compact)

    // Verify signature
    let deserializedSignature = try ctx.signature(normal: serializedSignature, format: .compact)
    let deserializedPublicKey = try ctx.publicKey(bytes: serializedPublicKey)
    let isSignatureValid = deserializedPublicKey.verify(signature: deserializedSignature, messageHash: msg_hash)

    // Print results
    print("Is the signature valid? \(isSignatureValid ? "true" : "false")")
    print("Secret Key: \(hexadec(data: secretKey.serialize()))")
    print("Public Key: \(hexadec(data: serializedPublicKey))")
    print("Signature: \(hexadec(data: serializedSignature))")

    // Verify with static context for comparison
    let isValid2 = try SECP256K1
        .limitedContext
        .publicKey(bytes: serializedPublicKey)
        .verify(signature: deserializedSignature, messageHash: msg_hash)

    print("Is the signature valid? \(isValid2 ? "true" : "false")")

    guard isValid2 == isSignatureValid else {
        fatalError("Signature verification mismatch between context and static context")
    }
}

func exampleRecoverableSignature() throws {
    // Create context and keys
    let ctx = try SECP256K1()
    let secretKey = try ctx.secretKey()
    let publicKey = try ctx.publicKey(secretKey: secretKey)
    let serializedPublicKey = try publicKey.serialize(format: .compressed)

    // Message to sign
    let msg_hash: [UInt8] = [
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    ]

    // Create and serialize signatures
    let recoverableSignature = try secretKey.signRecoverable(messageHash: msg_hash)
    let serializedRecoverableSignature = recoverableSignature.serialize()
    let serializedSignature = try recoverableSignature.convert().serialize(format: .der)

    // Recover public key from signature
    let deserializedRecoverableSignature = try ctx.recoverableSignature(
        recoverable: serializedRecoverableSignature.bytes,
        recid: serializedRecoverableSignature.recid
    )
    
    guard let recoveredPublicKey = SECP256K1.PubKey.recover(
        signature: deserializedRecoverableSignature,
        messageHash: msg_hash
    ) else {
        fatalError("Failed to recover public key")
    }

    // Deserialize the .der signature
    let deserializedSignature = try ctx.signature(normal: serializedSignature, format: .der)

    // verify the deserialized signature
    let isValid = recoveredPublicKey.verify(signature: deserializedSignature, messageHash: msg_hash)

    guard isValid else {
        fatalError("Signature verification mismatch between recoverable and der")
    }

    // Serialize and deserialize the secret key
    var serializedSecretKey = secretKey.serialize()
    defer { serializedSecretKey = [UInt8](repeating: 0, count: serializedSecretKey.count) }
    let deserializedSecretKey = try ctx.secretKey(bytes: serializedSecretKey)

    // Re-create public key from the deserialized secret key
    let publicKey2 = try ctx.publicKey(secretKey: deserializedSecretKey)

    // Compare public keys to test comparisons
    guard recoveredPublicKey == publicKey2 && !(recoveredPublicKey < publicKey) && !(recoveredPublicKey > publicKey) else {
        fatalError("Public key mismatch between original and deserialized")
    }

    // Print results
    print("Recovered Public Key: \(hexadec(data: try recoveredPublicKey.serialize(format: .compressed)))")
    print("Secret Key: \(hexadec(data: secretKey.serialize()))")
    print("Public Key: \(hexadec(data: serializedPublicKey))")
    print("Recoverable Signature: \(hexadec(data: serializedRecoverableSignature.bytes)) recid: \(serializedRecoverableSignature.recid)")
    print("Signature: \(hexadec(data: serializedSignature))")
}
