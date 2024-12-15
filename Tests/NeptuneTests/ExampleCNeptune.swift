@preconcurrency import CNeptune
import Security

func exampleECDSA() {
    // creating context
    let ctx: OpaquePointer! =
        secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))
    // clear memory
    defer {
        secp256k1_context_destroy(ctx)
    }

    // randomize context

    // * generate random seed
    var randomize = [UInt8](repeating: 0, count: 32)
    let statusRandomize = SecRandomCopyBytes(
        kSecRandomDefault,
        randomize.count,
        &randomize
    )
    guard statusRandomize == errSecSuccess else {
        fatalError("Failed to generate randomness")
    }

    let returnValRandomize = secp256k1_context_randomize(ctx, &randomize)
    guard returnValRandomize != 0 else {
        fatalError("Failed to randomize context")
    }

    // Key Generation
    var seckey = [UInt8](repeating: 0, count: 32)
    let statusSeckey = SecRandomCopyBytes(
        kSecRandomDefault,
        seckey.count,
        &seckey
    )
    // clear secrets from memory
    defer {
        // set secKey memory to 0 using Swift
        seckey = [UInt8](repeating: 0, count: seckey.count)
    }
    guard statusSeckey == errSecSuccess else {
        fatalError("Failed to generate randomness")
    }

    let returnValVerify = secp256k1_ec_seckey_verify(ctx, &seckey)
    guard returnValVerify != 0 else {
        fatalError(
            "Generated secret key is invalid." +
                "This indicates an issue with the random number generator."
        )
    }

    // Public Key Creation, should never fail with a valid context and verified
    // secret key
    var pubkey = secp256k1_pubkey()
    let returnValPubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey)
    guard returnValPubkey != 0 else {
        fatalError("Failed to create public key")
    }

    // Serialize the pubkey in a compressed form (33 bytes)
    var compressedPubkey = [UInt8](repeating: 0, count: 33)
    var len = compressedPubkey.count
    let returnValSerialize = secp256k1_ec_pubkey_serialize(
        ctx,
        &compressedPubkey,
        &len,
        &pubkey,
        UInt32(SECP256K1_EC_COMPRESSED)
    )
    guard returnValSerialize != 0 else {
        fatalError("Failed to serialize public key")
    }
    guard len == compressedPubkey.count else {
        fatalError("Serialized public key length mismatch")
    }

    // Signing
    var signature = secp256k1_ecdsa_signature()
    var msgHash: [UInt8] = [
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    ]
    let returnValSign = secp256k1_ecdsa_sign(
        ctx,
        &signature,
        &msgHash,
        &seckey,
        nil,
        nil
    )
    guard returnValSign != 0 else {
        fatalError("Failed to sign message")
    }

    // Serialize the signature in a compact form (64 bytes)
    var serializedSignature = [UInt8](repeating: 0, count: 64)
    let returnValSerializeSignature =
        secp256k1_ecdsa_signature_serialize_compact(
            ctx,
            &serializedSignature,
            &signature
        )
    guard returnValSerializeSignature != 0 else {
        fatalError("Failed to serialize signature")
    }

    // Verification

    // Deserialize the signature
    let returnValDeserializeSignature =
        secp256k1_ecdsa_signature_parse_compact(
            ctx,
            &signature,
            &serializedSignature
        )
    guard returnValDeserializeSignature != 0 else {
        fatalError("Failed to deserialize signature")
    }

    // Deserialize the public key
    let returnValDeserializePubkey = secp256k1_ec_pubkey_parse(
        ctx,
        &pubkey,
        &compressedPubkey,
        compressedPubkey.count
    )
    guard returnValDeserializePubkey != 0 else {
        fatalError("Failed to deserialize public key")
    }

    // Verify the signature
    let isSignatureValid = secp256k1_ecdsa_verify(
        ctx,
        &signature,
        &msgHash,
        &pubkey
    )

    print(
        "Is the signature valid? \(isSignatureValid == 1 ? "true" : "false")"
    )

    // print the secret key in hexadecimal
    print("Secret Key: \(hexadec(data: seckey))")
    // print the pubkey in hexadecimal
    print("Public Key: \(hexadec(data: compressedPubkey))")
    // print the signature in hexadecimal
    print("Signature: \(hexadec(data: serializedSignature))")

    // Signature verification doesn't need a created context for public key
    // verification
    secp256k1_selftest()

    let isSignatureValid2 = secp256k1_ecdsa_verify(
        secp256k1_context_static,
        &signature,
        &msgHash,
        &pubkey
    )
    guard isSignatureValid2 == isSignatureValid else {
        fatalError(
            "Signature verification mismatch between context and static context"
        )
    }
}

func hexadec(data: [UInt8]) -> String {
    "0x" + data.map {
        String(format: "%02x", $0)
    }.joined()
}
