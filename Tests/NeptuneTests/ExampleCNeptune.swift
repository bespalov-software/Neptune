@preconcurrency import CNeptune
import Security

func exampleECDSA() {
    // creating context
    let ctx: OpaquePointer! = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))
    // clear memory
    defer {
        secp256k1_context_destroy(ctx)
    }

    // randomize context

    // * generate random seed
    var randomize: [UInt8] = [UInt8](repeating: 0, count: 32)
    let statusRandomize = SecRandomCopyBytes(kSecRandomDefault, randomize.count, &randomize)
    guard statusRandomize == errSecSuccess else {
        fatalError("Failed to generate randomness")
    }
    
    let return_val_randomize = secp256k1_context_randomize(ctx, &randomize)
    guard return_val_randomize != 0 else {
        fatalError("Failed to randomize context")
    }

    // Key Generation
    var seckey: [UInt8] = [UInt8](repeating: 0, count: 32)
    let statusSeckey = SecRandomCopyBytes(kSecRandomDefault, seckey.count, &seckey)
    // clear secrets from memory
    defer {
        // set secKey memory to 0 using Swift
        seckey = [UInt8](repeating: 0, count: seckey.count)
    }
    guard statusSeckey == errSecSuccess else {
        fatalError("Failed to generate randomness")
    }

    let return_val_verify = secp256k1_ec_seckey_verify(ctx, &seckey)
    guard return_val_verify != 0 else {
        fatalError("Generated secret key is invalid. This indicates an issue with the random number generator.")
    }

    // Public Key Creation, should never fail with a valid context and verified secret key
    var pubkey: secp256k1_pubkey = secp256k1_pubkey()
    let return_val_pubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey)
    guard return_val_pubkey != 0 else {
        fatalError("Failed to create public key")
    }

    // Serialize the pubkey in a compressed form (33 bytes)
    var compressed_pubkey: [UInt8] = [UInt8](repeating: 0, count: 33)
    var len = compressed_pubkey.count
    let return_val_serialize = secp256k1_ec_pubkey_serialize(ctx, &compressed_pubkey, &len, &pubkey, UInt32(SECP256K1_EC_COMPRESSED))
    guard return_val_serialize != 0 else {
        fatalError("Failed to serialize public key")
    }
    guard len == compressed_pubkey.count else {
        fatalError("Serialized public key length mismatch")
    }

    // Signing
    var signature: secp256k1_ecdsa_signature = secp256k1_ecdsa_signature()
    var msg_hash: [UInt8] = [
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    ]
    let return_val_sign = secp256k1_ecdsa_sign(ctx, &signature, &msg_hash, &seckey, nil, nil)
    guard return_val_sign != 0 else {
        fatalError("Failed to sign message")
    }

    // Serialize the signature in a compact form (64 bytes)
    var serialized_signature: [UInt8] = [UInt8](repeating: 0, count: 64)
    let return_val_serialize_signature = secp256k1_ecdsa_signature_serialize_compact(ctx, &serialized_signature, &signature)
    guard return_val_serialize_signature != 0 else {
        fatalError("Failed to serialize signature")
    }

    // Verification

    // Deserialize the signature
    let return_val_deserialize_signature = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, &serialized_signature)
    guard return_val_deserialize_signature != 0 else {
        fatalError("Failed to deserialize signature")
    }

    // Deserialize the public key
    let return_val_deserialize_pubkey = secp256k1_ec_pubkey_parse(ctx, &pubkey, &compressed_pubkey, compressed_pubkey.count)
    guard return_val_deserialize_pubkey != 0 else {
        fatalError("Failed to deserialize public key")
    }

    // Verify the signature
    let is_signature_valid = secp256k1_ecdsa_verify(ctx, &signature, &msg_hash, &pubkey)
    
    print("Is the signature valid? \(is_signature_valid == 1 ? "true" : "false")")

    // print the secret key in hexadecimal
    print("Secret Key: \(hexadec(data: seckey))")
    // print the pubkey in hexadecimal
    print("Public Key: \(hexadec(data: compressed_pubkey))")
    // print the signature in hexadecimal
    print("Signature: \(hexadec(data: serialized_signature))")

    // Signature verification doesn't need a created context for public key verification
    secp256k1_selftest()
    
    let is_signature_valid2 = secp256k1_ecdsa_verify(secp256k1_context_static, &signature, &msg_hash, &pubkey)
    guard is_signature_valid2 == is_signature_valid else {
        fatalError("Signature verification mismatch between context and static context")
    }
    
}

func hexadec(data: [UInt8]) -> String {
    return "0x" + data.map { 
        String($0, radix: 16, uppercase: true)
    }.joined()
}
