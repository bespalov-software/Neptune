// The Swift Programming Language
// https://docs.swift.org/swift-book

@preconcurrency import CNeptune
import Security

/// A class for performing SECP256K1 elliptic curve operations
public class SECP256K1 {
    /// The context for SECP256K1 operations
    private var ctx: OpaquePointer!

    /// Creates and randomizes a new SECP256K1 context
    public init() {
        // Create context
        let ctx: OpaquePointer! = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))
        
        // Generate random seed for context
        var randomize: [UInt8] = [UInt8](repeating: 0, count: 32)
        let statusRandomize = SecRandomCopyBytes(kSecRandomDefault, randomize.count, &randomize)
        guard statusRandomize == errSecSuccess else {
            fatalError("Failed to generate randomness")
        }
        
        // Randomize the context
        let return_val_randomize = secp256k1_context_randomize(ctx, &randomize)
        guard return_val_randomize != 0 else {
            fatalError("Failed to randomize context") 
        }

        self.ctx = ctx
    }

    /// Creates a context with existing context
    /// - Parameter ctx: The existing context
    internal init(ctx: OpaquePointer!) {
        self.ctx = ctx
    }
    
    /// Destroys the context when the instance is deallocated
    deinit {
        guard ctx != secp256k1_context_static else {
            return
        }
        secp256k1_context_destroy(ctx)
    }
    
    /// Returns a static context after performing self-test
    public static var limitedContext: SECP256K1 {
        secp256k1_selftest()
        return SECP256K1(ctx: secp256k1_context_static)
    }
    
    /// Creates a secret key from serialized bytes
    /// - Parameter bytes: The serialized secret key
    /// - Returns: The secret key
    public func secretKey(bytes: [UInt8]) -> SecKey {
        return SecKey(bytes: bytes, ctx: ctx)
    }

    /// Creates a new random secret key
    /// - Returns: The secret key
    public func secretKey() -> SecKey {
        return SecKey(ctx: ctx)
    }
    
    /// Creates a public key from serialized bytes
    /// - Parameters:
    ///   - bytes: The serialized public key
    /// - Returns: The public key
    public func publicKey(bytes: [UInt8]) -> PubKey {
        return PubKey(bytes: bytes, ctx: ctx)
    }

    /// Creates a public key from a secret key
    /// - Parameter secretKey: The secret key
    /// - Returns: The public key
    public func publicKey(secretKey: SecKey) -> PubKey {
        return PubKey(secretKey: secretKey, ctx: ctx)
    }
    
    /// Creates a signature from serialized bytes
    /// - Parameters:
    ///   - normal: The serialized signature
    ///   - format: The format (.compact or .der)
    /// - Returns: The signature
    public func signature(normal bytes: [UInt8], format: Signature.Format) -> Signature {
        return Signature(bytes: bytes, format: format, ctx: ctx)
    }
    
    /// Creates a recoverable signature from serialized bytes
    /// - Parameters:
    ///   - recoverable: The serialized recoverable signature
    ///   - recid: The recovery id
    /// - Returns: The signature
    public func recoverableSignature(recoverable: [UInt8], recid: Int32) -> RecoverableSignature {
        return RecoverableSignature(bytes: recoverable, recid: recid, ctx: ctx)
    }
    
    /// A secret key for SECP256K1 operations
    public class SecKey {
        /// The context for SECP256K1 operations
        private var ctx: OpaquePointer!

        /// The secret key
        private var seckey: [UInt8]

        /// Creates a new random secret key and verifies it
        /// - Parameter ctx: The context for SECP256K1 operations
        internal init(ctx: OpaquePointer!) {
            // Generate random secret key
            var seckey: [UInt8] = [UInt8](repeating: 0, count: 32)
            let statusSeckey = SecRandomCopyBytes(kSecRandomDefault, seckey.count, &seckey)
            guard statusSeckey == errSecSuccess else {
                fatalError("Failed to generate randomness")
            }

            // Verify the secret key
            let return_val_verify = secp256k1_ec_seckey_verify(ctx, &seckey)
            guard return_val_verify != 0 else {
                fatalError("Generated secret key is invalid. This indicates an issue with the random number generator.")
            }

            self.ctx = ctx
            self.seckey = seckey
        }
        
        /// Clears the secret key from memory
        deinit {
            seckey = [UInt8](repeating: 0, count: seckey.count)
        }

        /// Creates a secret key from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized secret key
        ///   - ctx: The context for SECP256K1 operations
        internal init(bytes: [UInt8], ctx: OpaquePointer!) {
            var bytes = bytes
            // Verify the secret key
            let return_val_verify = secp256k1_ec_seckey_verify(ctx, &bytes)
            guard return_val_verify != 0 else {
                fatalError("Serialized secret key is invalid. This indicates an issue with the random number generator.")
            }

            self.ctx = ctx
            self.seckey = bytes
        }
        
        /// Signs a message with this secret key to produce a normal signature
        /// - Parameter messageHash: The message hash to sign
        /// - Returns: The signature
        /// 
        /// Requires:
        /// - The message hash is 32 bytes
        public func sign(messageHash: [UInt8]) -> Signature {
            var messageHash = messageHash
            var signature = secp256k1_ecdsa_signature()
            let return_val_sign = secp256k1_ecdsa_sign(ctx, &signature, &messageHash, &seckey, nil, nil)
            guard return_val_sign != 0 else {
                fatalError("Failed to sign message")
            }

            return Signature(signature: signature, ctx: ctx)
        }

        /// Signs a message with this secret key to produce a recoverable signature
        /// - Parameter messageHash: The message hash to sign
        /// - Returns: The recoverable signature
        /// 
        /// Requires:
        /// - The message hash is 32 bytes
        public func signRecoverable(messageHash: [UInt8]) -> RecoverableSignature {
            var messageHash = messageHash
            var signature = secp256k1_ecdsa_recoverable_signature()
            let return_val_sign = secp256k1_ecdsa_sign_recoverable(ctx, &signature, &messageHash, &seckey, nil, nil)
            guard return_val_sign != 0 else {
                fatalError("Failed to sign message")
            }
            
            return RecoverableSignature(signature: signature, ctx: ctx)
        }
        
        /// Serializes the secret key to bytes
        /// - Returns: The serialized secret key
        public func serialize() -> [UInt8] {
            return seckey
        }
    }
    
    /// A public key for SECP256K1 operations
    public class PubKey {
        /// The context for SECP256K1 operations
        private var ctx: OpaquePointer!

        /// The public key
        private var pubkey: secp256k1_pubkey

        /// Creates a public key with existing underlying struct
        /// - Parameters:
        ///   - pubkey: The existing public key
        ///   - ctx: The context for SECP256K1 operations
        internal init(pubkey: secp256k1_pubkey, ctx: OpaquePointer!) {
            self.pubkey = pubkey
            self.ctx = ctx
        }

        /// Creates a public key from a secret key
        /// - Parameter secretKey: The secret key
        internal init(secretKey: SecKey, ctx: OpaquePointer!) {
            var pubkey = secp256k1_pubkey()
            var seckey = secretKey.serialize()
            defer{
                seckey = [UInt8](repeating: 0, count: seckey.count)
            }
            let return_val_pubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey)
            guard return_val_pubkey != 0 else {
                fatalError("Failed to create public key")
            }
            
            self.ctx = ctx
            self.pubkey = pubkey
        }
        
        /// Creates a public key from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized public key
        ///   - ctx: The context for SECP256K1 operations
        internal init(bytes: [UInt8], ctx: OpaquePointer!) {
            var bytes = bytes
            var pubkey = secp256k1_pubkey()
            let return_val_pubkey = secp256k1_ec_pubkey_parse(ctx, &pubkey, &bytes, bytes.count)
            guard return_val_pubkey != 0 else {
                fatalError("Failed to parse public key")
            }

            self.ctx = ctx
            self.pubkey = pubkey
        }
        
        /// Serializes the public key
        /// - Parameter format: The format (.compressed or .uncompressed)
        /// - Returns: The serialized public key
        public func serialize(format: Format) -> [UInt8] {
            var len = format == .compressed ? 33 : 65
            var serialized_pubkey = [UInt8](repeating: 0, count: len)
            let flags = format == .compressed ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
            let return_val_serialize = secp256k1_ec_pubkey_serialize(ctx, &serialized_pubkey, &len, &pubkey, flags)
            guard return_val_serialize != 0 else {
                fatalError("Failed to serialize public key")
            }
            guard len == serialized_pubkey.count else {
                fatalError("Serialized public key length mismatch")
            }
            return serialized_pubkey
        }
        
        /// Verifies a signature against a message
        /// - Parameters:
        ///   - signature: The signature to verify
        ///   - messageHash: The message hash
        /// - Returns: Whether the signature is valid
        public func verify(signature: Signature, messageHash: [UInt8]) -> Bool {
            var messageHash = messageHash
            let is_signature_valid = secp256k1_ecdsa_verify(ctx, &signature.signature, &messageHash, &pubkey)
            return is_signature_valid != 0
        }

        /// Recovers a public key from a recoverable signature and message hash
        /// - Parameters:
        ///   - signature: The recoverable signature
        ///   - messageHash: The message hash that was signed
        /// - Returns: The recovered public key, or nil if recovery failed
        public static func recover(signature: RecoverableSignature, messageHash: [UInt8]) -> PubKey? {
            let ctx = SECP256K1.limitedContext.ctx
            var messageHash = messageHash
            var pubkey = secp256k1_pubkey()
            let return_val_recover = secp256k1_ecdsa_recover(ctx!, &pubkey, &signature.signature, &messageHash)
            guard return_val_recover != 0 else {
                return nil
            }
            return PubKey(pubkey: pubkey, ctx: ctx)
        }
        
        /// The format for public key serialization
        public enum Format {
            case compressed
            case uncompressed
        }
    }
    
    /// A signature for SECP256K1 operations
    public class Signature {
        /// The context for SECP256K1 operations
        private var ctx: OpaquePointer!

        /// The signature
        internal var signature: secp256k1_ecdsa_signature

        /// Creates a signature with existing underlying struct
        /// - Parameters:
        ///   - signature: The existing signature
        ///   - ctx: The context for SECP256K1 operations
        internal init(signature: secp256k1_ecdsa_signature, ctx: OpaquePointer!) {
            self.signature = signature
            self.ctx = ctx
        }

        /// Creates a normal signature from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized signature
        ///   - format: The format (.compact or .der)
        ///   - ctx: The context for SECP256K1 operations
        internal init(bytes: [UInt8], format: Format, ctx: OpaquePointer!) {
            var signature = secp256k1_ecdsa_signature()
            var bytes = bytes
            
            let success: Int32
            switch format {
            case .compact:
                success = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, &bytes)
            case .der:
                success = secp256k1_ecdsa_signature_parse_der(ctx, &signature, &bytes, bytes.count)
            }
            
            guard success != 0 else {
                fatalError("Failed to parse signature")
            }
            
            self.signature = signature
            self.ctx = ctx
        }
        
        /// Serializes the signature
        /// - Parameter format: The format (.compact or .der for normal signature)
        /// - Returns: The serialized signature
        public func serialize(format: Format = .compact) -> [UInt8] {
            switch format {
            case .compact:
                var serialized_signature = [UInt8](repeating: 0, count: 64)
                let return_val_serialize = secp256k1_ecdsa_signature_serialize_compact(ctx, &serialized_signature, &signature)
                guard return_val_serialize != 0 else {
                    fatalError("Failed to serialize compact signature")
                }
                return serialized_signature
            case .der:
                var serialized_signature = [UInt8](repeating: 0, count: 72) // Max DER length
                var outputlen = serialized_signature.count
                let return_val_serialize = secp256k1_ecdsa_signature_serialize_der(ctx, &serialized_signature, &outputlen, &signature)
                guard return_val_serialize != 0 else {
                    fatalError("Failed to serialize DER signature")
                }
                return Array(serialized_signature[..<outputlen])
            }
        }
        
        /// The format for signature serialization
        public enum Format {
            case compact
            case der
        }
    }

    /// A recoverable signature for SECP256K1 operations
    public class RecoverableSignature {

        /// Context
        private var ctx: OpaquePointer!

        /// Signature
        internal var signature: secp256k1_ecdsa_recoverable_signature

        /// Creates a recoverable signature with existing underlying struct
        /// - Parameters:
        ///   - signature: The existing signature
        ///   - ctx: The context for SECP256K1 operations
        internal init(signature: secp256k1_ecdsa_recoverable_signature, ctx: OpaquePointer!) {
            self.signature = signature
            self.ctx = ctx
        }
        
        /// Creates a recoverable signature from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized recoverable signature
        ///   - recid: The recovery id
        ///   - format: The format (ignored for recoverable signatures)
        ///   - ctx: The context for SECP256K1 operations
        internal init(bytes: [UInt8], recid: Int32, ctx: OpaquePointer!) {
            var bytes = bytes
            var recoverable_signature = secp256k1_ecdsa_recoverable_signature()
            let return_val = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recoverable_signature, &bytes, recid)
            guard return_val != 0 else {
                fatalError("Failed to parse recoverable signature")
            }
                        
            self.signature = recoverable_signature
            self.ctx = ctx
        }
        
        /// Serializes the signature into compact format
        /// - Returns: The serialized signature and recovery id
        public func serialize() -> (bytes: [UInt8], recid: Int32) {
            var serialized_signature = [UInt8](repeating: 0, count: 64)
            var recid: Int32 = 0
            let return_val = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &serialized_signature, &recid, &signature)
            guard return_val != 0 else {
                fatalError("Failed to serialize recoverable signature")
            }
            return (bytes: serialized_signature, recid: recid)
        }

        /// Converts the recoverable signature to a normal signature
        /// - Returns: The normal signature
        public func convert() -> Signature {
            var normal_signature = secp256k1_ecdsa_signature()
            let return_val = secp256k1_ecdsa_recoverable_signature_convert(ctx, &normal_signature, &signature)
            guard return_val != 0 else {
                fatalError("Failed to convert recoverable signature")
            }
            return Signature(signature: normal_signature, ctx: ctx)
        }
    }
}
