// The Swift Programming Language
// https://docs.swift.org/swift-book

@preconcurrency import CNeptune
import Security
import os.log

/// A class for performing SECP256K1 elliptic curve operations
public class SECP256K1 {
    /// Errors that can occur during SECP256K1 operations
    public enum SECPError: Error, CustomStringConvertible {
        /// Failed to generate cryptographically secure random bytes
        case randomGenerationFailed
        /// Failed to randomize the SECP256K1 context
        case contextRandomizationFailed
        /// Generated or provided secret key is invalid
        case invalidSecretKey
        /// Failed to sign message with secret key
        case signatureFailed
        /// Failed to create public key from secret key
        case publicKeyCreationFailed
        /// Failed to parse serialized public key
        case publicKeyParseFailed
        /// Failed to serialize public key
        case publicKeySerializationFailed
        /// Public key length mismatch after serialization
        case publicKeyLengthMismatch
        /// Failed to parse signature from bytes
        case signatureParsingFailed
        /// Failed to serialize signature
        case signatureSerializationFailed
        /// Failed to convert recoverable signature
        case signatureConversionFailed

        public var description: String {
            switch self {
            case .randomGenerationFailed:
                return "Failed to generate cryptographically secure random bytes"
            case .contextRandomizationFailed:
                return "Failed to randomize the SECP256K1 context"
            case .invalidSecretKey:
                return "Generated or provided secret key is invalid"
            case .signatureFailed:
                return "Failed to sign message with secret key"
            case .publicKeyCreationFailed:
                return "Failed to create public key from secret key"
            case .publicKeyParseFailed:
                return "Failed to parse serialized public key"
            case .publicKeySerializationFailed:
                return "Failed to serialize public key"
            case .publicKeyLengthMismatch:
                return "Public key length mismatch after serialization"
            case .signatureParsingFailed:
                return "Failed to parse signature from bytes"
            case .signatureSerializationFailed:
                return "Failed to serialize signature"
            case .signatureConversionFailed:
                return "Failed to convert recoverable signature"
            }
        }
    }

    /// Logger
    /// subsystem: software.bespalov.neptune
    /// category: secp256k1
    fileprivate class Log {
        private static let logger = Logger(subsystem: "software.bespalov.neptune", category: "secp256k1")
        
        static func debug(_ message: String) {
            logger.debug(("\(message)"))
        }
        
        static func error(_ message: String) {
            logger.error("\(message)")
        }
    }

    /// The context for SECP256K1 operations
    private var ctx: OpaquePointer!

    /// Creates and randomizes a new SECP256K1 context
    /// - Throws: SECPError.randomGenerationFailed if secure random bytes cannot be generated
    /// - Throws: SECPError.contextRandomizationFailed if context randomization fails
    public init() throws {
        // Create context
        let ctx: OpaquePointer! = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))
        Log.debug("Created SECP256K1 context")
        
        // Generate random seed for context
        var randomize: [UInt8] = [UInt8](repeating: 0, count: 32)
        let statusRandomize = SecRandomCopyBytes(kSecRandomDefault, randomize.count, &randomize)
        guard statusRandomize == errSecSuccess else {
            Log.error("Failed to generate random bytes for context")
            throw SECPError.randomGenerationFailed
        }
        Log.debug("Generated random seed for context")
        
        // Randomize the context
        let return_val_randomize = secp256k1_context_randomize(ctx, &randomize)
        guard return_val_randomize != 0 else {
            Log.error("Failed to randomize context")
            throw SECPError.contextRandomizationFailed
        }
        Log.debug("Successfully randomized context")

        self.ctx = ctx
    }

    /// Creates a context with existing context
    /// - Parameter ctx: The existing context
    public init(ctx: OpaquePointer!) {
        self.ctx = ctx
    }
    
    /// Destroys the context when the instance is deallocated
    deinit {
        guard ctx != secp256k1_context_static else {
            Log.debug("Not destroying context because it is static")
            return
        }
        secp256k1_context_destroy(ctx)
        Log.debug("Destroyed context")
    }
    
    /// Returns a static context after performing self-test
    public static var limitedContext: SECP256K1 {
        secp256k1_selftest()
        return SECP256K1(ctx: secp256k1_context_static)
    }
    
    /// Creates a secret key from serialized bytes
    /// - Parameter bytes: The serialized secret key
    /// - Returns: The secret key
    /// - Requires: bytes.count must be 32
    /// - Throws: SECPError.invalidSecretKey if the provided bytes are not a valid secret key
    public func secretKey(bytes: [UInt8]) throws -> SecKey {
        return try SecKey(bytes: bytes, ctx: ctx)
    }

    /// Creates a new random secret key
    /// - Returns: The secret key
    /// - Throws: SECPError.randomGenerationFailed if secure random bytes cannot be generated
    /// - Throws: SECPError.invalidSecretKey if the generated key is invalid
    public func secretKey() throws -> SecKey {
        return try SecKey(ctx: ctx)
    }
    
    /// Creates a public key from serialized bytes
    /// - Parameters:
    ///   - bytes: The serialized public key
    /// - Returns: The public key
    /// - Requires: bytes.count must be 33 (compressed) or 65 (uncompressed)
    /// - Throws: SECPError.publicKeyParseFailed if the bytes cannot be parsed as a valid public key
    public func publicKey(bytes: [UInt8]) throws -> PubKey {
        return try PubKey(bytes: bytes, ctx: ctx)
    }

    /// Creates a public key from a secret key
    /// - Parameter secretKey: The secret key
    /// - Returns: The public key
    /// - Throws: SECPError.publicKeyCreationFailed if public key creation fails
    public func publicKey(secretKey: SecKey) throws -> PubKey {
        return try PubKey(secretKey: secretKey, ctx: ctx)
    }
    
    /// Creates a signature from serialized bytes
    /// - Parameters:
    ///   - normal: The serialized signature
    ///     - For .compact format: Must be exactly 64 bytes
    ///     - For .der format: Must be a valid DER-encoded signature (70-72 bytes)
    ///   - format: The format (.compact or .der)
    /// - Returns: The signature
    /// - Throws: SECPError.signatureParsingFailed if the bytes cannot be parsed as a valid signature
    public func signature(normal bytes: [UInt8], format: Signature.Format) throws -> Signature {
        return try Signature(bytes: bytes, format: format, ctx: ctx)
    }
    
    /// Creates a recoverable signature from serialized bytes
    /// - Parameters:
    ///   - recoverable: The serialized recoverable signature
    ///     - Must be exactly 64 bytes
    ///   - recid: The recovery id
    ///     - Must be in the range [0,3]
    /// - Returns: The signature
    /// - Throws: SECPError.signatureParsingFailed if the bytes cannot be parsed as a valid recoverable signature
    public func recoverableSignature(recoverable: [UInt8], recid: Int32) throws -> RecoverableSignature {
        return try RecoverableSignature(bytes: recoverable, recid: recid, ctx: ctx)
    }
    
    /// A secret key for SECP256K1 operations
    public class SecKey {
        /// The context for SECP256K1 operations
        private var ctx: OpaquePointer!

        /// The secret key
        private var seckey: [UInt8]

        /// Creates a new random secret key and verifies it
        /// - Parameter ctx: The context for SECP256K1 operations
        /// - Throws: SECPError.randomGenerationFailed if secure random bytes cannot be generated
        /// - Throws: SECPError.invalidSecretKey if the generated key is invalid
        internal init(ctx: OpaquePointer!) throws {
            // Generate random secret key
            var seckey: [UInt8] = [UInt8](repeating: 0, count: 32)
            let statusSeckey = SecRandomCopyBytes(kSecRandomDefault, seckey.count, &seckey)
            guard statusSeckey == errSecSuccess else {
                Log.error("Failed to generate random bytes for secret key")
                throw SECPError.randomGenerationFailed
            }
            Log.debug("Generated random bytes for secret key")

            // Verify the secret key
            let return_val_verify = secp256k1_ec_seckey_verify(ctx, &seckey)
            guard return_val_verify != 0 else {
                Log.error("Failed to verify secret key")
                throw SECPError.invalidSecretKey
            }
            Log.debug("Successfully verified secret key")

            self.ctx = ctx
            self.seckey = seckey
        }
        
        /// Clears the secret key from memory
        deinit {
            seckey = [UInt8](repeating: 0, count: seckey.count)
            Log.debug("Cleared secret key from memory")
        }

        /// Creates a secret key from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized secret key
        ///     - Must be exactly 32 bytes
        ///     - Must represent a valid secret key (a scalar in the range [1,n-1] where n is the curve order)
        ///   - ctx: The context for SECP256K1 operations
        /// - Throws: SECPError.invalidSecretKey if the provided bytes are not a valid secret key
        internal init(bytes: [UInt8], ctx: OpaquePointer!) throws {
            var bytes = bytes
            Log.debug("Verifying provided secret key bytes")
            // Verify the secret key
            let return_val_verify = secp256k1_ec_seckey_verify(ctx, &bytes)
            guard return_val_verify != 0 else {
                Log.error("Failed to verify provided secret key bytes")
                throw SECPError.invalidSecretKey
            }
            Log.debug("Successfully verified provided secret key bytes")

            self.ctx = ctx
            self.seckey = bytes
        }
        
        /// Signs a message with this secret key to produce a normal signature
        /// - Parameter messageHash: The message hash to sign
        ///     - Must be exactly 32 bytes
        ///     - Must be the SHA256 hash of the message to sign
        /// - Returns: The signature
        /// - Throws: SECPError.signatureFailed if signing fails
        public func sign(messageHash: [UInt8]) throws -> Signature {
            Log.debug("Signing message hash with secret key")
            var messageHash = messageHash
            var signature = secp256k1_ecdsa_signature()
            let return_val_sign = secp256k1_ecdsa_sign(ctx, &signature, &messageHash, &seckey, nil, nil)
            guard return_val_sign != 0 else {
                Log.error("Failed to sign message hash")
                throw SECPError.signatureFailed
            }
            Log.debug("Successfully signed message hash")

            return Signature(signature: signature, ctx: ctx)
        }

        /// Signs a message with this secret key to produce a recoverable signature
        /// - Parameter messageHash: The message hash to sign
        /// - Returns: The recoverable signature
        /// - Throws: SECPError.signatureFailed if signing fails
        /// 
        /// Requires:
        /// - The message hash is 32 bytes
        public func signRecoverable(messageHash: [UInt8]) throws -> RecoverableSignature {
            Log.debug("Signing message hash with secret key (recoverable)")
            var messageHash = messageHash
            var signature = secp256k1_ecdsa_recoverable_signature()
            let return_val_sign = secp256k1_ecdsa_sign_recoverable(ctx, &signature, &messageHash, &seckey, nil, nil)
            guard return_val_sign != 0 else {
                Log.error("Failed to create recoverable signature")
                throw SECPError.signatureFailed
            }
            Log.debug("Successfully created recoverable signature")
            
            return RecoverableSignature(signature: signature, ctx: ctx)
        }
        
        /// Serializes the secret key to bytes
        /// - Returns: The serialized secret key
        ///   - Always returns exactly 32 bytes
        ///   - The bytes represent a valid secret key (a scalar in the range [1,n-1] where n is the curve order)
        ///   - The bytes are in big-endian format
        public func serialize() -> [UInt8] {
            Log.debug("Serializing secret key")
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
            Log.debug("Created public key with existing underlying struct")
        }

        /// Creates a public key from a secret key
        /// - Parameter secretKey: The secret key
        /// - Throws: SECPError.publicKeyCreationFailed if public key creation fails
        internal init(secretKey: SecKey, ctx: OpaquePointer!) throws {
            var pubkey = secp256k1_pubkey()
            var seckey = secretKey.serialize()
            defer{
                seckey = [UInt8](repeating: 0, count: seckey.count)
                Log.debug("Cleared secret key from memory")
            }
            let return_val_pubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey)
            guard return_val_pubkey != 0 else {
                Log.error("Failed to create public key from secret key")
                throw SECPError.publicKeyCreationFailed
            }
            
            self.ctx = ctx
            self.pubkey = pubkey
            Log.debug("Successfully created public key from secret key")
        }
        
        /// Creates a public key from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized public key
        ///   - ctx: The context for SECP256K1 operations
        /// - Requires: bytes.count must be 33 (compressed) or 65 (uncompressed)
        /// - Throws: SECPError.publicKeyParseFailed if the bytes cannot be parsed as a valid public key
        internal init(bytes: [UInt8], ctx: OpaquePointer!) throws {
            var bytes = bytes
            var pubkey = secp256k1_pubkey()
            let return_val_pubkey = secp256k1_ec_pubkey_parse(ctx, &pubkey, &bytes, bytes.count)
            guard return_val_pubkey != 0 else {
                Log.error("Failed to parse public key from bytes")
                throw SECPError.publicKeyParseFailed
            }

            self.ctx = ctx
            self.pubkey = pubkey
            Log.debug("Successfully parsed public key from bytes")
        }
        
        /// Serializes the public key
        /// - Parameter format: The format (.compressed or .uncompressed)
        /// - Returns: The serialized public key
        ///   - For .compressed format: Returns exactly 33 bytes
        ///   - For .uncompressed format: Returns exactly 65 bytes
        ///   - The bytes represent a valid public key point on the secp256k1 curve
        ///   - The bytes are in SEC format (0x02/0x03 prefix for compressed, 0x04 prefix for uncompressed)
        /// - Throws: SECPError.publicKeySerializationFailed if serialization fails
        /// - Throws: SECPError.publicKeyLengthMismatch if the serialized length is incorrect
        public func serialize(format: Format) throws -> [UInt8] {
            var len = format == .compressed ? 33 : 65
            var serialized_pubkey = [UInt8](repeating: 0, count: len)
            let flags = format == .compressed ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
            Log.debug("Attempting to serialize public key in \(format) format")
            let return_val_serialize = secp256k1_ec_pubkey_serialize(ctx, &serialized_pubkey, &len, &pubkey, flags)
            guard return_val_serialize != 0 else {
                Log.error("Failed to serialize public key")
                throw SECPError.publicKeySerializationFailed
            }
            guard len == serialized_pubkey.count else {
                Log.error("Public key length mismatch after serialization")
                throw SECPError.publicKeyLengthMismatch
            }
            Log.debug("Successfully serialized public key")
            return serialized_pubkey
        }
        
        /// Verifies a signature against a message
        /// - Parameters:
        ///   - signature: The signature to verify
        ///   - messageHash: The message hash
        ///     - Must be exactly 32 bytes
        ///     - Must be a hash of the message that was signed
        /// - Returns: Whether the signature is valid
        public func verify(signature: Signature, messageHash: [UInt8]) -> Bool {
            Log.debug("Attempting to verify signature")
            var messageHash = messageHash
            let is_signature_valid = secp256k1_ecdsa_verify(ctx, &signature.signature, &messageHash, &pubkey)
            if is_signature_valid != 0 {
                Log.debug("Signature verification succeeded")
            } else {
                Log.debug("Signature verification failed") 
            }
            return is_signature_valid != 0
        }

        /// Recovers a public key from a recoverable signature and message hash
        /// - Parameters:
        ///   - signature: The recoverable signature
        ///   - messageHash: The message hash that was signed
        ///     - Must be exactly 32 bytes
        ///     - Must be a hash of the message that was signed
        ///     - Must be the same message hash that was used to create the signature
        /// - Returns: The recovered public key, or nil if recovery failed
        public static func recover(signature: RecoverableSignature, messageHash: [UInt8]) -> PubKey? {
            Log.debug("Attempting to recover public key from signature")
            let ctx = SECP256K1.limitedContext.ctx
            var messageHash = messageHash
            var pubkey = secp256k1_pubkey()
            let return_val_recover = secp256k1_ecdsa_recover(ctx!, &pubkey, &signature.signature, &messageHash)
            guard return_val_recover != 0 else {
                Log.debug("Failed to recover public key from signature")
                return nil
            }
            Log.debug("Successfully recovered public key from signature")
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
            Log.debug("Created signature with existing underlying struct")
        }

        /// Creates a normal signature from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized signature
        ///     - For .compact format: Must be exactly 64 bytes
        ///     - For .der format: Must be a valid DER-encoded signature (70-72 bytes)
        ///   - format: The format (.compact or .der)
        ///   - ctx: The context for SECP256K1 operations
        /// - Throws: SECPError.signatureParsingFailed if the bytes cannot be parsed as a valid signature
        internal init(bytes: [UInt8], format: Format, ctx: OpaquePointer!) throws {
            Log.debug("Creating signature from bytes in \(format) format")
            var signature = secp256k1_ecdsa_signature()
            var bytes = bytes
            
            let success: Int32
            switch format {
            case .compact:
                Log.debug("Parsing compact format signature")
                success = secp256k1_ecdsa_signature_parse_compact(ctx, &signature, &bytes)
            case .der:
                Log.debug("Parsing DER format signature")
                success = secp256k1_ecdsa_signature_parse_der(ctx, &signature, &bytes, bytes.count)
            }
            
            guard success != 0 else {
                Log.error("Failed to parse signature from bytes")
                throw SECPError.signatureParsingFailed
            }
            
            self.signature = signature
            self.ctx = ctx
            Log.debug("Successfully created signature from bytes")
        }
        
        /// Serializes the signature
        /// - Parameter format: The format (.compact or .der for normal signature)
        /// - Returns: The serialized signature
        ///   - For .compact format: Returns exactly 64 bytes
        ///   - For .der format: Returns 70-72 bytes
        ///   - The bytes represent a valid ECDSA signature
        ///   - For .compact format: The bytes are in big-endian format (r,s)
        ///   - For .der format: The bytes are in DER format
        /// - Throws: SECPError.signatureSerializationFailed if serialization fails
        public func serialize(format: Format = .compact) throws -> [UInt8] {
            Log.debug("Serializing signature in \(format) format")
            switch format {
            case .compact:
                Log.debug("Using compact format serialization")
                var serialized_signature = [UInt8](repeating: 0, count: 64)
                let return_val_serialize = secp256k1_ecdsa_signature_serialize_compact(ctx, &serialized_signature, &signature)
                guard return_val_serialize != 0 else {
                    Log.error("Failed to serialize signature in compact format")
                    throw SECPError.signatureSerializationFailed
                }
                Log.debug("Successfully serialized signature in compact format")
                return serialized_signature
            case .der:
                Log.debug("Using DER format serialization")
                var serialized_signature = [UInt8](repeating: 0, count: 72) // Max DER length
                var outputlen = serialized_signature.count
                let return_val_serialize = secp256k1_ecdsa_signature_serialize_der(ctx, &serialized_signature, &outputlen, &signature)
                guard return_val_serialize != 0 else {
                    Log.error("Failed to serialize signature in DER format") 
                    throw SECPError.signatureSerializationFailed
                }
                Log.debug("Successfully serialized signature in DER format")
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
            Log.debug("Created recoverable signature with existing underlying struct")
        }
        
        /// Creates a recoverable signature from serialized bytes
        /// - Parameters:
        ///   - bytes: The serialized recoverable signature
        ///     - Must be exactly 64 bytes
        ///     - The bytes represent a valid ECDSA signature (r,s) in big-endian format
        ///   - recid: The recovery id
        ///     - Must be in the range [0,3]
        ///   - format: The format (ignored for recoverable signatures)
        ///   - ctx: The context for SECP256K1 operations
        /// - Throws: SECPError.signatureParsingFailed if the bytes cannot be parsed as a valid recoverable signature
        internal init(bytes: [UInt8], recid: Int32, ctx: OpaquePointer!) throws {
            Log.debug("Creating recoverable signature from bytes")
            var bytes = bytes
            var recoverable_signature = secp256k1_ecdsa_recoverable_signature()
            let return_val = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recoverable_signature, &bytes, recid)
            guard return_val != 0 else {
                Log.error("Failed to parse recoverable signature from bytes")
                throw SECPError.signatureParsingFailed
            }
            Log.debug("Successfully parsed recoverable signature from bytes")
                        
            self.signature = recoverable_signature
            self.ctx = ctx
            Log.debug("Created recoverable signature from bytes")
        }

        /// Serializes the signature into compact format
        /// - Returns: The serialized signature and recovery id
        ///   - bytes: Always returns exactly 64 bytes representing the (r,s) values in big-endian format
        ///   - recid: Always returns a value in the range [0,3] that allows recovering the public key
        /// - Throws: SECPError.signatureSerializationFailed if serialization fails
        public func serialize() throws -> (bytes: [UInt8], recid: Int32) {
            Log.debug("Serializing recoverable signature")
            var serialized_signature = [UInt8](repeating: 0, count: 64)
            var recid: Int32 = 0
            let return_val = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &serialized_signature, &recid, &signature)
            guard return_val != 0 else {
                Log.error("Failed to serialize recoverable signature")
                throw SECPError.signatureSerializationFailed
            }
            Log.debug("Successfully serialized recoverable signature")
            return (bytes: serialized_signature, recid: recid)
        }

        /// Converts the recoverable signature to a normal signature
        /// - Returns: The normal signature
        /// - Throws: SECPError.signatureConversionFailed if conversion fails
        public func convert() throws -> Signature {
            Log.debug("Converting recoverable signature to normal signature")
            var normal_signature = secp256k1_ecdsa_signature()
            let return_val = secp256k1_ecdsa_recoverable_signature_convert(ctx, &normal_signature, &signature)
            guard return_val != 0 else {
                Log.error("Failed to convert recoverable signature")
                throw SECPError.signatureConversionFailed
            }
            Log.debug("Successfully converted recoverable signature")
            return Signature(signature: normal_signature, ctx: ctx)
        }
    }
}
