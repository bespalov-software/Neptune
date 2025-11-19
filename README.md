# Neptune

[![Swift](https://img.shields.io/badge/Swift-6.0-orange.svg)](https://swift.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-iOS%20%7C%20macOS%20%7C%20tvOS%20%7C%20watchOS%20%7C%20visionOS-lightgrey.svg)](Package.swift)

A high-performance Swift package providing secp256k1 elliptic curve cryptography functionality with support for ECDSA signatures, key generation, and recoverable signatures.

## Features

- ✅ **ECDSA Signatures** - Create and verify ECDSA signatures on secp256k1 curve
- ✅ **Key Generation** - Generate cryptographically secure secret and public keys
- ✅ **Recoverable Signatures** - Support for ECDSA pubkey recovery
- ✅ **Signature Formats** - Support for both compact (64-byte) and DER signature formats
- ✅ **Public Key Serialization** - Compressed (33-byte) and uncompressed (65-byte) formats
- ✅ **Swift-native API** - Clean, type-safe Swift interface
- ✅ **Cross-platform** - Supports iOS, macOS, tvOS, watchOS, and visionOS
- ✅ **Well-tested** - Comprehensive test suite
- ✅ **Optimized** - Built on bitcoin-core/secp256k1 with native optimizations

## Requirements

- **Swift**: 6.0 or later
- **Platforms**:
  - iOS 15.0+
  - macOS 13.0+
  - tvOS 15.0+
  - watchOS 8.0+
  - visionOS 1.0+
  - macCatalyst 15.0+

## Installation

### Swift Package Manager

Add Neptune to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/bespalov-software/Neptune.git", from: "1.0.0")
]
```

Or add it through Xcode:
1. File → Add Packages...
2. Enter the repository URL
3. Select the version you want to use

## Quick Start

### Basic Usage

Generate a key pair and sign a message:

```swift
import Neptune

// Create a SECP256K1 context
let secp256k1 = try SECP256K1()

// Generate a secret key
let secretKey = try secp256k1.secretKey()

// Create a public key from the secret key
let publicKey = try secp256k1.publicKey(secretKey: secretKey)

// Message hash (32 bytes) - must be SHA-256 hash of your message
// For "Hello, world!" this would be computed separately using SHA-256
let messageHash: [UInt8] = [
    0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
    0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
    0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
    0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
]

// Sign the message hash
let signature = try secretKey.sign(messageHash: messageHash)

// Verify the signature
let isValid = publicKey.verify(signature: signature, messageHash: messageHash)
print("Signature valid: \(isValid)")
```

### Recoverable Signatures

Create and recover public keys from signatures:

```swift
import Neptune

let secp256k1 = try SECP256K1()
let secretKey = try secp256k1.secretKey()
// Message hash (32 bytes) - must be SHA-256 hash of your message
let messageHash: [UInt8] = [
    0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
    0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
    0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
    0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
]

// Create a recoverable signature
let recoverableSignature = try secretKey.signRecoverable(messageHash: messageHash)

// Recover the public key from the signature
if let recoveredPublicKey = SECP256K1.PubKey.recover(
    signature: recoverableSignature,
    messageHash: messageHash
) {
    print("Public key recovered successfully")
}
```

### Working with Serialized Keys

```swift
import Neptune

let secp256k1 = try SECP256K1()

// Create a secret key from bytes
let secretKeyBytes: [UInt8] = [/* 32 bytes */]
let secretKey = try secp256k1.secretKey(bytes: secretKeyBytes)

// Serialize the secret key
let serialized = secretKey.serialize()

// Create a public key from bytes (compressed or uncompressed)
let publicKeyBytes: [UInt8] = [/* 33 or 65 bytes */]
let publicKey = try secp256k1.publicKey(bytes: publicKeyBytes)

// Serialize the public key
let compressed = try publicKey.serialize(format: .compressed)  // 33 bytes
let uncompressed = try publicKey.serialize(format: .uncompressed)  // 65 bytes
```

## API Documentation

### Main Types

#### `SECP256K1`

The main class for performing secp256k1 operations.

```swift
public class SECP256K1 {
    public init() throws
    public func secretKey() throws -> SecKey
    public func secretKey(bytes: [UInt8]) throws -> SecKey
    public func publicKey(secretKey: SecKey) throws -> PubKey
    public func publicKey(bytes: [UInt8]) throws -> PubKey
    public func signature(normal bytes: [UInt8], format: Signature.Format) throws -> Signature
    public func recoverableSignature(recoverable: [UInt8], recid: Int32) throws -> RecoverableSignature
}
```

#### `SECP256K1.SecKey`

Represents a secret key (private key).

```swift
public class SecKey {
    public func sign(messageHash: [UInt8]) throws -> Signature
    public func signRecoverable(messageHash: [UInt8]) throws -> RecoverableSignature
    public func serialize() -> [UInt8]
}
```

#### `SECP256K1.PubKey`

Represents a public key.

```swift
public class PubKey: Comparable {
    public func verify(signature: Signature, messageHash: [UInt8]) -> Bool
    public func serialize(format: Format) throws -> [UInt8]
    public static func recover(signature: RecoverableSignature, messageHash: [UInt8]) -> PubKey?
    
    public enum Format {
        case compressed    // 33 bytes
        case uncompressed  // 65 bytes
    }
}
```

#### `SECP256K1.Signature`

Represents a normal ECDSA signature.

```swift
public class Signature {
    public func serialize(format: Format = .compact) throws -> [UInt8]
    
    public enum Format {
        case compact  // 64 bytes
        case der      // 70-72 bytes
    }
}
```

#### `SECP256K1.RecoverableSignature`

Represents a recoverable ECDSA signature.

```swift
public class RecoverableSignature {
    public func serialize() -> (bytes: [UInt8], recid: Int32)
    public func convert() -> Signature
}
```

### Error Handling

```swift
public enum SECPError: Error {
    case randomGenerationFailed
    case contextRandomizationFailed
    case invalidSecretKey
    case signatureFailed
    case publicKeyCreationFailed
    case publicKeyParseFailed
    case publicKeyLengthMismatch
    case signatureParsingFailed
    case signatureSerializationFailed
}
```

## Development

### Prerequisites

- Swift 6.0+
- Xcode 15.0+ (for development)
- Git with submodule support

### Setting Up the Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bespalov-software/Neptune.git
   cd Neptune
   ```

2. **Initialize submodules:**
   ```bash
   git submodule update --init --recursive
   ```

3. **Verify submodule setup:**
   ```bash
   make check-secp256k1
   ```

### Development Tools

This project uses the following tools for code quality:

- **SwiftLint** - Linting and style checking
  ```bash
  brew install swiftlint
  swiftlint
  ```

- **SwiftFormat** - Code formatting
  ```bash
  brew install swiftformat
  swiftformat .
  ```

- **pre-commit** - Git hooks for quality checks
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install pre-commit
  pre-commit install
  ```

### Building

Build the package:

```bash
swift build
```

Run tests:

```bash
swift test
```

### Code Style

- Follow Swift API Design Guidelines
- Use conventional commits: https://www.conventionalcommits.org/
- Code is automatically formatted with SwiftFormat
- Linting is enforced via SwiftLint

### Updating secp256k1 Submodule

If you need to update the secp256k1 submodule:

```bash
# Update to referenced commit and verify
make update-secp256k1

# Or pull latest from secp256k1 remote
make pull-secp256k1

# Verify submodule is properly initialized
make check-secp256k1
```

See the [Makefile](Makefile) for more build targets.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following the code style guidelines
4. **Add tests** for new functionality
5. **Run the test suite** (`swift test`)
6. **Commit your changes** using [conventional commits](https://www.conventionalcommits.org/)
7. **Push to your branch** (`git push origin feature/amazing-feature`)
8. **Open a Pull Request**

### Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub with:
- A clear description of the problem
- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Swift version and platform information

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for full terms.

## Acknowledgments

This project is built on top of [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1), which provides the underlying cryptographic implementations. secp256k1 is released under the MIT License.

## Support

- **Documentation**: Check this README and inline code documentation
- **Issues**: [GitHub Issues](https://github.com/bespalov-software/Neptune/issues)
- **Professional Support**: Need help with integration, custom development, or have questions? Contact us at [hello@bespalov.software](mailto:hello@bespalov.software) or visit [bespalov.software](https://bespalov.software)
- **Sponsorship**: Interested in sponsoring this project or other services? Reach out via [hello@bespalov.software](mailto:hello@bespalov.software) or visit [bespalov.software](https://bespalov.software)

## Related Projects

- [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) - The underlying cryptographic library
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) - Reference implementation using secp256k1

---

**Note**: Remember to initialize git submodules when cloning:
```bash
git submodule update --init --recursive
```
