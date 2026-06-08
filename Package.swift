// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to
// build this package.
//
// DocC plugin is not listed here; run `make generate-docs` to build GitHub
// Pages docs.

import PackageDescription

let package = Package(
    name: "Neptune",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
        .tvOS(.v15),
        .watchOS(.v8),
        .visionOS(.v1),
        .macCatalyst(.v15),
    ],
    products: [
        .library(
            name: "Neptune",
            targets: ["Neptune"]
        ),
    ],
    targets: [
        .target(
            name: "Neptune",
            dependencies: ["CNeptune"]
        ),
        .testTarget(
            name: "NeptuneTests",
            dependencies: ["Neptune"]
        ),
        .target(
            name: "CNeptune",
            sources: [
                "./secp256k1/src/secp256k1.c",
                "./secp256k1/src/precomputed_ecmult.c",
                "./secp256k1/src/precomputed_ecmult_gen.c",
            ],
            publicHeadersPath: "./secp256k1/include",
            cSettings: [
                .headerSearchPath("./secp256k1/src"),
                .define("ENABLE_MODULE_ECDH"),
                .define("ENABLE_MODULE_RECOVERY"),
                .define("ENABLE_MODULE_EXTRAKEYS"),
                .define("ENABLE_MODULE_SCHNORRSIG"),
                .define("ENABLE_MODULE_MUSIG"),
                .define("ENABLE_MODULE_ELLSWIFT"),
            ]
        ),
    ]
)
