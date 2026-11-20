// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "DigestThings",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
        .tvOS(.v15),
        .watchOS(.v8),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "DigestThings",
            targets: ["DigestThings"]
        ),
    ],
    targets: [
        .target(
            name: "DigestThings"
        ),
        .testTarget(
            name: "DigestThingsTests",
            dependencies: ["DigestThings"]
        ),
    ]
)
