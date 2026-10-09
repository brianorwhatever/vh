// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VHLog",
    platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v9), .visionOS(.v1)],
    products: [
        .library(name: "VHLog", targets: ["VHLog"]),
        .executable(name: "vh-log-driver", targets: ["vh-log-driver"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
    ],
    targets: [
        .target(name: "VHLog", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .executableTarget(name: "vh-log-driver", dependencies: ["VHLog"]),
        .testTarget(name: "VHLogTests", dependencies: ["VHLog"]),
    ]
)
