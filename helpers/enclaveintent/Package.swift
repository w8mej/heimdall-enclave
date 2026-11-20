// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "enclaveintent",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "enclave-intent", targets: ["enclaveintent"])
    ],
    targets: [
        .executableTarget(
            name: "enclaveintent",
            path: "Sources/enclaveintent"
        )
    ]
)
