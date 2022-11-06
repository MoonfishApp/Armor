// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Armor",
    
    platforms: [
       .macOS(.v12)
    ],
    
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "Armor",
            targets: ["Armor"]),
    ],
    dependencies: [
        .package(url: "https://github.com/MoonfishApp/mew-wallet-ios-tweetnacl.git", branch: "main"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "Armor",
            dependencies: [
                .product(name: "MEWwalletTweetNacl", package: "mew-wallet-ios-tweetnacl")
                ]),
        .testTarget(
            name: "ArmorTests",
            dependencies: ["Armor"]),
    ]
)
