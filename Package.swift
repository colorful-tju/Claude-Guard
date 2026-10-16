// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ClaudeSafeLauncher",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GuardCore", targets: ["GuardCore"]),
        .executable(name: "guard-simulation", targets: ["GuardSimulation"]),
        .executable(name: "guard-daemon", targets: ["GuardDaemon"]),
        .executable(name: "guardctl", targets: ["GuardCLI"]),
        .executable(name: "guard-probe", targets: ["GuardProbe"]),
        .executable(name: "ClaudeSafeLauncher", targets: ["GuardApp"])
    ],
    targets: [
        .target(name: "GuardCore"),
        .executableTarget(name: "GuardSimulation", dependencies: ["GuardCore"]),
        .target(name: "NativeGuard", linkerSettings: [.linkedLibrary("proc"), .linkedLibrary("bsm")]),
        .target(name: "GuardRuntime", dependencies: ["GuardCore", "NativeGuard"], linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration")]),
        .executableTarget(name: "GuardDaemon", dependencies: ["GuardRuntime"]),
        .executableTarget(name: "GuardCLI", dependencies: ["GuardRuntime"]),
        .executableTarget(name: "GuardProbe", dependencies: ["GuardRuntime"]),
        .target(name:"GuardUIModel",dependencies:["GuardRuntime"],linkerSettings:[.linkedFramework("AppKit")]),
        .executableTarget(name: "GuardApp", dependencies: ["GuardRuntime","GuardUIModel"], linkerSettings: [.linkedFramework("SwiftUI"), .linkedFramework("AppKit")]),
        .testTarget(name:"GuardUIModelTests",dependencies:["GuardUIModel","GuardRuntime"]),
        .testTarget(name: "GuardRuntimeTests", dependencies: ["GuardRuntime"]),
        .testTarget(name: "GuardCoreTests", dependencies: ["GuardCore"])
    ]
)
