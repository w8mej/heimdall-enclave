import Darwin
import Foundation

/// Explicit native root fixture for the real shared read-only gate. It creates
/// only one unique child of an already protected checkout-local target parent.
/// An unavailable protected parent/root identity is a refused prerequisite,
/// never a passing case or a reason to change checkout ancestor permissions.
@main
struct UpgradeGateFixture {
    enum Failure: Error { case prerequisite, assertion }

    static func require(_ value: Bool) throws {
        guard value else { throw Failure.assertion }
    }

    static func refuses(_ operation: () throws -> Void) throws {
        do { try operation() }
        catch { return }
        throw Failure.assertion
    }

    static func main() {
        do {
            try run()
            print("{\"status\":\"PASS\",\"scope\":\"ACTUAL_SHARED_SWIFT_ROOT_FILESYSTEM_GATE_ONLY\",\"installed_qualification\":false}")
        } catch Failure.prerequisite {
            print("{\"status\":\"PREREQUISITE_REFUSED\",\"scope\":\"NATIVE_ROOT_AND_PROTECTED_REPOSITORY_LOCAL_TARGET_PARENT_REQUIRED\"}")
            exit(3)
        } catch {
            print("{\"status\":\"FAIL\",\"scope\":\"ACTUAL_SHARED_SWIFT_ROOT_FILESYSTEM_GATE_ONLY\"}")
            exit(1)
        }
    }

    static func run() throws {
        guard geteuid() == 0, CommandLine.arguments.count == 2 else { throw Failure.prerequisite }
        let base = CommandLine.arguments[1]
        let checkout = FileManager.default.currentDirectoryPath
        guard base.hasPrefix(checkout + "/target/"), !base.hasSuffix("/"),
              !base.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else {
            throw Failure.prerequisite
        }
        // The same production checker must first admit the preexisting parent.
        // This also refuses unsafe/missing/symlinked repository ancestry.
        do { try DeploymentUpgrade.assertStartAllowed(supportRoot: base) }
        catch { throw Failure.prerequisite }

        let root = base + "/swift-upgrade-" + UUID().uuidString.lowercased()
        guard mkdir(root, 0o700) == 0 else { throw Failure.prerequisite }
        defer { try? FileManager.default.removeItem(atPath: root) }
        try require(chmod(root, 0o700) == 0)
        let marker = root + "/" + DeploymentUpgrade.inhibitionLeaf
        func admitted() throws { try DeploymentUpgrade.assertStartAllowed(supportRoot: root) }
        func denied() throws { try refuses { try admitted() } }
        func removeMarker() throws { try FileManager.default.removeItem(atPath: marker) }

        try admitted()
        try require(!FileManager.default.fileExists(atPath: marker))

        // Marker contents never become a successful completion/resume token.
        for bytes in [Data(), Data("{".utf8), Data("null".utf8), Data("{}".utf8),
                      Data("{\"complete\":true}".utf8), Data("{\"version\":999}".utf8)] {
            try bytes.write(to: URL(fileURLWithPath: marker))
            try denied()
            try require(try Data(contentsOf: URL(fileURLWithPath: marker)) == bytes)
            try removeMarker()
        }

        let sentinel = root + "/sentinel"
        let sentinelBytes = Data("untouched".utf8)
        try sentinelBytes.write(to: URL(fileURLWithPath: sentinel))
        for destination in [sentinel, root + "/missing-destination"] {
            try require(symlink(destination, marker) == 0)
            try denied()
            var metadata = stat()
            try require(lstat(marker, &metadata) == 0 && metadata.st_mode & S_IFMT == S_IFLNK)
            try require(try Data(contentsOf: URL(fileURLWithPath: sentinel)) == sentinelBytes)
            try removeMarker()
        }
        try require(!FileManager.default.fileExists(atPath: root + "/missing-destination"))

        try require(mkdir(marker, 0o700) == 0)
        try denied()
        try removeMarker()
        try require(mkfifo(marker, 0o600) == 0)
        try denied() // Must not open or block on the FIFO.
        try removeMarker()
        try require(link(sentinel, marker) == 0)
        try denied()
        try require(try Data(contentsOf: URL(fileURLWithPath: sentinel)) == sentinelBytes)
        try removeMarker()

        for mode in [mode_t(0o000), mode_t(0o600), mode_t(0o644), mode_t(0o777)] {
            try Data("marker".utf8).write(to: URL(fileURLWithPath: marker))
            try require(chmod(marker, mode) == 0)
            try denied()
            var metadata = stat()
            try require(lstat(marker, &metadata) == 0 && metadata.st_mode & 0o777 == mode)
            try removeMarker()
        }

        let missing = root + "/not-created/support"
        try refuses { try DeploymentUpgrade.assertStartAllowed(supportRoot: missing) }
        try require(!FileManager.default.fileExists(atPath: root + "/not-created"))
        let alias = root + "/support-alias"
        try require(symlink(root, alias) == 0)
        try refuses { try DeploymentUpgrade.assertStartAllowed(supportRoot: alias) }
        try FileManager.default.removeItem(atPath: alias)
        try require(chmod(root, 0o777) == 0)
        try denied()
        try require(chmod(root, 0o700) == 0)
        try require(chown(root, 501, gid_t.max) == 0)
        try denied()
        try require(chown(root, 0, gid_t.max) == 0)
        try admitted()
        try require(!FileManager.default.fileExists(atPath: marker))
    }
}
