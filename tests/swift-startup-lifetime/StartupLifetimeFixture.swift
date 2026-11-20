import Darwin
import Foundation

/// Standalone actual-root SOFTWARE fixture for the real shared Swift class.
/// Compile with DeploymentUpgrade.swift only. No helper, selected descriptor
/// authority, native provisioner, installed operation or credential is created.
@main
struct StartupLifetimeFixture {
    enum Failure: Error { case prerequisite, assertion }
    static let bytes = Data("SYNTHETIC PUBLIC STARTUP LEASE FIXTURE\n".utf8)
    static var cleanupUncertain = false

    static func require(_ value: Bool) throws { if !value { throw Failure.assertion } }
    static func refuses(_ body: () throws -> Void) throws {
        do { try body() } catch { return }
        throw Failure.assertion
    }
    static func status(_ text: String) { print("STARTUP_FIXTURE:" + text); fflush(stdout) }
    static func command(_ expected: String) throws { try require(readLine() == expected) }

    static func writeNew(_ path: String, data: Data) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure.assertion }
        defer { close(fd) }
        try require(fchown(fd, 0, 0) == 0 && fchmod(fd, 0o644) == 0)
        var offset = 0
        try data.withUnsafeBytes { buffer in
            while offset < buffer.count {
                let n = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if n < 0 && errno == EINTR { continue }
                try require(n > 0); offset += n
            }
        }
    }

    static func readDescriptor(_ path: String) throws -> Data {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.assertion }
        defer { close(fd) }
        var metadata = stat()
        try require(fstat(fd, &metadata) == 0 && metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_uid == 0 && metadata.st_mode & 0o022 == 0
            && metadata.st_nlink == 1 && metadata.st_size > 0 && metadata.st_size <= 65_536)
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while data.count <= 65_536 {
            let n = read(fd, &buffer, min(buffer.count, 65_537 - data.count))
            if n < 0 && errno == EINTR { continue }
            try require(n >= 0)
            if n == 0 { break }
            data.append(contentsOf: buffer.prefix(n))
        }
        try require(data.count <= 65_536)
        return data
    }

    static func child(root: String, mode: String) throws {
        let config = root + "/descriptor.txt"
        let binding = DeploymentUpgrade.SelectedBinding(configPath: config, descriptorBytes: bytes, supportRoot: root)
        if mode == "observe" {
            try DeploymentUpgrade.assertStartAllowed(supportRoot: root)
            status("OBSERVATION_ONLY"); try command("EXIT"); return
        }
        if mode == "delayed" {
            try DeploymentUpgrade.assertStartAllowed(supportRoot: root)
            status("OBSERVED_ABSENCE"); try command("CONTINUE")
        }
        if mode == "refuse" || mode == "delayed" {
            try refuses { try DeploymentUpgrade.retainSelectedActor(binding: binding) { try readDescriptor(config) } }
            status("DENIED_BEFORE_EFFECT"); return
        }
        let results = NSLock()
        var failed = false
        DispatchQueue.concurrentPerform(iterations: 4) { _ in
            do { try DeploymentUpgrade.retainSelectedActor(binding: binding) { try readDescriptor(config) } }
            catch { results.lock(); failed = true; results.unlock() }
        }
        try require(!failed)
        // Same process repeat must use the retained owner, not reacquire a FD.
        try DeploymentUpgrade.retainSelectedActor(binding: binding) { try readDescriptor(config) }
        try DeploymentUpgrade.assertSelectedActor(binding: binding) { try readDescriptor(config) }
        status("HELD")
        if mode == "poison" {
            try command("RECHECK")
            try refuses { try DeploymentUpgrade.assertSelectedActor(binding: binding) { try readDescriptor(config) } }
            status("POISONED"); try command("RECHECK")
            try refuses { try DeploymentUpgrade.assertSelectedActor(binding: binding) { try readDescriptor(config) } }
            try refuses { try DeploymentUpgrade.retainSelectedActor(binding: binding) { try readDescriptor(config) } }
            status("STILL_POISONED")
        }
        try command("EXIT")
        // The actual static owner remains until the process exits after return.
        status("EXITING")
    }

    final class Child {
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        var finished = false

        init(root: String, mode: String) throws {
            process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
            process.arguments = ["--child", root, mode]
            process.standardInput = input
            process.standardOutput = output
            process.standardError = FileHandle.standardError
            try process.run()
        }
        func send(_ text: String) throws {
            try input.fileHandleForWriting.write(contentsOf: Data((text + "\n").utf8))
        }
        func expect(_ expected: String) throws {
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            var line = Data(), total = 0
            while ProcessInfo.processInfo.systemUptime < deadline {
                var watched = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
                let result = poll(&watched, 1, 20)
                if result < 0 && errno == EINTR { continue }
                try require(result >= 0)
                if result == 0 { continue }
                let byte = output.fileHandleForReading.readData(ofLength: 1)
                try require(byte.count == 1); total += 1
                try require(total <= 16_384)
                if byte[0] == 10 {
                    if String(data: line, encoding: .utf8) == "STARTUP_FIXTURE:" + expected { return }
                    line.removeAll(keepingCapacity: true)
                } else { line.append(byte) }
            }
            throw Failure.assertion
        }
        func finish() throws {
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.002) }
            try require(!process.isRunning)
            finished = true
            try require(process.terminationReason == .exit && process.terminationStatus == 0)
        }
        deinit {
            if !finished {
                // Only close our known pipe endpoint. A numeric PID plus
                // Process.isRunning cannot exclude a reap/PID-reuse race.
                // This child's readLine receives EOF and exits through its
                // assertion path. Never signal a process by an observed PID.
                try? input.fileHandleForWriting.close()
                let deadline = ProcessInfo.processInfo.systemUptime + 4
                while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.002) }
                if process.isRunning { cleanupUncertain = true; status("CLEANUP_UNCONFIRMED") }
            }
        }
    }

    static func exclusiveAvailable(_ root: String) throws -> Bool {
        let path = root + "/" + DeploymentUpgrade.lifetimeLeaf
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.assertion }
        defer { close(fd) }
        if flock(fd, LOCK_EX | LOCK_NB) == 0 { return true }
        let code = errno
        try require(code == EWOULDBLOCK || code == EAGAIN)
        return false
    }

    static func parent(base: String) throws -> Int {
        let checkout = FileManager.default.currentDirectoryPath
        guard geteuid() == 0, base.hasPrefix(checkout + "/target/"), !base.hasSuffix("/"),
              !base.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }) else { throw Failure.prerequisite }
        do { try DeploymentUpgrade.assertStartAllowed(supportRoot: base) }
        catch { throw Failure.prerequisite }
        let root = base + "/swift-startup-lifetime-" + UUID().uuidString.lowercased()
        guard mkdir(root, 0o700) == 0 else { throw Failure.prerequisite }
        defer { if !cleanupUncertain { try? FileManager.default.removeItem(atPath: root) } }
        var cases = 0
        func fixture(_ name: String, lease: Bool = true) throws -> String {
            let path = root + "/" + name
            try require(mkdir(path, 0o700) == 0)
            try writeNew(path + "/descriptor.txt", data: bytes)
            if lease { try writeNew(path + "/" + DeploymentUpgrade.lifetimeLeaf, data: Data()) }
            return path
        }
        func inhibit(_ path: String) throws { try writeNew(path + "/" + DeploymentUpgrade.inhibitionLeaf, data: Data("{\n".utf8)) }
        func marker(_ path: String) -> String { path + "/" + DeploymentUpgrade.inhibitionLeaf }

        // The unchanged observation gate does not require or retain a lease.
        do {
            let path = try fixture("observation", lease: false)
            let observed = try Child(root: path, mode: "observe"); try observed.expect("OBSERVATION_ONLY")
            try writeNew(path + "/" + DeploymentUpgrade.lifetimeLeaf, data: Data())
            try inhibit(path); try require(try exclusiveAvailable(path))
            try observed.send("EXIT"); try observed.finish(); cases += 1
        }
        // Actual retained SH in either child prevents EX until both have exited.
        do {
            let path = try fixture("two-actors")
            let first = try Child(root: path, mode: "hold"); try first.expect("HELD")
            let second = try Child(root: path, mode: "hold"); try second.expect("HELD")
            try inhibit(path); try require(try !exclusiveAvailable(path))
            try first.send("EXIT"); try first.finish(); try require(try !exclusiveAvailable(path))
            try second.send("EXIT"); try second.finish(); try require(try exclusiveAvailable(path)); cases += 1
        }
        // A process delayed after its old marker observation still cannot start.
        do {
            let path = try fixture("delayed")
            let delayed = try Child(root: path, mode: "delayed"); try delayed.expect("OBSERVED_ABSENCE")
            try inhibit(path); try require(try exclusiveAvailable(path))
            try delayed.send("CONTINUE"); try delayed.expect("DENIED_BEFORE_EFFECT"); try delayed.finish(); cases += 1
        }
        for drift in ["marker", "descriptor"] {
            let path = try fixture("poison-" + drift)
            let actor = try Child(root: path, mode: "poison"); try actor.expect("HELD")
            if drift == "marker" { try inhibit(path) }
            else { try Data("CHANGED PUBLIC DESCRIPTOR\n".utf8).write(to: URL(fileURLWithPath: path + "/descriptor.txt")) }
            try actor.send("RECHECK"); try actor.expect("POISONED"); try require(try !exclusiveAvailable(path))
            if drift == "marker" { try FileManager.default.removeItem(atPath: marker(path)) }
            else { try bytes.write(to: URL(fileURLWithPath: path + "/descriptor.txt")) }
            try actor.send("RECHECK"); try actor.expect("STILL_POISONED"); try require(try !exclusiveAvailable(path))
            if drift == "marker" { try inhibit(path) }
            try actor.send("EXIT"); try actor.finish(); try require(try exclusiveAvailable(path)); cases += 1
        }
        for malformed in ["missing", "directory", "symlink", "fifo", "mode", "owner", "group", "linked", "bytes"] {
            let path = try fixture("unsafe-" + malformed, lease: false)
            let leaf = path + "/" + DeploymentUpgrade.lifetimeLeaf
            switch malformed {
            case "missing": break
            case "directory": try require(mkdir(leaf, 0o755) == 0)
            case "symlink": try require(symlink(path + "/missing", leaf) == 0)
            case "fifo": try require(mkfifo(leaf, 0o644) == 0)
            default:
                try writeNew(leaf, data: malformed == "bytes" ? Data("x".utf8) : Data())
                if malformed == "mode" { try require(chmod(leaf, 0o666) == 0) }
                if malformed == "owner" { try require(chown(leaf, 501, 0) == 0) }
                if malformed == "group" { try require(chown(leaf, 0, 1) == 0) }
                if malformed == "linked" { try require(link(leaf, path + "/extra-link") == 0) }
            }
            let denied = try Child(root: path, mode: "refuse"); try denied.expect("DENIED_BEFORE_EFFECT"); try denied.finish(); cases += 1
            var observed = stat()
            if malformed == "missing" { try require(lstat(leaf, &observed) == -1 && errno == ENOENT) }
        }
        try require(!cleanupUncertain)
        return cases
    }

    static func main() {
        do {
            guard geteuid() == 0 else { throw Failure.prerequisite }
            let args = CommandLine.arguments
            if args.count == 4 && args[1] == "--child" {
                try child(root: args[2], mode: args[3]); return
            }
            guard args.count == 2 else { throw Failure.prerequisite }
            let cases = try parent(base: args[1])
            print("{\"status\":\"PASS\",\"scope\":\"ACTUAL_SHARED_SWIFT_CLASS_NATIVE_ROOT_SOFTWARE_ONLY\",\"cases\":\(cases),\"decoded_helper_authority\":false,\"installed_qualified\":false}")
        } catch Failure.prerequisite {
            print("{\"status\":\"PREREQUISITE_REFUSED\",\"scope\":\"ACTUAL_NATIVE_ROOT_AND_PREEXISTING_PROTECTED_CHECKOUT_LOCAL_TARGET_PARENT_REQUIRED\"}")
            exit(3)
        } catch {
            print("{\"status\":\"FAIL\",\"scope\":\"ACTUAL_SHARED_SWIFT_CLASS_ONLY\"}")
            exit(1)
        }
    }
}
