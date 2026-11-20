import Darwin
import Foundation

/// Shared selected-startup observation and cooperative actor lifetime exclusion.
/// Neither supplies installation, inactivity, recovery or mutation authority.
/// Missing permanent provisioning refuses; no startup path creates or repairs it.
enum DeploymentUpgrade {
    enum Failure: Error { case startInhibited }

    // Must remain identical to enclave_core::deployment::upgrade's constant.
    static let inhibitionLeaf = ".depot-upgrade-inhibited-v1.json"
    // Must remain identical to enclave_core::deployment::startup_lease.
    static let lifetimeLeaf = ".depot-startup-lifetime-v1.lock"

    /// Internal binding from a helper's private immutable decoded selection.
    /// Exact raw bytes are public configuration, never a JSON reserialization.
    struct SelectedBinding: Equatable {
        let configPath: String
        let descriptorBytes: Data
        let supportRoot: String
    }

    private final class Descriptor {
        let value: Int32
        init(_ value: Int32) throws {
            guard value >= 0 else { throw Failure.startInhibited }
            self.value = value
        }
        deinit { close(value) }
    }

    private struct DirectoryNode {
        let file: Descriptor
        let stamp: stat
        let name: String?
    }

    /// The same full nofollow ancestry is used by observations and retained SH.
    /// Descriptor objects close provisional resources on every throwing path.
    private final class HeldSupportDirectory {
        let nodes: [DirectoryNode]
        private let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC

        init(supportRoot: String) throws {
            let path = try normalizedSupportRoot(supportRoot)
            let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            let root = try Descriptor(open("/", flags))
            var nodes = [DirectoryNode(file: root, stamp: try protectedDirectory(root.value), name: nil)]
            for component in path.split(separator: "/").map(String.init) {
                let child = try Descriptor(openat(nodes.last!.file.value, component, flags))
                nodes.append(DirectoryNode(file: child, stamp: try protectedDirectory(child.value), name: component))
            }
            self.nodes = nodes
            try assertCurrent()
        }

        var directory: Int32 { nodes.last!.file.value }

        func assertCurrent() throws {
            let namedRoot = try Descriptor(open("/", flags))
            guard sameDirectory(try protectedDirectory(namedRoot.value), nodes[0].stamp) else {
                throw Failure.startInhibited
            }
            for (index, node) in nodes.enumerated() {
                guard sameDirectory(try protectedDirectory(node.file.value), node.stamp) else {
                    throw Failure.startInhibited
                }
                if let name = node.name {
                    var named = stat()
                    guard index > 0,
                          fstatat(nodes[index - 1].file.value, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
                          isProtectedDirectory(named), sameDirectory(named, node.stamp) else {
                        throw Failure.startInhibited
                    }
                }
            }
        }

        func requireMarkerAbsent() throws {
            var marker = stat()
            let result = fstatat(directory, inhibitionLeaf, &marker, AT_SYMLINK_NOFOLLOW)
            let status = errno
            guard result == -1, status == ENOENT else { throw Failure.startInhibited }
        }
    }

    /// Any named marker denies, including a dangling symlink or invalid file.
    /// Its bytes are never read. Missing or unsafe support ancestry also denies.
    /// The caller supplies only its validated selected descriptor's support root.
    /// Absence is an observation, not a lifetime exclusion lease: the installer
    /// must still stop and observe all affected processes before public writes.
    static func assertStartAllowed(supportRoot: String) throws {
        let held = try HeldSupportDirectory(supportRoot: supportRoot)
        try held.assertCurrent()
        try held.requireMarkerAbsent()
        try held.assertCurrent()
        try held.requireMarkerAbsent()
    }

    private static func isProtectedLease(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFREG && value.st_uid == 0 && value.st_gid == 0
            && value.st_mode & 0o7777 == 0o644 && value.st_nlink == 1 && value.st_size == 0
    }

    private static func sameLease(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_gid == b.st_gid
            && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_size == b.st_size
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }

    private static func namedLease(_ directory: Int32) throws -> stat {
        var named = stat()
        guard fstatat(directory, lifetimeLeaf, &named, AT_SYMLINK_NOFOLLOW) == 0,
              isProtectedLease(named) else { throw Failure.startInhibited }
        return named
    }

    private static func assertDescriptor(_ binding: SelectedBinding, readDescriptor: () throws -> Data) throws {
        guard !binding.descriptorBytes.isEmpty, binding.descriptorBytes.count <= 65_536,
              try readDescriptor() == binding.descriptorBytes else { throw Failure.startInhibited }
    }

    private final class ActorOwner {
        let binding: SelectedBinding
        let ancestry: HeldSupportDirectory
        let file: Descriptor
        let stamp: stat
        let process: pid_t

        init(binding: SelectedBinding, readDescriptor: () throws -> Data) throws {
            try assertDescriptor(binding, readDescriptor: readDescriptor)
            let ancestry = try HeldSupportDirectory(supportRoot: binding.supportRoot)
            try ancestry.assertCurrent()
            try ancestry.requireMarkerAbsent()
            let named = try namedLease(ancestry.directory)
            // No O_CREAT, writable access or opening of a known special inode.
            let file = try Descriptor(openat(ancestry.directory, lifetimeLeaf,
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC))
            var stamp = stat()
            guard fstat(file.value, &stamp) == 0, isProtectedLease(stamp), sameLease(stamp, named) else {
                throw Failure.startInhibited
            }
            self.binding = binding
            self.ancestry = ancestry
            self.file = file
            self.stamp = stamp
            self.process = getpid()
            try assertDescriptor(binding, readDescriptor: readDescriptor)
            try ancestry.assertCurrent()
            try assertFileCurrent()
            try ancestry.requireMarkerAbsent()
            guard flock(file.value, LOCK_SH | LOCK_NB) == 0 else { throw Failure.startInhibited }
            // Failure may close this provisional owner: no actor was admitted.
            try assertCurrent(binding: binding, readDescriptor: readDescriptor)
        }

        func assertFileCurrent() throws {
            var before = stat(), after = stat()
            let access = fcntl(file.value, F_GETFL)
            let descriptor = fcntl(file.value, F_GETFD)
            guard fstat(file.value, &before) == 0, isProtectedLease(before), sameLease(before, stamp),
                  access >= 0, descriptor >= 0, access & O_ACCMODE == O_RDONLY,
                  access & O_NONBLOCK != 0, descriptor & FD_CLOEXEC != 0,
                  sameLease(try namedLease(ancestry.directory), stamp),
                  fstat(file.value, &after) == 0, sameLease(after, stamp) else { throw Failure.startInhibited }
        }

        func assertCurrent(binding: SelectedBinding, readDescriptor: () throws -> Data) throws {
            guard binding == self.binding, getpid() == process else { throw Failure.startInhibited }
            try assertDescriptor(binding, readDescriptor: readDescriptor)
            try ancestry.assertCurrent()
            try assertFileCurrent()
            try ancestry.requireMarkerAbsent()
            try assertDescriptor(binding, readDescriptor: readDescriptor)
            try ancestry.assertCurrent()
            try assertFileCurrent()
            try ancestry.requireMarkerAbsent()
        }
    }

    private static let actorLock = NSLock()
    private static var actor: ActorOwner?
    private static var actorPoisoned = false

    /// Only helper actor selection calls this, after its private immutable
    /// selection. No droppable owner/FD is returned. The callback is a pure
    /// protected descriptor read and must not reenter selection/lease methods.
    static func retainSelectedActor(binding: SelectedBinding, readDescriptor: () throws -> Data) throws {
        actorLock.lock()
        defer { actorLock.unlock() }
        guard !actorPoisoned else { throw Failure.startInhibited }
        if let retained = actor {
            do { try retained.assertCurrent(binding: binding, readDescriptor: readDescriptor) }
            catch { actorPoisoned = true; throw error }
            return
        }
        let admitted = try ActorOwner(binding: binding, readDescriptor: readDescriptor)
        // The process-static strong reference remains even after later poison.
        actor = admitted
    }

    /// Repeated peer/action admission requires the existing actual owner; it
    /// never acquires/replaces a lease from a target supplied by that action.
    static func assertSelectedActor(binding: SelectedBinding, readDescriptor: () throws -> Data) throws {
        actorLock.lock()
        defer { actorLock.unlock() }
        guard !actorPoisoned, let retained = actor else { throw Failure.startInhibited }
        do { try retained.assertCurrent(binding: binding, readDescriptor: readDescriptor) }
        catch { actorPoisoned = true; throw error }
    }

    private static func isProtectedDirectory(_ value: stat) -> Bool {
        value.st_mode & S_IFMT == S_IFDIR && value.st_uid == 0 && value.st_mode & 0o022 == 0
    }

    private static func protectedDirectory(_ fd: Int32) throws -> stat {
        var value = stat()
        guard fstat(fd, &value) == 0, isProtectedDirectory(value) else { throw Failure.startInhibited }
        return value
    }

    private static func sameDirectory(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid
            && a.st_gid == b.st_gid && a.st_mode == b.st_mode
    }

    /// Only macOS's fixed root aliases are normalized. The decoded descriptor's
    /// root must otherwise retain its exact absolute, bounded ASCII spelling.
    private static func normalizedSupportRoot(_ path: String) throws -> String {
        guard path.hasPrefix("/"), path != "/", path.utf8.count <= 4096,
              path.utf8.allSatisfy({ $0 < 128 }),
              !path.unicodeScalars.contains(where: {
                  CharacterSet.controlCharacters.contains($0) || "'\"`$;&|<>()\\".unicodeScalars.contains($0)
              }) else { throw Failure.startInhibited }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.first == "", parts.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw Failure.startInhibited
        }
        let first = String(parts[1]), folded = first.lowercased()
        if ["var", "tmp", "etc", "private"].contains(folded) && first != folded {
            throw Failure.startInhibited
        }
        if first == "private" && parts.count > 2 {
            let second = String(parts[2]), lowerSecond = second.lowercased()
            if ["var", "tmp", "etc"].contains(lowerSecond) && second != lowerSecond {
                throw Failure.startInhibited
            }
        }
        for alias in ["/var", "/tmp", "/etc"] {
            if path == alias || path.hasPrefix(alias + "/") { return "/private" + path }
        }
        return path
    }
}
