import Darwin
import Foundation
import Security
import CoreGraphics

/// The GUI helper authenticates the connected process before reading any prompt.
/// A service UID is necessary but does not identify the executable holding it.
enum PeerIdentity {
    private static let custodyIdentifier = "com.enterprise.enclave.custody"
    private static let pinDirectory = "/Library/Application Support/EnterpriseEnclave"
    private static let pinPath = pinDirectory + "/codesign-pins.json"

    static func isCurrentConsole() -> Bool {
        var console = stat()
        guard stat("/dev/console", &console) == 0 && getuid() >= 500 && console.st_uid == getuid(),
              let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return session[kCGSessionOnConsoleKey as String] as? Bool == true
            && session[kCGSessionLoginDoneKey as String] as? Bool == true
    }

    /// UID of the custody peer. Installed builds: the dedicated `_piivault`
    /// UID 703. Development builds (`-D depot_DEV_SAME_UID`, Track C local
    /// fleet only): the console user's own UID, and nothing else. The code
    /// identity check (identifier + root-owned cdhash pins) is unchanged.
    /// Present only in development builds; packaging refuses a helper that
    /// carries it (packaging/macos/build.sh).
    #if depot_DEV_SAME_UID
    static let devSameUidMarker = "depot intent helper dev same-UID (development only)"
    #endif

    static var custodyUid: uid_t {
        #if depot_DEV_SAME_UID
        return getuid()
        #else
        return 703
        #endif
    }

    static func socketDirectoryIsProtected(_ path: String) -> Bool {
        #if depot_DEV_SAME_UID
        // Development fleet: the socket lives in the fleet's private socket
        // directory, owned by this user, mode 0700, never a symlink.
        let directory = (path as NSString).deletingLastPathComponent
        var info = stat()
        guard path.hasSuffix("/intent.sock"), isCurrentConsole(),
              lstat(directory, &info) == 0 else { return false }
        return info.st_mode & S_IFMT == S_IFDIR && info.st_uid == getuid() && info.st_mode & 0o077 == 0
        #else
        if let target = DeploymentTargetContext.selected {
            return path == target.intentSocket(uid: getuid()) && isCurrentConsole()
                && DeploymentTargetContext.intentDirectoryIsProtected(target, uid: getuid())
        }
        let parent = "/var/run/enclave/intent"
        let child = parent + "/\(getuid())"
        guard path == child + "/intent.sock", isCurrentConsole() else { return false }
        var parentStat = stat()
        var childStat = stat()
        guard lstat(parent, &parentStat) == 0, lstat(child, &childStat) == 0 else { return false }
        return parentStat.st_mode & S_IFMT == S_IFDIR && parentStat.st_uid == 0
            && parentStat.st_gid == 0 && parentStat.st_mode & 0o7777 == 0o755
            && childStat.st_mode & S_IFMT == S_IFDIR && childStat.st_uid == getuid()
            && childStat.st_gid == 8703 && childStat.st_mode & 0o7777 == 0o2710
        #endif
    }

    private static func signingInformation(_ code: SecCode) -> [String: Any]? {
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess else { return nil }
        return information as? [String: Any]
    }

    /// Fresh root-protected pins on every connection; rotation/revocation is not cached.
    private static func custodyPins() -> [String]? {
        if let target = DeploymentTargetContext.selected {
            // Fresh exact target pins only: no cache, installed fallback or union.
            return try? DeploymentTargetContext.selectedCustodyPins(target)
        }
        var directory = stat()
        guard lstat(pinDirectory, &directory) == 0,
              directory.st_mode & S_IFMT == S_IFDIR, directory.st_uid == 0,
              directory.st_mode & 0o022 == 0 else { return nil }
        let fd = open(pinPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == 0, metadata.st_mode & 0o022 == 0,
              metadata.st_size > 0, metadata.st_size <= 1_048_576 else { return nil }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while data.count <= 1_048_576 {
            let count = read(fd, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 { if errno == EINTR { continue }; return nil }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard data.count <= 1_048_576,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["v"] as? Int == 1,
              let pins = object["pins"] as? [String: [String]],
              let hashes = pins[custodyIdentifier], !hashes.isEmpty,
              hashes.allSatisfy({ $0.utf8.count == 40 && $0.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) }) else { return nil }
        return hashes.map { $0.lowercased() }
    }

    static func verifyCustody(_ fd: Int32) -> Bool {
        guard isCurrentConsole() else { return false }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == custodyUid,
              let hashes = custodyPins() else { return false }
        // LOCAL_PEERTOKEN is kernel-attested and includes PID version; do not
        // resolve a caller-supplied PID, which could race process replacement.
        var token = [UInt32](repeating: 0, count: 8)
        var tokenSize = socklen_t(MemoryLayout<UInt32>.size * token.count)
        guard getsockopt(fd, 0, LOCAL_PEERTOKEN, &token, &tokenSize) == 0,
              tokenSize == 32 else { return false }
        let audit = token.withUnsafeBytes { Data($0) }
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary, SecCSFlags(), &guest) == errSecSuccess,
              let guest, let information = signingInformation(guest),
              information[kSecCodeInfoIdentifier as String] as? String == custodyIdentifier,
              let digest = information[kSecCodeInfoUnique as String] as? Data,
              hashes.contains(digest.map { String(format: "%02x", $0) }.joined()) else { return false }
        var ownCode: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &ownCode) == errSecSuccess, let ownCode,
              let own = signingInformation(ownCode) else { return false }
        let team = own[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        let peerTeam = information[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        guard team == peerTeam else { return false }
        let identity = "identifier \"\(custodyIdentifier)\""
        let text = team.isEmpty ? identity : "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and \(identity)"
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(guest, SecCSFlags(), requirement) == errSecSuccess
    }
}
