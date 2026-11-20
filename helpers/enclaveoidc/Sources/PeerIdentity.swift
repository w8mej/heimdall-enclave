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

    private static func selectedSelfMatches(_ target: OIDCDeploymentTargetContext.Target, pins: [String: [String]]) -> Bool {
        var ownCode: SecCode?
        guard target.signingMode == OIDCDeploymentTargetContext.compiledSigningMode,
              SecCodeCopySelf(SecCSFlags(), &ownCode) == errSecSuccess, let ownCode,
              SecCodeCheckValidity(ownCode, SecCSFlags(), nil) == errSecSuccess,
              let own = signingInformation(ownCode),
              own[kSecCodeInfoIdentifier as String] as? String == "com.enterprise.enclave.oidc-broker",
              let flags = own[kSecCodeInfoFlags as String] as? NSNumber, flags.uint32Value & 0x10000 != 0,
              let hash = own[kSecCodeInfoUnique as String] as? Data,
              pins["com.enterprise.enclave.oidc-broker"]?.contains(hash.map { String(format: "%02x", $0) }.joined()) == true else { return false }
        let team = own[kSecCodeInfoTeamIdentifier as String] as? String ?? ""
        return signingModeMatches(team: team)
    }
    static func signingModeMatches(team: String) -> Bool {
        #if MCPMAC_TEAM_ID_MODE
        return !team.isEmpty
        #else
        return team.isEmpty
        #endif
    }
    static func validateSelectedSelf(_ target: OIDCDeploymentTargetContext.Target) throws {
        let pins = try OIDCDeploymentTargetContext.selectedPins(target)
        guard selectedSelfMatches(target, pins: pins) else { throw BrokerFailure.refused }
        try OIDCDeploymentTargetContext.check(target)
    }

    static func verifyCustody(_ fd: Int32) -> Bool {
        guard isCurrentConsole() else { return false }
        let hashes: [String]
        if let target = OIDCDeploymentTargetContext.selected {
            // One fresh exact selected map authenticates both parties. No
            // installed pin union/fallback, JSON-controlled path or UID claim.
            guard let pins = try? OIDCDeploymentTargetContext.selectedPins(target),
                  let custody = pins[custodyIdentifier], selectedSelfMatches(target, pins: pins),
                  let runtime = try? OIDCDeploymentTargetContext.RuntimeDirectory.openSelected(target, uid: getuid()),
                  (try? runtime.check()) != nil else { return false }
            hashes = custody
        } else {
            guard let legacy = custodyPins() else { return false }; hashes = legacy
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == 703 else { return false }
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
