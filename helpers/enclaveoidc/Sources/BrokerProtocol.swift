import AppKit
import CoreGraphics
import CryptoKit
import Darwin
import Foundation
import Security

enum BrokerFailure: Error { case refused }

enum BrokerSession {
    static func current() -> (UInt32, UInt32)? {
        guard PeerIdentity.isCurrentConsole(),
              let session = CGSessionCopyCurrentDictionary() as? [String: Any],
              let user = session["kCGSessionUserIDKey"] as? NSNumber,
              let audit = session["kCGSessionAuditIDKey"] as? NSNumber,
              let uid = UInt32(exactly: user.int64Value), uid == getuid(),
              let asid = UInt32(exactly: audit.int64Value), asid != 0, asid != UInt32.max else { return nil }
        return (uid, asid)
    }
    static func matches(_ uid: UInt32, _ audit: UInt32) -> Bool {
        guard let current = current() else { return false }
        return current.0 == uid && current.1 == audit
    }
}

enum ProtectedBrokerFile {
    static func load(_ path: String) throws -> Data {
        guard path.hasPrefix("/"), URL(fileURLWithPath: path).standardized.path == path else { throw BrokerFailure.refused }
        if let target = OIDCDeploymentTargetContext.selected {
            try OIDCDeploymentTargetContext.check(target)
            let data = try OIDCDeploymentTargetContext.readProtected(path, maximum: 16384)
            try OIDCDeploymentTargetContext.check(target)
            return data
        }
        var ancestor = URL(fileURLWithPath: path).deletingLastPathComponent()
        while true {
            var state = stat()
            guard lstat(ancestor.path, &state) == 0, state.st_mode & S_IFMT == S_IFDIR,
                  state.st_uid == 0, state.st_mode & 0o022 == 0 else { throw BrokerFailure.refused }
            if ancestor.path == "/" { break }
            ancestor.deleteLastPathComponent()
        }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw BrokerFailure.refused }
        defer { close(fd) }
        var state = stat()
        guard fstat(fd, &state) == 0, state.st_mode & S_IFMT == S_IFREG,
              state.st_uid == 0, state.st_mode & 0o022 == 0, state.st_nlink == 1,
              state.st_size > 0, state.st_size <= 16384 else { throw BrokerFailure.refused }
        var data = Data(); var bytes = [UInt8](repeating: 0, count: 4096)
        while data.count <= 16384 {
            let count = read(fd, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw BrokerFailure.refused }
            if count == 0 { break }
            data.append(contentsOf: bytes.prefix(count))
        }
        guard data.count == state.st_size else { throw BrokerFailure.refused }
        return data
    }

    static func decode<T: Decodable>(_ type: T.Type, _ data: Data, keys: Set<String>) throws -> T {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys,
              try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]) == data else { throw BrokerFailure.refused }
        // Exact compact sorted JSON also refuses duplicate members before the
        // resulting configuration is used. Public configuration has no secrets.
        return try JSONDecoder().decode(type, from: data)
    }
}

struct BrokerIdentityConfig: Decodable {
    let v: UInt8
    let socket: String
    let identifier: String
    let console_uid: UInt32
    let audit_session_id: UInt32
    let expires_unix: Int64
    func matchesRoute(_ expectedSocket: String, uid: UInt32) -> Bool {
        v == 1 && identifier == "com.enterprise.enclave.oidc-broker" && socket == expectedSocket && console_uid == uid
    }
    static func load(_ path: String) throws -> (BrokerIdentityConfig, Data) {
        let expectedSocket: String
        if let target = OIDCDeploymentTargetContext.selected {
            guard path == target.identityPath else { throw BrokerFailure.refused }
            try OIDCDeploymentTargetContext.check(target)
            expectedSocket = target.brokerSocket(uid: getuid())
        } else { expectedSocket = "/var/run/enclave/oidc/\(getuid())/broker.sock" }
        let data = try ProtectedBrokerFile.load(path)
        let value = try ProtectedBrokerFile.decode(Self.self, data, keys: ["v", "socket", "identifier", "console_uid", "audit_session_id", "expires_unix"])
        guard value.matchesRoute(expectedSocket, uid: getuid()),
              value.expires_unix > Int64(Date().timeIntervalSince1970),
              BrokerSession.matches(value.console_uid, value.audit_session_id) else { throw BrokerFailure.refused }
        return (value, Data(SHA256.hash(data: data)))
    }
}

struct BrokerOAuthConfig: Decodable {
    let v: UInt8
    let issuer: String
    let audience: String
    let client_id: String
    let authorization_endpoint: String
    let token_endpoint: String
    let redirect_uri: String
    let callback_scheme: String
    let expires_unix: Int64
    static func https(_ text: String) -> URL? {
        guard text.utf8.count <= 2048, let parts = URLComponents(string: text),
              parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil,
              parts.fragment == nil, parts.port == nil || parts.port == 443 else { return nil }
        return parts.url
    }
    static func load(_ path: String) throws -> (BrokerOAuthConfig, Data) {
        if let target = OIDCDeploymentTargetContext.selected {
            guard path == target.oauthPath else { throw BrokerFailure.refused }
            try OIDCDeploymentTargetContext.check(target)
        }
        let data = try ProtectedBrokerFile.load(path)
        let value = try ProtectedBrokerFile.decode(Self.self, data, keys: ["v", "issuer", "audience", "client_id", "authorization_endpoint", "token_endpoint", "redirect_uri", "callback_scheme", "expires_unix"])
        try value.validate()
        return (value, Data(SHA256.hash(data: data)))
    }
    func validate() throws {
        guard v == 1, Self.https(issuer) != nil, Self.https(authorization_endpoint) != nil,
              Self.https(token_endpoint) != nil, !audience.isEmpty, audience.utf8.count <= 1024,
              !client_id.isEmpty, client_id.utf8.count <= 1024,
              !client_id.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              expires_unix > Int64(Date().timeIntervalSince1970),
              callback_scheme.hasPrefix("com.enterprise.enclave.oidc"), callback_scheme.utf8.count <= 128,
              callback_scheme.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 45 }),
              redirect_uri.utf8.count <= 2048, let redirect = URLComponents(string: redirect_uri),
              redirect.scheme == callback_scheme, redirect.host != nil, redirect.user == nil,
              redirect.password == nil, redirect.port == nil, redirect.query == nil,
              redirect.fragment == nil else { throw BrokerFailure.refused }
    }
}

struct BrokerRequest {
    let nonce: String
    let digest: String
    let boot: String
    let start: UInt64
    let deadline: UInt64
    let uid: UInt32
    let audit: UInt32
    let issuer: String
    let audience: String
    private static func strictEncoding(_ bytes: [UInt8]) throws {
        var offset = 0
        func length(_ major: UInt8) throws -> UInt64 {
            guard offset < bytes.count else { throw BrokerFailure.refused }
            let initial = bytes[offset]; offset += 1
            guard initial >> 5 == major else { throw BrokerFailure.refused }
            let info = initial & 31
            if info < 24 { return UInt64(info) }
            let width: Int
            switch info { case 24: width = 1; case 25: width = 2; case 26: width = 4; case 27: width = 8; default: throw BrokerFailure.refused }
            guard offset + width <= bytes.count else { throw BrokerFailure.refused }
            let value = bytes[offset..<(offset + width)].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            offset += width
            let minimum: UInt64 = width == 1 ? 24 : width == 2 ? 256 : width == 4 ? 65536 : 4294967296
            guard value >= minimum else { throw BrokerFailure.refused }
            return value
        }
        func text() throws {
            let size = try length(3)
            guard size <= UInt64(bytes.count - offset) else { throw BrokerFailure.refused }
            offset += Int(size)
        }
        guard try length(5) == 11 else { throw BrokerFailure.refused }
        for _ in 0..<11 {
            try text()
            guard offset < bytes.count else { throw BrokerFailure.refused }
            if bytes[offset] >> 5 == 3 { try text() }
            else { _ = try length(0) }
        }
        guard offset == bytes.count else { throw BrokerFailure.refused }
    }
    static func decode(_ bytes: [UInt8]) throws -> BrokerRequest {
        try strictEncoding(bytes)
        var reader = CBORReader(data: bytes)
        guard case .map(let pairs) = try reader.readValue(), pairs.count == 11,
              reader.offset == bytes.count else { throw BrokerFailure.refused }
        var fields = [String: CBORValue]()
        for (key, value) in pairs {
            guard case .textString(let key) = key, fields[key] == nil else { throw BrokerFailure.refused }
            fields[key] = value
        }
        func text(_ name: String) throws -> String {
            guard case .textString(let value)? = fields[name] else { throw BrokerFailure.refused }; return value
        }
        func number(_ name: String) throws -> UInt64 {
            guard case .unsigned(let value)? = fields[name] else { throw BrokerFailure.refused }; return value
        }
        guard Set(fields.keys) == ["protocol", "nonce", "d_jcs", "boot_epoch_id", "t_start_ns", "deadline_ns", "console_uid", "audit_session_id", "max_age_s", "issuer", "audience"],
              try text("protocol") == "enclave.oidc-step-up.v1", try number("max_age_s") == 0,
              let uid = UInt32(exactly: try number("console_uid")),
              let audit = UInt32(exactly: try number("audit_session_id")) else { throw BrokerFailure.refused }
        return BrokerRequest(nonce: try text("nonce"), digest: try text("d_jcs"), boot: try text("boot_epoch_id"),
            start: try number("t_start_ns"), deadline: try number("deadline_ns"), uid: uid, audit: audit,
            issuer: try text("issuer"), audience: try text("audience"))
    }
    func validate(_ identity: BrokerIdentityConfig, _ oauth: BrokerOAuthConfig, now: UInt64) throws {
        guard nonce.utf8.count == 43, nonce.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }),
              digest.utf8.count == 64, digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              !boot.isEmpty, boot.utf8.count <= 128, boot.utf8.allSatisfy({ (32...126).contains($0) }),
              start <= now, now < deadline, deadline > start, deadline - start <= 10_000_000_000,
              uid == identity.console_uid, audit == identity.audit_session_id,
              BrokerSession.matches(uid, audit), issuer == oauth.issuer, audience == oauth.audience else { throw BrokerFailure.refused }
    }
    func appendReply(token: Data, to bytes: inout [UInt8]) throws {
        guard !token.isEmpty, token.count <= 16384 else { throw BrokerFailure.refused }
        bytes += [0xa1] + CBOREncoder.encodeText("Ok") + [0xa3]
        bytes += CBOREncoder.encodeText("protocol") + CBOREncoder.encodeText("enclave.oidc-step-up.v1")
        bytes += CBOREncoder.encodeText("nonce") + CBOREncoder.encodeText(nonce)
        bytes += CBOREncoder.encodeText("token")
        if token.count < 24 { bytes.append(0x40 | UInt8(token.count)) }
        else if token.count <= 255 { bytes += [0x58, UInt8(token.count)] }
        else { bytes += [0x59, UInt8(token.count >> 8), UInt8(token.count & 255)] }
        token.withUnsafeBytes { bytes.append(contentsOf: $0) }
    }
}
