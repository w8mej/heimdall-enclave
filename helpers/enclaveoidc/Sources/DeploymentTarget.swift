import Darwin
import Foundation

/// Root-selected deployment routing. No descriptor is discovered from a socket,
/// peer, user preference or fallback search. Selection finishes before NSApp.
enum OIDCDeploymentTargetContext {
    enum Failure: Error { case configuration }

    struct Target {
        let configPath: String
        let descriptorBytes: Data
        let supportRoot: String
        let targetID: String
        let profile: String
        let socketRoot: String
        let pinsFile: String
        let signingMode: String
        let references: [(String, Int)]
        var identityPath: String { supportRoot + "/oidc-broker-identity.json" }
        var oauthPath: String { supportRoot + "/oidc-oauth.json" }
        var brokerParent: String { socketRoot + "/oidc" }
        func brokerSocket(uid: uid_t) -> String { brokerParent + "/\(uid)/broker.sock" }
    }

    // Fix selection before actor admission; callbacks never recurse into the
    // actor-facing selected initializer while the private lease mutex is held.
    private static let configuration: Target? = {
        do { return try select(arguments: CommandLine.arguments) }
        catch { fputs("enclave-oidc: DEPLOYMENT_TARGET_CONFIGURATION\n", stderr); exit(2) }
    }()

    // No mutator/fallback. Retain actual SH before NSApplication or effects.
    static let selected: Target? = {
        guard let target = configuration else { return nil }
        do {
            let binding = try selectedBinding(target)
            try DeploymentUpgrade.retainSelectedActor(binding: binding) {
                try readProtected(target.configPath, maximum: 65_536)
            }
            try check(target)
            _ = try selectedPins(target)
            try check(target)
            return target
        } catch { fputs("enclave-oidc: DEPLOYMENT_TARGET_CONFIGURATION\n", stderr); exit(2) }
    }()

    private static func selectedBinding(_ target: Target) throws -> DeploymentUpgrade.SelectedBinding {
        guard let fixed = configuration,
              target.configPath == fixed.configPath, target.descriptorBytes == fixed.descriptorBytes,
              target.supportRoot == fixed.supportRoot, target.targetID == fixed.targetID,
              target.profile == fixed.profile, target.socketRoot == fixed.socketRoot,
              target.pinsFile == fixed.pinsFile, target.signingMode == fixed.signingMode,
              target.references.count == fixed.references.count,
              zip(target.references, fixed.references).allSatisfy({ $0.0.0 == $0.1.0 && $0.0.1 == $0.1.1 }) else {
            throw Failure.configuration
        }
        return DeploymentUpgrade.SelectedBinding(configPath: fixed.configPath,
            descriptorBytes: fixed.descriptorBytes, supportRoot: fixed.supportRoot)
    }

    private static func assertSelectedActor(_ target: Target) throws {
        let binding = try selectedBinding(target)
        try DeploymentUpgrade.assertSelectedActor(binding: binding) {
            try readProtected(target.configPath, maximum: 65_536)
        }
    }

    private indirect enum JSONValue {
        case object([String: JSONValue]), array([JSONValue]), string(String), atom(String)
    }

    /// Foundation's dictionary decoder alone silently merges duplicate keys.
    /// This bounded grammar keeps decoded key uniqueness at EVERY object level.
    private struct JSONReader {
        let bytes: [UInt8]
        var offset = 0
        mutating func whitespace() { while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
        mutating func consume(_ byte: UInt8) -> Bool {
            whitespace()
            if offset < bytes.count && bytes[offset] == byte { offset += 1; return true }
            return false
        }
        mutating func string() throws -> String {
            whitespace()
            guard offset < bytes.count && bytes[offset] == 34 else { throw Failure.configuration }
            let start = offset; offset += 1
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 34 {
                    let data = Data(bytes[start..<offset])
                    guard let value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? String else { throw Failure.configuration }
                    return value
                }
                if byte == 92 {
                    guard offset < bytes.count else { throw Failure.configuration }
                    offset += 1
                } else if byte < 32 { throw Failure.configuration }
            }
            throw Failure.configuration
        }
        mutating func value(depth: Int = 0) throws -> JSONValue {
            guard depth <= 12 else { throw Failure.configuration }
            whitespace(); guard offset < bytes.count else { throw Failure.configuration }
            if bytes[offset] == 34 { return .string(try string()) }
            if consume(123) {
                var fields: [String: JSONValue] = [:]
                if consume(125) { return .object(fields) }
                repeat {
                    let key = try string()
                    guard fields[key] == nil, fields.count < 32768, consume(58) else { throw Failure.configuration }
                    fields[key] = try value(depth: depth + 1)
                    if consume(125) { return .object(fields) }
                    guard consume(44) else { throw Failure.configuration }
                } while true
            }
            if consume(91) {
                var values: [JSONValue] = []
                if consume(93) { return .array(values) }
                repeat {
                    guard values.count < 32768 else { throw Failure.configuration }
                    values.append(try value(depth: depth + 1))
                    if consume(93) { return .array(values) }
                    guard consume(44) else { throw Failure.configuration }
                } while true
            }
            let start = offset
            while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
            guard start < offset, let text = String(bytes: bytes[start..<offset], encoding: .utf8),
                  (try? JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: [.fragmentsAllowed])) != nil else { throw Failure.configuration }
            return .atom(text)
        }
        mutating func complete() throws -> JSONValue {
            let result = try value(); whitespace()
            guard offset == bytes.count else { throw Failure.configuration }
            return result
        }
    }

    private static func object(_ node: JSONValue, keys: Set<String>) throws -> [String: JSONValue] {
        guard case .object(let value) = node, Set(value.keys) == keys else { throw Failure.configuration }
        return value
    }
    private static func text(_ node: JSONValue?) throws -> String {
        guard let node, case .string(let value) = node else { throw Failure.configuration }
        return value
    }
    private static func name(_ value: String, maximum: Int, dotted: Bool) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximum else { return false }
        let labels = dotted ? value.split(separator: ".", omittingEmptySubsequences: false).map(String.init) : [value]
        guard !dotted || labels.count >= 2 else { return false }
        return labels.allSatisfy { label in
            let bytes = Array(label.utf8)
            guard !bytes.isEmpty, bytes.count <= (dotted ? 63 : maximum),
                  (97...122).contains(bytes[0]), let last = bytes.last,
                  (97...122).contains(last) || (48...57).contains(last) else { return false }
            return bytes.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }
    /// Lexical aliases only; never follow arbitrary links to manufacture trust.
    static func normalizedPath(_ path: String) throws -> String {
        guard path.hasPrefix("/"), path != "/", path.utf8.count <= 4096,
              path.utf8.allSatisfy({ $0 < 128 }),
              !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || "'\"`$;&|<>()\\".unicodeScalars.contains($0) }) else { throw Failure.configuration }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard components.first == "", components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw Failure.configuration }
        // The fixed macOS root aliases have one accepted spelling. Reject
        // case variants before held-FD traversal; preserve all actual routes.
        let first = String(components[1]), foldedFirst = first.lowercased()
        if ["var", "tmp", "etc", "private"].contains(foldedFirst) && first != foldedFirst { throw Failure.configuration }
        if first == "private" && components.count > 2 {
            let second = String(components[2]), foldedSecond = second.lowercased()
            if ["var", "tmp", "etc"].contains(foldedSecond) && second != foldedSecond { throw Failure.configuration }
        }
        for prefix in ["/var", "/tmp", "/etc"] {
            if path == prefix || path.hasPrefix(prefix + "/") { return "/private" + path }
        }
        return path
    }
    private static func overlaps(_ left: String, _ right: String) -> Bool {
        // Isolation must also hold on case-insensitive macOS volumes. Paths
        // are ASCII and fixed-alias normalized before this comparison.
        let lowerLeft = left.lowercased(), lowerRight = right.lowercased()
        return lowerLeft == lowerRight || lowerLeft.hasPrefix(lowerRight + "/") || lowerRight.hasPrefix(lowerLeft + "/")
    }
    static func decode(_ data: Data, configPath: String) throws -> Target {
        guard !data.isEmpty, data.count <= 65536 else { throw Failure.configuration }
        var reader = JSONReader(bytes: Array(data))
        let fields = try object(reader.complete(), keys: ["version", "target_id", "role", "profile", "authority_config", "expected_artifacts_manifest", "codesign_pins_file", "signing_identity_mode", "layout", "broker", "shared_read_only_inputs"])
        guard let version = fields["version"], case .atom("1") = version else { throw Failure.configuration }
        let identifier = try text(fields["target_id"])
        let role = try text(fields["role"]), profile = try text(fields["profile"])
        let signingMode = try text(fields["signing_identity_mode"])
        guard name(identifier, maximum: 64, dotted: false), ["dedicated-test", "existing-upgrade"].contains(role),
              ["L2", "L3"].contains(profile), ["local-pins", "team-id"].contains(signingMode) else { throw Failure.configuration }
        let layout = try object(fields["layout"]!, keys: ["binary_dir", "custody_bundle", "sandbox_dir", "socket_root", "state_root", "audit_root", "cas_store_root", "staging_root", "support_root", "launchd_namespace", "mach_service"])
        guard name(try text(layout["launchd_namespace"]), maximum: 112, dotted: true),
              name(try text(layout["mach_service"]), maximum: 128, dotted: true) else { throw Failure.configuration }
        let rootKeys = ["binary_dir", "custody_bundle", "sandbox_dir", "socket_root", "state_root", "audit_root", "cas_store_root", "staging_root", "support_root"]
        var roots: [String: String] = [:]
        for key in rootKeys {
            let raw = try text(layout[key]), path = try normalizedPath(raw)
            if ["socket_root", "state_root", "audit_root", "cas_store_root", "staging_root"].contains(key)
                && raw.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) }) { throw Failure.configuration }
            roots[key] = path
        }
        for (index, key) in rootKeys.enumerated() {
            for other in rootKeys.dropFirst(index + 1) where overlaps(roots[key]!, roots[other]!) {
                let bundleBelowSupport = Set([key, other]) == Set(["custody_bundle", "support_root"])
                    && roots["custody_bundle"]!.hasPrefix(roots["support_root"]! + "/")
                guard bundleBelowSupport else { throw Failure.configuration }
            }
        }
        let authority = try normalizedPath(text(fields["authority_config"]))
        let artifacts = try normalizedPath(text(fields["expected_artifacts_manifest"]))
        let pins = try normalizedPath(text(fields["codesign_pins_file"]))
        var references = [(authority, 1_048_576), (artifacts, 1_048_576)]
        var outputs = Array(roots.values)
        guard let broker = fields["broker"] else { throw Failure.configuration }
        if profile == "L2" {
            guard case .atom("null") = broker else { throw Failure.configuration }
        } else {
            let values = try object(broker, keys: ["base_dir", "tuf_root_file"])
            let base = try normalizedPath(text(values["base_dir"]))
            guard base == roots["state_root"]! + "/apfs-broker" else { throw Failure.configuration }
            outputs.append(base)
            references.append((try normalizedPath(text(values["tuf_root_file"])), 4_194_304))
        }
        for input in references.map({ $0.0 }) + [pins, try normalizedPath(configPath)] {
            guard !outputs.filter({ $0 != roots["support_root"]! }).contains(where: { overlaps(input, $0) }) else { throw Failure.configuration }
        }
        guard !references.contains(where: { overlaps($0.0, pins) }) else { throw Failure.configuration }
        for (index, reference) in references.enumerated() {
            guard !references.dropFirst(index + 1).contains(where: { overlaps(reference.0, $0.0) }) else { throw Failure.configuration }
        }
        if role == "dedicated-test" {
            let installed = try ["/opt/enterprise/enclave", "/var/run/enclave", "/var/db/enclave", "/var/log/enclave", "/Library/Application Support/EnterpriseEnclave"].map(normalizedPath)
            guard !(outputs + [pins]).contains(where: { root in installed.contains(where: { overlaps(root, $0) }) }),
                  try text(layout["launchd_namespace"]) != "com.enterprise.enclave",
                  try text(layout["mach_service"]) != "com.enterprise.enclave.exception" else { throw Failure.configuration }
        }
        guard let sharedNode = fields["shared_read_only_inputs"], case .array(let shared) = sharedNode, shared.count <= 8 else { throw Failure.configuration }
        var seen: Set<String> = []
        for node in shared {
            let path = try normalizedPath(text(node))
            guard references.contains(where: { $0.0 == path }), seen.insert(path).inserted else { throw Failure.configuration }
        }
        let target = Target(configPath: configPath, descriptorBytes: data, supportRoot: try text(layout["support_root"]), targetID: identifier, profile: profile,
            socketRoot: try text(layout["socket_root"]), pinsFile: try text(fields["codesign_pins_file"]), signingMode: signingMode, references: references)
        // Bound the longest possible UID route, before trusting the live console.
        guard target.brokerSocket(uid: UInt32.max).utf8.count < 104 else { throw Failure.configuration }
        return target
    }

    static var compiledSigningMode: String {
        #if depot_TEAM_ID_MODE
        return "team-id"
        #else
        return "local-pins"
        #endif
    }
    static func validateArguments(_ options: BrokerArguments, target: Target) throws {
        guard options.deploymentPath == target.configPath, options.identityPath == target.identityPath,
              options.oauthPath == target.oauthPath, target.signingMode == compiledSigningMode else { throw Failure.configuration }
    }
    private static func select(arguments: [String]) throws -> Target? {
        let options = try BrokerArguments.parse(arguments)
        guard let path = options.deploymentPath else { return nil }
        #if depot_OIDC_NATIVE_TESTING
        // A differently compiled pure fixture can never activate a deployment.
        throw Failure.configuration
        #else
        guard getuid() >= 500, getuid() != UInt32.max else { throw Failure.configuration }
        let bytes = try readProtected(path, maximum: 65536)
        let target = try decode(bytes, configPath: path)
        try validateArguments(options, target: target)
        try DeploymentUpgrade.assertStartAllowed(supportRoot: target.supportRoot)
        return target
        #endif
    }
    #if depot_OIDC_NATIVE_TESTING
    static func testSelection(_ arguments: [String]) throws -> Target? { try select(arguments: arguments) }
    #endif
    static func validateDescriptorBytes(_ bytes: Data, target: Target) throws {
        guard bytes == target.descriptorBytes else { throw Failure.configuration }
    }
    static func check(_ target: Target) throws {
        // This boundary is reused before selected startup and live peer/action
        // admission. A marker is denial only; its contents are never trusted.
        try assertSelectedActor(target)
        try validateDescriptorBytes(readProtected(target.configPath, maximum: 65536), target: target)
        for (path, maximum) in target.references { _ = try readProtected(path, maximum: maximum) }
        try validateDescriptorBytes(readProtected(target.configPath, maximum: 65536), target: target)
        try assertSelectedActor(target)
    }
    static func selectedPins(_ target: Target) throws -> [String: [String]] {
        try check(target)
        let pins = try decodePins(readProtected(target.pinsFile, maximum: 1_048_576))
        try check(target)
        return pins
    }
    static func decodePins(_ data: Data) throws -> [String: [String]] {
        guard !data.isEmpty, data.count <= 1_048_576 else { throw Failure.configuration }
        var reader = JSONReader(bytes: Array(data))
        guard case .object(let fields) = try reader.complete(),
              Set(fields.keys) == Set(["v", "pins"]) || Set(fields.keys) == Set(["v", "mode", "pins"]),
              let version = fields["v"], case .atom("1") = version,
              let node = fields["pins"], case .object(let entries) = node else { throw Failure.configuration }
        if let mode = fields["mode"] { guard try text(mode) == compiledSigningMode else { throw Failure.configuration } }
        var result: [String: [String]] = [:]
        for (identifier, node) in entries {
            guard case .array(let values) = node, !values.isEmpty else { throw Failure.configuration }
            result[identifier] = try values.map {
                let value = try text($0)
                guard value.utf8.count == 40, value.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else { throw Failure.configuration }
                return value.lowercased()
            }
        }
        guard result["com.enterprise.enclave.custody"] != nil,
              result["com.enterprise.enclave.oidc-broker"] != nil else { throw Failure.configuration }
        return result
    }

    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_gid == b.st_gid
            && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_size == b.st_size
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    /// Every ancestor remains held until final named-entry/FD checks complete.
    /// Only Darwin's fixed lexical aliases are normalized for filesystem reads.
    static func readProtected(_ rawPath: String, maximum: Int) throws -> Data {
        let path = try normalizedPath(rawPath)
        let parts = path.split(separator: "/").map(String.init)
        guard maximum > 0, maximum <= 4_194_304, parts.count <= 96 else { throw Failure.configuration }
        let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw Failure.configuration }
        var held: [(Int32, stat, Int32?, String?)] = []
        var opened: [Int32] = [root]
        defer { for fd in opened.reversed() { close(fd) } }
        var initial = stat()
        guard fstat(root, &initial) == 0, initial.st_uid == 0,
              initial.st_mode & S_IFMT == S_IFDIR, initial.st_mode & 0o022 == 0 else { throw Failure.configuration }
        held.append((root, initial, nil, nil))
        for (index, part) in parts.enumerated() {
            let parent = opened.last!, last = index + 1 == parts.count
            let fd = openat(parent, part, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (last ? 0 : O_DIRECTORY))
            guard fd >= 0 else { throw Failure.configuration }
            opened.append(fd)
            var before = stat(), named = stat()
            guard fstat(fd, &before) == 0, fstatat(parent, part, &named, AT_SYMLINK_NOFOLLOW) == 0,
                  same(before, named), before.st_uid == 0, before.st_mode & 0o022 == 0,
                  before.st_mode & S_IFMT == (last ? S_IFREG : S_IFDIR) else { throw Failure.configuration }
            held.append((fd, before, parent, part))
            if last {
                guard before.st_nlink == 1, before.st_size > 0, before.st_size <= off_t(maximum) else { throw Failure.configuration }
                var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
                while data.count <= maximum {
                    let count = read(fd, &buffer, min(buffer.count, maximum + 1 - data.count))
                    if count < 0 && errno == EINTR { continue }
                    guard count >= 0 else { throw Failure.configuration }
                    if count == 0 { break }
                    data.append(contentsOf: buffer.prefix(count))
                }
                guard off_t(data.count) == before.st_size, data.count <= maximum else { throw Failure.configuration }
                for (fd, observed, parent, part) in held.reversed() {
                    var current = stat()
                    guard fstat(fd, &current) == 0, same(current, observed) else { throw Failure.configuration }
                    if let parent, let part {
                        guard fstatat(parent, part, &current, AT_SYMLINK_NOFOLLOW) == 0,
                              same(current, observed) else { throw Failure.configuration }
                    }
                }
                return data
            }
        }
        throw Failure.configuration
    }

    /// Held runtime ancestry. Console-child contents may change because this
    /// process owns its lock/socket, so directory identity/ownership/mode are
    /// rechecked without treating our own content writes as descriptor drift.
    final class RuntimeDirectory {
        private let held: [(Int32, stat, Int32?, String?)]
        var fd: Int32 { held.last!.0 }
        private init(_ held: [(Int32, stat, Int32?, String?)]) { self.held = held }
        deinit { for entry in held.reversed() { close(entry.0) } }
        private static func sameDirectory(_ a: stat, _ b: stat) -> Bool {
            a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid
                && a.st_gid == b.st_gid && a.st_mode == b.st_mode && a.st_mode & S_IFMT == S_IFDIR
        }
        func check() throws {
            for (fd, observed, parent, part) in held.reversed() {
                var current = stat()
                guard fstat(fd, &current) == 0, Self.sameDirectory(current, observed) else { throw Failure.configuration }
                if let parent, let part {
                    guard fstatat(parent, part, &current, AT_SYMLINK_NOFOLLOW) == 0,
                          Self.sameDirectory(current, observed) else { throw Failure.configuration }
                }
            }
        }
        static func openSelected(_ target: Target, uid: uid_t) throws -> RuntimeDirectory {
            let path = try normalizedPath(target.brokerParent + "/\(uid)")
            let parts = path.split(separator: "/").map(String.init)
            guard parts.count <= 96 else { throw Failure.configuration }
            let root = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard root >= 0 else { throw Failure.configuration }
            var held: [(Int32, stat, Int32?, String?)] = []
            var opened: [Int32] = [root], transferred = false
            defer { if !transferred { for fd in opened.reversed() { close(fd) } } }
            var rootStat = stat()
            guard fstat(root, &rootStat) == 0, rootStat.st_mode & S_IFMT == S_IFDIR,
                  rootStat.st_uid == 0, rootStat.st_mode & 0o022 == 0 else { throw Failure.configuration }
            held.append((root, rootStat, nil, nil))
            for (index, part) in parts.enumerated() {
                let parent = opened.last!
                let fd = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
                guard fd >= 0 else { throw Failure.configuration }
                opened.append(fd)
                var state = stat(), named = stat()
                guard fstat(fd, &state) == 0, fstatat(parent, part, &named, AT_SYMLINK_NOFOLLOW) == 0,
                      Self.sameDirectory(state, named) else { throw Failure.configuration }
                if index + 1 == parts.count {
                    guard state.st_uid == uid, state.st_gid == 8703, state.st_mode & 0o7777 == 0o2710 else { throw Failure.configuration }
                } else {
                    guard state.st_uid == 0, state.st_mode & 0o022 == 0 else { throw Failure.configuration }
                    if index + 2 == parts.count {
                        guard state.st_gid == 0, state.st_mode & 0o7777 == 0o755 else { throw Failure.configuration }
                    }
                }
                held.append((fd, state, parent, part))
            }
            let result = RuntimeDirectory(held); transferred = true
            try result.check(); return result
        }
    }
}

/// Closed fixed-order renderer arguments; there are no socket/pin overrides.
struct BrokerArguments {
    let identityPath: String
    let oauthPath: String
    let deploymentPath: String?
    static func parse(_ args: [String]) throws -> BrokerArguments {
        guard (args.count == 5 || args.count == 7), args[1] == "--identity-config",
              args[3] == "--oauth-config" else { throw BrokerFailure.refused }
        if args.count == 7 { guard args[5] == "--deployment-target" else { throw BrokerFailure.refused } }
        return BrokerArguments(identityPath: args[2], oauthPath: args[4], deploymentPath: args.count == 7 ? args[6] : nil)
    }
}

