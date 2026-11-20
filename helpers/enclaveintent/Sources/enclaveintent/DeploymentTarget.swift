import Darwin
import Foundation

/// Root-selected deployment routing. No descriptor is discovered from a socket,
/// peer, user preference or fallback search. Selection finishes before NSApp.
enum DeploymentTargetContext {
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
        var intentParent: String { socketRoot + "/intent" }
        func intentSocket(uid: uid_t) -> String { intentParent + "/\(uid)/intent.sock" }
        var supervisorSocket: String { socketRoot + "/supervisor/supervisor.sock" }
    }

    // Fix the configuration separately from actor admission. Lease descriptor
    // callbacks only read this completed choice, never the selected initializer.
    private static let configuration: Target? = {
        do { return try select(arguments: CommandLine.arguments) }
        catch { fputs("enclave-intent: DEPLOYMENT_TARGET_CONFIGURATION\n", stderr); exit(2) }
    }()

    // No mutator/fallback. Hold the actual SH before any helper service effects.
    static let selected: Target? = {
        guard let target = configuration else { return nil }
        do {
            let binding = try selectedBinding(target)
            try DeploymentUpgrade.retainSelectedActor(binding: binding) {
                try readProtected(target.configPath, maximum: 65_536)
            }
            for (reference, maximum) in target.references { _ = try readProtected(reference, maximum: maximum) }
            _ = try selectedCustodyPins(target)
            try assertSelectedActor(target)
            return target
        } catch { fputs("enclave-intent: DEPLOYMENT_TARGET_CONFIGURATION\n", stderr); exit(2) }
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
    private static func decode(_ data: Data, configPath: String) throws -> Target {
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
        let target = Target(configPath: try normalizedPath(configPath), descriptorBytes: data, supportRoot: roots["support_root"]!, targetID: identifier, profile: profile,
            socketRoot: roots["socket_root"]!, pinsFile: pins, signingMode: signingMode, references: references)
        // Bound the longest possible UID route, before trusting the live console.
        guard target.intentSocket(uid: UInt32.max).utf8.count < 104, target.supervisorSocket.utf8.count < 104 else { throw Failure.configuration }
        return target
    }

    /// Held no-follow FD traversal is also reused for fresh selected pin reads.
    static func readProtected(_ rawPath: String, maximum: Int) throws -> Data {
        let path = try normalizedPath(rawPath)
        let components = path.split(separator: "/").map(String.init)
        var directory = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw Failure.configuration }
        defer { close(directory) }
        for (index, component) in components.enumerated() {
            var parent = stat()
            guard fstat(directory, &parent) == 0, parent.st_mode & S_IFMT == S_IFDIR,
                  parent.st_uid == 0, parent.st_mode & 0o022 == 0 else { throw Failure.configuration }
            let last = index + 1 == components.count
            let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (last ? 0 : O_DIRECTORY)
            let fd = openat(directory, component, flags)
            guard fd >= 0 else { throw Failure.configuration }
            if last {
                defer { close(fd) }
                var before = stat()
                guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
                      before.st_uid == 0, before.st_mode & 0o022 == 0, before.st_nlink == 1,
                      before.st_size > 0, before.st_size <= off_t(maximum) else { throw Failure.configuration }
                var data = Data(), buffer = [UInt8](repeating: 0, count: 4096)
                while data.count <= maximum {
                    let count = read(fd, &buffer, min(buffer.count, maximum + 1 - data.count))
                    if count < 0 && errno == EINTR { continue }
                    guard count >= 0 else { throw Failure.configuration }
                    if count == 0 { break }
                    data.append(contentsOf: buffer.prefix(count))
                }
                var after = stat()
                guard off_t(data.count) == before.st_size, data.count <= maximum, fstat(fd, &after) == 0,
                      before.st_dev == after.st_dev, before.st_ino == after.st_ino,
                      before.st_mode == after.st_mode, before.st_uid == after.st_uid,
                      before.st_gid == after.st_gid, before.st_nlink == after.st_nlink,
                      before.st_size == after.st_size,
                      before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
                      before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw Failure.configuration }
                return data
            }
            close(directory); directory = fd
        }
        throw Failure.configuration
    }

    /// Resolve the selected socket directory only through held no-follow FDs.
    /// All ancestors stay root-owned; the console child retains the established
    /// UID/current-console/group8703/02710 policy checked by the caller.
    static func intentDirectoryIsProtected(_ target: Target, uid: uid_t) -> Bool {
        let components = (target.intentParent + "/\(uid)").split(separator: "/").map(String.init)
        var directory = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return false }
        defer { close(directory) }
        for (index, component) in components.enumerated() {
            var parent = stat()
            guard fstat(directory, &parent) == 0, parent.st_mode & S_IFMT == S_IFDIR,
                  parent.st_uid == 0, parent.st_mode & 0o022 == 0 else { return false }
            let fd = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { return false }
            close(directory); directory = fd
            if index + 2 == components.count {
                var intent = stat()
                guard fstat(directory, &intent) == 0, intent.st_uid == 0,
                      intent.st_gid == 0, intent.st_mode & 0o7777 == 0o755 else { return false }
            }
        }
        var child = stat()
        return fstat(directory, &child) == 0 && child.st_mode & S_IFMT == S_IFDIR
            && child.st_uid == uid && child.st_gid == 8703 && child.st_mode & 0o7777 == 0o2710
    }

    static func selectedCustodyPins(_ target: Target) throws -> [String] {
        // Pin admission can run again in an already selected helper. Refuse
        // new peer admission after inhibition as well as at initial startup.
        try assertSelectedActor(target)
        let data = try readProtected(target.pinsFile, maximum: 1_048_576)
        let pins = try decodeCustodyPins(data)
        try assertSelectedActor(target)
        return pins
    }
    private static func decodeCustodyPins(_ data: Data) throws -> [String] {
        guard !data.isEmpty, data.count <= 1_048_576 else { throw Failure.configuration }
        var reader = JSONReader(bytes: Array(data))
        let root = try reader.complete()
        guard case .object(let fields) = root,
              Set(fields.keys) == Set(["v", "pins"]) || Set(fields.keys) == Set(["v", "mode", "pins"]) else { throw Failure.configuration }
        // Existing packaging adds public mode metadata. It may not select or
        // contradict the compiled helper identity mode.
        #if MCPMAC_TEAM_ID_MODE
        let compiledMode = "team-id"
        #else
        let compiledMode = "local-pins"
        #endif
        if let mode = fields["mode"] { guard try text(mode) == compiledMode else { throw Failure.configuration } }
        guard let version = fields["v"], case .atom("1") = version,
              let pinsNode = fields["pins"], case .object(let pins) = pinsNode,
              let custodyNode = pins["com.enterprise.enclave.custody"], case .array(let values) = custodyNode,
              !values.isEmpty else { throw Failure.configuration }
        // Keep other identifiers separate; they cannot authorize custody.
        for node in pins.values {
            guard case .array(let hashes) = node, !hashes.isEmpty else { throw Failure.configuration }
            for hash in hashes {
                let value = try text(hash)
                guard value.utf8.count == 40, value.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else { throw Failure.configuration }
            }
        }
        return try values.map { try text($0).lowercased() }
    }

    private static func select(arguments: [String]) throws -> Target? {
        #if MCPMAC_NATIVE_TESTING
        let targetOptions = arguments.dropFirst().filter { $0 != "--deployment-target-self-test" }
        #else
        let targetOptions = arguments.dropFirst()
        #endif
        guard !targetOptions.contains(where: { $0.hasPrefix("--deployment-target") && $0 != "--deployment-target" }) else { throw Failure.configuration }
        let positions = arguments.indices.filter { arguments[$0] == "--deployment-target" }
        guard !positions.isEmpty else { return nil }
        guard positions.count == 1 else { throw Failure.configuration }
        #if MCPMAC_NATIVE_TESTING
        // A test helper cannot activate a production deployment, even if no
        // test flag was supplied. It has separate native-only bypasses.
        throw Failure.configuration
        #else
        guard getuid() >= 500, getuid() != UInt32.max else { throw Failure.configuration }
        let position = positions[0]
        guard position + 1 < arguments.count else { throw Failure.configuration }
        let path = try normalizedPath(arguments[position + 1])
        let target = try decode(readProtected(path, maximum: 65536), configPath: path)
        #if MCPMAC_TEAM_ID_MODE
        guard target.signingMode == "team-id" else { throw Failure.configuration }
        #else
        guard target.signingMode == "local-pins" else { throw Failure.configuration }
        #endif
        // An explicit selected target has no fallback if inhibition or its
        // protected support parent cannot be confidently ruled out.
        try DeploymentUpgrade.assertStartAllowed(supportRoot: target.supportRoot)
        try validateArguments(arguments, target: target, uid: getuid())
        return target
        #endif
    }

    private static func validateArguments(_ arguments: [String], target: Target, uid: uid_t) throws {
        var seen: Set<String> = [], index = 1
        while index < arguments.count {
            let flag = arguments[index]
            guard seen.insert(flag).inserted else { throw Failure.configuration }
            switch flag {
            case "--deployment-target", "--socket", "--supervisor-socket":
                guard index + 1 < arguments.count else { throw Failure.configuration }
                let value = try normalizedPath(arguments[index + 1])
                if flag == "--deployment-target" && value != target.configPath { throw Failure.configuration }
                if flag == "--socket" {
                    guard value == target.intentSocket(uid: uid) || value == target.intentParent + "/intent.sock" else { throw Failure.configuration }
                }
                if flag == "--supervisor-socket" && value != target.supervisorSocket { throw Failure.configuration }
                index += 2
            case "--idle-exit": index += 1
            default: throw Failure.configuration
            }
        }
        guard seen.contains("--deployment-target") else { throw Failure.configuration }
    }

    #if MCPMAC_NATIVE_TESTING
    /// Pure synthetic parser/routing fixtures. No file/socket/GUI/hardware action.
    static func selfTest() throws {
        guard case .none = try select(arguments: ["helper", "--native-test", "--deployment-target-self-test"]) else { preconditionFailure("pure fixture selected deployment") }
        for spelling in ["--deployment-target=/fixture/target.json", "--deployment-target-self-test=spoof", "--deployment-target-self-test-spoof"] {
            do { _ = try select(arguments: ["helper", "--native-test", spelling]); preconditionFailure("spoofed deployment option admitted") } catch {}
        }
        do { _ = try select(arguments: ["helper", "--deployment-target", "/fixture/target.json"]); preconditionFailure("test helper selected production deployment") } catch {}
        let layout: [String: String] = ["binary_dir":"/fixture/bin", "custody_bundle":"/fixture/custody.app", "sandbox_dir":"/fixture/sandbox", "socket_root":"/fixture/run", "state_root":"/fixture/state", "audit_root":"/fixture/log", "cas_store_root":"/fixture/cas", "staging_root":"/fixture/staging", "support_root":"/fixture/support", "launchd_namespace":"com.example.fixture", "mach_service":"com.example.fixture.exception"]
        let base: [String: Any] = ["version":1, "target_id":"fixture", "role":"dedicated-test", "profile":"L2", "authority_config":"/fixture-config/authority.json", "expected_artifacts_manifest":"/fixture-config/artifacts.json", "codesign_pins_file":"/fixture-config/pins.json", "signing_identity_mode":"local-pins", "layout":layout, "broker":NSNull(), "shared_read_only_inputs":[]]
        let data = try JSONSerialization.data(withJSONObject: base, options: [.sortedKeys])
        let target = try decode(data, configPath: "/fixture-config/target.json")
        precondition(target.descriptorBytes == data)
        let respelled = data + Data("\n".utf8)
        let respelledTarget = try decode(respelled, configPath: "/fixture-config/target.json")
        precondition(respelledTarget.descriptorBytes == respelled && respelledTarget.descriptorBytes != target.descriptorBytes)
        precondition(target.intentSocket(uid: 501) == "/fixture/run/intent/501/intent.sock")
        precondition(target.supervisorSocket == "/fixture/run/supervisor/supervisor.sock")
        precondition(target.pinsFile == "/fixture-config/pins.json")
        precondition(target.supportRoot == "/fixture/support")
        // Both selected roles retain only their decoded support route. These
        // parser cases do not invoke or bypass the actual filesystem gate.
        for role in ["dedicated-test", "existing-upgrade"] {
            for profile in ["L2", "L3"] {
                var selected = base; selected["role"] = role; selected["profile"] = profile
                if profile == "L3" {
                    selected["broker"] = ["base_dir":"/fixture/state/apfs-broker", "tuf_root_file":"/fixture-config/tuf.json"]
                }
                let decoded = try decode(JSONSerialization.data(withJSONObject: selected), configPath: "/fixture-config/target.json")
                precondition(decoded.supportRoot == "/fixture/support")
            }
        }
        var aliasSupport = layout; aliasSupport["support_root"] = "/var/lib/mcpmac-selected-support"
        var aliasSelected = base; aliasSelected["layout"] = aliasSupport
        let aliasTarget = try decode(JSONSerialization.data(withJSONObject: aliasSelected), configPath: "/fixture-config/target.json")
        precondition(aliasTarget.supportRoot == "/private/var/lib/mcpmac-selected-support")
        func refuses(_ value: Data) {
            do { _ = try decode(value, configPath: "/fixture-config/target.json"); preconditionFailure("invalid descriptor admitted") } catch {}
        }
        var missing = base; missing.removeValue(forKey: "broker"); refuses(try JSONSerialization.data(withJSONObject: missing))
        var unknown = base; unknown["fallback_pins"] = "/global/pins"; refuses(try JSONSerialization.data(withJSONObject: unknown))
        var wrong = base; wrong["profile"] = "L1"; refuses(try JSONSerialization.data(withJSONObject: wrong))
        var shared = base; shared["shared_read_only_inputs"] = ["/fixture-config/pins.json"]; refuses(try JSONSerialization.data(withJSONObject: shared))
        for alias in ["/fixture-config/authority.json", "/fixture-config/authority.json/child"] {
            var aliased = base; aliased["expected_artifacts_manifest"] = alias; refuses(try JSONSerialization.data(withJSONObject: aliased))
        }
        var nested = layout; nested["custody_bundle"] = "/fixture/support/Custody.app"
        var supported = base; supported["layout"] = nested
        _ = try decode(JSONSerialization.data(withJSONObject: supported), configPath: "/fixture/support/target.json")
        var l3 = base; l3["profile"] = "L3"; l3["broker"] = ["base_dir":"/fixture/state/apfs-broker", "tuf_root_file":"/fixture-config/tuf.json"]
        _ = try decode(JSONSerialization.data(withJSONObject: l3), configPath: "/fixture-config/target.json")
        l3["broker"] = ["base_dir":"/other/broker", "tuf_root_file":"/fixture-config/tuf.json"]; refuses(try JSONSerialization.data(withJSONObject: l3))
        var equalSupport = layout; equalSupport["custody_bundle"] = "/fixture/support"
        var equalBundle = base; equalBundle["layout"] = equalSupport; refuses(try JSONSerialization.data(withJSONObject: equalBundle))
        var collision = layout; collision["audit_root"] = "/fixture/state/log"
        var badLayout = base; badLayout["layout"] = collision; refuses(try JSONSerialization.data(withJSONObject: badLayout))
        collision = layout; collision["support_root"] = "/Library/Application Support/EnterpriseEnclave"; badLayout["layout"] = collision; refuses(try JSONSerialization.data(withJSONObject: badLayout))
        for installed in ["/OPT/ENTERPRISE/ENCLAVE", "/opt/Enterprise/enclave/child"] {
            collision = layout; collision["binary_dir"] = installed; badLayout["layout"] = collision
            refuses(try JSONSerialization.data(withJSONObject: badLayout))
        }
        collision = layout; collision["audit_root"] = "/FIXTURE/STATE/log"; badLayout["layout"] = collision
        refuses(try JSONSerialization.data(withJSONObject: badLayout))
        collision = layout; collision["custody_bundle"] = "/FIXTURE/SUPPORT"; badLayout["layout"] = collision
        refuses(try JSONSerialization.data(withJSONObject: badLayout))
        var aliasedPins = base; aliasedPins["codesign_pins_file"] = "/FIXTURE-CONFIG/AUTHORITY.JSON"
        refuses(try JSONSerialization.data(withJSONObject: aliasedPins))
        let args = ["helper", "--deployment-target", target.configPath]
        try validateArguments(args, target: target, uid: 501)
        try validateArguments(args + ["--socket", target.intentParent + "/intent.sock", "--supervisor-socket", target.supervisorSocket], target: target, uid: 501)
        for suffix in [["--socket", "/other/intent/501/intent.sock"], ["--supervisor-socket", "/other/supervisor/supervisor.sock"], ["--socket", target.intentSocket(uid: 502)], ["--native-test"], ["--test-occlusion"], ["--dev"], ["--unknown"], ["--idle-exit", "--idle-exit"], ["--deployment-target", target.configPath], ["--socket"]] {
            do { try validateArguments(args + suffix, target: target, uid: 501); preconditionFailure("unsafe arguments admitted") } catch {}
        }
        let custodyID = "com.enterprise.enclave.custody", otherID = "com.enterprise.enclave.other"
        let hashA = String(repeating: "a", count: 40), hashB = String(repeating: "b", count: 40)
        let pinsA = try JSONSerialization.data(withJSONObject: ["v":1, "pins":[custodyID:[hashA], otherID:[hashB]]])
        let pinsB = try JSONSerialization.data(withJSONObject: ["v":1, "pins":[custodyID:[hashB]]])
        let decodedA = try decodeCustodyPins(pinsA), decodedB = try decodeCustodyPins(pinsB)
        precondition(decodedA == [hashA] && decodedB == [hashB])
        #if MCPMAC_TEAM_ID_MODE
        let currentMode = "team-id", wrongMode = "local-pins"
        #else
        let currentMode = "local-pins", wrongMode = "team-id"
        #endif
        let packaged = try JSONSerialization.data(withJSONObject: ["v":1, "mode":currentMode, "pins":[custodyID:[hashA]]])
        let decodedPackaged = try decodeCustodyPins(packaged)
        precondition(decodedPackaged == [hashA])
        let wrongPackaged = try JSONSerialization.data(withJSONObject: ["v":1, "mode":wrongMode, "pins":[custodyID:[hashA]]])
        do { _ = try decodeCustodyPins(wrongPackaged); preconditionFailure("wrong packaged mode admitted") } catch {}
        for badPins in [Data("{\"v\":1,\"v\":1,\"pins\":{}}".utf8), try JSONSerialization.data(withJSONObject: ["v":1, "pins":[otherID:[hashA]]]), try JSONSerialization.data(withJSONObject: ["v":1, "pins":[custodyID:["bad"]]])] {
            do { _ = try decodeCustodyPins(badPins); preconditionFailure("unsafe pins admitted") } catch {}
        }
        let raw = String(data: data, encoding: .utf8)!
        refuses(Data(raw.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1").utf8))
        refuses(Data(raw.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"\\u0076ersion\":1").utf8))
        for path in ["relative", "/a/../b", "/a/./b", "/a//b", "/a/b/", "/a/$(b)", "/a/\nb",
                     "/VAR/run/fixture", "/Tmp/fixture", "/ETC/fixture", "/PRIVATE/var/fixture",
                     "/private/VAR/fixture", "/private/Tmp/fixture", "/private/ETC/fixture",
                     "/fixture/\u{00e9}", "/fixture/e\u{0301}"] {
            do { _ = try normalizedPath(path); preconditionFailure("unsafe path admitted") } catch {}
        }
        let normalized = try normalizedPath("/var/run/fixture")
        precondition(normalized == "/private/var/run/fixture")
        let preservedCase = try normalizedPath("/Fixture/CasePreserved")
        precondition(preservedCase == "/Fixture/CasePreserved")
        precondition(overlaps("/fixture/A", "/FIXTURE/a/child"))
        print("deployment target synthetic parser/routing fixtures PASS; no installed paths or hardware")
    }
    #endif
}
