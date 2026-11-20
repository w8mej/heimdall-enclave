#if depot_OIDC_NATIVE_TESTING
import Foundation

/// Pure synthetic values only. No filesystem, native session/code observation,
/// sockets, NSApplication, browser, network, credential or issuer operation.
enum OIDCDeploymentTargetSelfTest {
    static func run() throws {
        func check(_ condition: @autoclosure () -> Bool) throws { try BrokerProtocolSelfTest.check(condition()) }
        func refuses(_ operation: () throws -> Void) throws { try BrokerProtocolSelfTest.refuses(operation) }
        let layout: [String: String] = ["binary_dir":"/fixture/bin", "custody_bundle":"/fixture/support/Custody.app",
            "sandbox_dir":"/fixture/sandbox", "socket_root":"/var/run/selected-oidc-fixture", "state_root":"/fixture/state",
            "audit_root":"/fixture/log", "cas_store_root":"/fixture/cas", "staging_root":"/fixture/stage",
            "support_root":"/fixture/support", "launchd_namespace":"com.example.fixture", "mach_service":"com.example.fixture.exception"]
        var base: [String: Any] = ["version":1, "target_id":"fixture", "role":"dedicated-test", "profile":"L2",
            "authority_config":"/fixture/support/authority.json", "expected_artifacts_manifest":"/fixture/support/artifacts.json",
            "codesign_pins_file":"/fixture-pins/selected-pins.json", "signing_identity_mode":OIDCDeploymentTargetContext.compiledSigningMode,
            "layout":layout, "broker":NSNull(), "shared_read_only_inputs":[]]
        let config = "/fixture/support/target.json"
        func bytes(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) }
        let original = try bytes(base)
        let target = try OIDCDeploymentTargetContext.decode(original, configPath: config)
        try check(target.socketRoot == "/var/run/selected-oidc-fixture")
        try check(target.brokerSocket(uid: 501) == "/var/run/selected-oidc-fixture/oidc/501/broker.sock")
        try check(target.identityPath == "/fixture/support/oidc-broker-identity.json")
        try check(target.oauthPath == "/fixture/support/oidc-oauth.json")
        try check(target.pinsFile == "/fixture-pins/selected-pins.json")
        let arguments = ["broker", "--identity-config", target.identityPath, "--oauth-config", target.oauthPath, "--deployment-target", config]
        let options = try BrokerArguments.parse(arguments)
        try OIDCDeploymentTargetContext.validateArguments(options, target: target)
        let legacy = try BrokerArguments.parse(Array(arguments.prefix(5)))
        try check(legacy.deploymentPath == nil)
        let noSelection = try OIDCDeploymentTargetContext.testSelection(Array(arguments.prefix(5)))
        try check(noSelection == nil)
        // Test-compiled binary refuses a production descriptor before any read.
        try refuses { _ = try OIDCDeploymentTargetContext.testSelection(arguments) }
        for index in [2, 4, 6] {
            var wrong = arguments; wrong[index] = "/other/target/file"
            try refuses { try OIDCDeploymentTargetContext.validateArguments(BrokerArguments.parse(wrong), target: target) }
        }
        for wrong in [arguments + ["--deployment-target", config], arguments + ["--socket", "/other/socket"],
                      Array(arguments.dropLast()), ["broker", "--deployment-target=" + config],
                      ["broker", "--oauth-config", target.oauthPath, "--identity-config", target.identityPath],
                      Array(arguments.prefix(5)) + ["--deployment-target-self-test", config],
                      Array(arguments.prefix(5)) + ["--deployment-target=" + config, config]] {
            try refuses { _ = try BrokerArguments.parse(wrong) }
        }
        try OIDCDeploymentTargetContext.validateDescriptorBytes(original, target: target)
        try refuses { try OIDCDeploymentTargetContext.validateDescriptorBytes(original + Data([10]), target: target) }
        try refuses { try OIDCDeploymentTargetContext.validateDescriptorBytes(try JSONSerialization.data(withJSONObject: base, options: [.prettyPrinted]), target: target) }
        for role in ["dedicated-test", "existing-upgrade"] {
            for profile in ["L2", "L3"] {
                var value = base; value["role"] = role; value["profile"] = profile
                if profile == "L3" { value["broker"] = ["base_dir":"/fixture/state/apfs-broker", "tuf_root_file":"/fixture/support/tuf-root.json"] }
                let decoded = try OIDCDeploymentTargetContext.decode(bytes(value), configPath: config)
                try OIDCDeploymentTargetContext.validateArguments(options, target: decoded)
            }
        }
        func refusesDescriptor(_ value: [String: Any]) throws {
            try refuses { _ = try OIDCDeploymentTargetContext.decode(bytes(value), configPath: config) }
        }
        for key in ["broker", "authority_config", "layout", "shared_read_only_inputs"] {
            var value = base; value.removeValue(forKey: key); try refusesDescriptor(value)
        }
        for (key, value) in [("version", true as Any), ("profile", "L1" as Any),
                             ("role", "other" as Any), ("unexpected_socket", "/other" as Any)] {
            var changed = base; changed[key] = value
            try refusesDescriptor(changed)
        }
        var wrongMode = base; wrongMode["signing_identity_mode"] = OIDCDeploymentTargetContext.compiledSigningMode == "local-pins" ? "team-id" : "local-pins"
        let mismatched = try OIDCDeploymentTargetContext.decode(bytes(wrongMode), configPath: config)
        try refuses { try OIDCDeploymentTargetContext.validateArguments(options, target: mismatched) }
        var nested = layout; nested["audit_root"] = "/FIXTURE/STATE/log"
        var changed = base; changed["layout"] = nested; try refusesDescriptor(changed)
        nested = layout; nested["binary_dir"] = "/OPT/ENTERPRISE/ENCLAVE"; changed["layout"] = nested; try refusesDescriptor(changed)
        nested = layout; nested["custody_bundle"] = "/FIXTURE/SUPPORT"; changed["layout"] = nested; try refusesDescriptor(changed)
        changed = base; changed["codesign_pins_file"] = "/FIXTURE/SUPPORT/AUTHORITY.JSON"; try refusesDescriptor(changed)
        changed = base; changed["shared_read_only_inputs"] = [target.pinsFile]; try refusesDescriptor(changed)
        changed = base; changed["profile"] = "L3"; changed["broker"] = NSNull(); try refusesDescriptor(changed)
        let raw = String(data: original, encoding: .utf8)!
        for atom in ["\"version\":1,\"version\":1", "\"version\":1,\"\\u0076ersion\":1", "\"version\":1.0"] {
            try refuses { _ = try OIDCDeploymentTargetContext.decode(Data(raw.replacingOccurrences(of: "\"version\":1", with: atom).utf8), configPath: config) }
        }
        for path in ["relative", "/a/../b", "/a/./b", "/a//b", "/a/b/", "/a/$(b)", "/a/\nb", "/fixture/é",
                     "/VAR/run/fixture", "/Tmp/fixture", "/private/VAR/fixture", "/PRIVATE/var/fixture"] {
            try refuses { _ = try OIDCDeploymentTargetContext.normalizedPath(path) }
        }
        let normalized = try OIDCDeploymentTargetContext.normalizedPath(target.socketRoot)
        try check(normalized == "/private/var/run/selected-oidc-fixture")
        try check(target.socketRoot != normalized)
        let custody = "com.enterprise.enclave.custody", oidc = "com.enterprise.enclave.oidc-broker"
        let hashA = String(repeating: "a", count: 40), hashB = String(repeating: "b", count: 40)
        func pinBytes(_ fields: [String: Any]) throws -> Data { try bytes(fields) }
        let pins = try OIDCDeploymentTargetContext.decodePins(pinBytes(["v":1, "mode":OIDCDeploymentTargetContext.compiledSigningMode, "pins":[custody:[hashA], oidc:[hashB]]]))
        try check(pins[custody] == [hashA] && pins[oidc] == [hashB])
        let invalidPins: [[String: Any]] = [["v":1, "pins":[custody:[hashA]]], ["v":1, "pins":[oidc:[hashA]]],
                                   ["v":1, "pins":[custody:["bad"], oidc:[hashB]]],
                                   ["v":1, "mode":wrongMode["signing_identity_mode"]!, "pins":[custody:[hashA], oidc:[hashB]]],
                                   ["v":true, "pins":[custody:[hashA], oidc:[hashB]]]]
        for value in invalidPins {
            try refuses { _ = try OIDCDeploymentTargetContext.decodePins(pinBytes(value)) }
        }
        try refuses { _ = try OIDCDeploymentTargetContext.decodePins(Data("{\"v\":1,\"v\":1,\"pins\":{}}".utf8)) }
        let identity = BrokerIdentityConfig(v: 1, socket: target.brokerSocket(uid: 501), identifier: oidc,
            console_uid: 501, audit_session_id: 42, expires_unix: 2_000_000_000)
        try check(identity.matchesRoute(target.brokerSocket(uid: 501), uid: 501))
        try check(!identity.matchesRoute("/var/run/enclave/oidc/501/broker.sock", uid: 501))
        try check(!identity.matchesRoute(target.brokerSocket(uid: 502), uid: 502))
        try check(!identity.matchesRoute("/other/oidc/501/broker.sock", uid: 501))
        #if depot_TEAM_ID_MODE
        try check(PeerIdentity.signingModeMatches(team: "SYNTHETIC") && !PeerIdentity.signingModeMatches(team: ""))
        #else
        try check(PeerIdentity.signingModeMatches(team: "") && !PeerIdentity.signingModeMatches(team: "SYNTHETIC"))
        #endif
        base.removeAll()
        print("OIDC selected deployment pure fixtures PASS: L2/L3 both roles, closed argv/schema, raw descriptor binding, exact UID socket/config/pins and compiled mode; no filesystem, code/session observation, browser, IdP or hardware")
    }
}
#endif
