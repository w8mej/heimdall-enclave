// Standalone UI/SEP diagnostic. No socket, deployment startup or custody API.
// This file is linked with exact production helper sources, without test defines.
import AppKit
import Darwin
import Foundation
import Security

func clockNs() -> UInt64? {
    var value = timespec()
    guard clock_gettime(CLOCK_MONOTONIC, &value) == 0, value.tv_sec >= 0,
          value.tv_nsec >= 0, value.tv_nsec < 1_000_000_000 else { return nil }
    let (seconds, overflow) = UInt64(value.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
    let (result, additionOverflow) = seconds.addingReportingOverflow(UInt64(value.tv_nsec))
    return overflow || additionOverflow || result == 0 || result == UInt64.max ? nil : result
}
func emit(_ status: String, code: Int32, fields: [String: Any] = [:]) -> Never {
    var report = fields
    report["schema"] = 1
    report["kind"] = "mcpmac-standalone-helper-touchid-diagnostic"
    report["status"] = status
    report["integrated_d2_qualified"] = false
    report["physical_yubikey_observed"] = false
    report["persistent_keychain_item_requested"] = false
    report["custody_socket_or_service_used"] = false
    if let data = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    }
    exit(code)
}
func verifies(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
    guard publicKey.count == 65, publicKey.first == 4,
          !signature.isEmpty, signature.count <= 80 else { return false }
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits: 256
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(Data(publicKey) as CFData, attributes as CFDictionary, &error),
          SecKeyIsAlgorithmSupported(key, .verify, .ecdsaSignatureMessageX962SHA256) else { return false }
    return SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256,
        Data(message) as CFData, Data(signature) as CFData, &error)
}
func bytes(_ text: String) -> [UInt8] {
    var output = [UInt8]()
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else { return [] }
        output.append(byte); index = next
    }
    return output
}
func signatureSelfTest() -> Never {
    // Public RFC6979 P-256/SHA-256 "sample" vector; no private key or signing.
    let key = bytes("0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
    let signature = bytes("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
    let message = Array("sample".utf8)
    var changed = signature; changed[changed.count - 1] ^= 1
    let positive = verifies(publicKey: key, message: message, signature: signature)
    let negatives = !verifies(publicKey: key, message: Array("changed".utf8), signature: signature)
        && !verifies(publicKey: key, message: message, signature: changed)
        && !verifies(publicKey: [], message: message, signature: signature)
        && !verifies(publicKey: key, message: message, signature: [])
    emit(positive && negatives ? "SOFTWARE_PUBLIC_SIGNATURE_FIXTURES_PASS" : "SOFTWARE_PUBLIC_SIGNATURE_FIXTURES_FAIL",
        code: positive && negatives ? 0 : 1,
        fields: ["biometric_attempted": false, "positive_controls": positive,
                 "negative_controls": negatives, "secret_key_created": false])
}
final class DiagnosticDelegate: NSObject, NSApplicationDelegate {
    private var sheet: IntentSheet?
    private var lockObserver: NSObjectProtocol?
    private var sessionObserver: NSObjectProtocol?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        guard PeerIdentity.isCurrentConsole(), getuid() == geteuid(), getuid() >= 500,
              DeploymentTargetContext.selected == nil else {
            emit("CURRENT_CONSOLE_REQUIRED", code: 2, fields: ["biometric_attempted": false])
        }
        var coreLimit = rlimit(rlim_cur: 0, rlim_max: 0)
        guard setrlimit(RLIMIT_CORE, &coreLimit) == 0 else {
            emit("CORE_DUMP_SUPPRESSION_REQUIRED", code: 2, fields: ["biometric_attempted": false])
        }
        var digest = [UInt8](repeating: 0, count: 32)
        var nonce = [UInt8](repeating: 0, count: 32)
        let digestRandom = digest.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        let nonceRandom = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard digestRandom == errSecSuccess, nonceRandom == errSecSuccess, let start = clockNs(),
              start < UInt64.max - 10_000_000_000 else {
            emit("FRESH_CHALLENGE_UNAVAILABLE", code: 2, fields: ["biometric_attempted": false])
        }
        let prompt = BiometricPrompt(localizedReason: "Test Touch ID for MCPMac. This authorizes this test only.",
            dJcs: digest, nonce: nonce, tStartNs: start, bioKeyBlob: [])
        let current = IntentSheet(prompt: prompt)
        sheet = current
        lockObserver = DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in self?.sheet?.cancelForSessionChange() }
        sessionObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.sheet?.cancelForSessionChange() }
        current.present { [weak self] outcome in
            if let token = self?.lockObserver { DistributedNotificationCenter.default().removeObserver(token) }
            if let token = self?.sessionObserver { NSWorkspace.shared.notificationCenter.removeObserver(token) }
            self?.sheet = nil
            switch outcome {
            case .approved(let signature, let visible, let approved, let publicKey, let wrappedBlob):
                // The exact production source requested a nonpermanent SEP key
                // carrying .privateKeyUsage|.biometryCurrentSet. No fallback is
                // supplied here. Verify its signed fresh prompt independently.
                guard let publicKey, let wrappedBlob, !wrappedBlob.isEmpty,
                      verifies(publicKey: publicKey, message: prompt.signedMessage(), signature: signature),
                      let finished = clockNs(), PeerIdentity.isCurrentConsole(),
                      visible >= start, visible <= approved, approved - visible >= 500_000_000,
                      approved < start + 10_000_000_000, finished < start + 10_000_000_000 else {
                    emit("BIO_OR_SIGNATURE_OR_ORIGINAL_CAP_REFUSED", code: 1,
                         fields: ["biometric_attempted": true])
                }
                // Neither the wrapped blob, public key, signature nor context
                // leaves this process. Swift memory erasure is not established.
                emit("FRESH_BIOMETRIC_AND_SEP_SIGNATURE_VERIFIED", code: 0,
                    fields: ["biometric_attempted": true, "sep_signature_verified": true,
                        "fresh_prompt_verified": true, "production_intent_sheet_used": true,
                        "start_boot_ns": start, "visible_boot_ns": visible,
                        "approved_boot_ns": approved, "finished_boot_ns": finished])
            case .cancelled: emit("CANCELLED", code: 3, fields: ["biometric_attempted": NSNull()])
            case .timedOut: emit("TIMED_OUT", code: 4, fields: ["biometric_attempted": NSNull()])
            case .occluded: emit("OCCLUDED", code: 5, fields: ["biometric_attempted": NSNull()])
            case .reportSuspicious: emit("REPORTED_SUSPICIOUS", code: 6, fields: ["biometric_attempted": NSNull()])
            }
        }
    }
}
// Explicit modes: compilation/signing and public-vector checking never prompt.
guard CommandLine.arguments.count == 2 else { emit("EXPLICIT_MODE_REQUIRED", code: 2) }
switch CommandLine.arguments[1] {
case "--signature-self-test": signatureSelfTest()
case "--touch":
    let app = NSApplication.shared
    let delegate = DiagnosticDelegate()
    app.delegate = delegate
    app.run()
    emit("APP_RETURNED_WITHOUT_OUTCOME", code: 1)
default: emit("UNKNOWN_MODE", code: 2)
}
