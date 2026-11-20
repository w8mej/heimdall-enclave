import AppKit
import Foundation
import LocalAuthentication
import Security

/// Visual intent sheet with anti-occlusion and 500 ms dwell gate (FS-703 §5.1, GAP-14).
public final class IntentSheet: NSWindowController {

    private let prompt: BiometricPrompt
    private let testOcclusion: Bool
    private var completion: ((BiometricOutcome) -> Void)?
    private var occlusionTimer: Timer?
    private var visibleAtNs: UInt64 = 0
    private var testOverlayWindow: NSWindow?
    private var activeContext: LAContext?
    private var ceremonyDeadline: UInt64 = 0

    public init(prompt: BiometricPrompt, testOcclusion: Bool = false) {
        self.prompt = prompt
        self.testOcclusion = testOcclusion

        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 260),
            styleMask: [.titled, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        // FS-703 §5.1: sharingType = .none prevents ScreenCaptureKit and other processes from viewing
        panel.sharingType = .none
        panel.level = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.modalPanelWindow)))
        panel.isFloatingPanel = true
        panel.title = "Enclave Security Intent"
        panel.center()

        super.init(window: panel)
        setupUI()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupUI() {
        guard let panel = window as? NSPanel else { return }
        let contentView = NSView(frame: panel.contentView?.bounds ?? NSRect(x: 0, y: 0, width: 480, height: 260))

        // Title icon / label
        let titleLabel = NSTextField(labelWithString: "Enclave Security Authorization")
        titleLabel.font = NSFont.boldSystemFont(ofSize: 15)
        titleLabel.frame = NSRect(x: 24, y: 210, width: 432, height: 24)
        contentView.addSubview(titleLabel)

        // Summary & SAS words inside scroll view (GAP-14)
        let scrollView = NSScrollView(frame: NSRect(x: 24, y: 70, width: 432, height: 130))
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.autohidesScrollers = true
        scrollView.borderType = .bezelBorder

        let reasonBox = NSTextView(frame: scrollView.contentView.bounds)
        reasonBox.isEditable = false
        reasonBox.isSelectable = true
        reasonBox.backgroundColor = NSColor.windowBackgroundColor.withAlphaComponent(0.5)
        reasonBox.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        reasonBox.string = prompt.localizedReason
        reasonBox.isVerticallyResizable = true
        reasonBox.autoresizingMask = [.width]
        scrollView.documentView = reasonBox
        contentView.addSubview(scrollView)

        // "Report Suspicious Prompt" button (FS-703 §5.1)
        let reportBtn = NSButton(frame: NSRect(x: 24, y: 24, width: 200, height: 32))
        reportBtn.title = "Report Suspicious Prompt"
        reportBtn.bezelStyle = .rounded
        reportBtn.target = self
        reportBtn.action = #selector(onReportSuspicious)
        contentView.addSubview(reportBtn)

        // "Cancel" button
        let cancelBtn = NSButton(frame: NSRect(x: 360, y: 24, width: 96, height: 32))
        cancelBtn.title = "Cancel"
        cancelBtn.bezelStyle = .rounded
        cancelBtn.keyEquivalent = "\u{1b}" // ESC
        cancelBtn.target = self
        cancelBtn.action = #selector(onCancel)
        contentView.addSubview(cancelBtn)

        panel.contentView = contentView
    }

    /// Continuous monotonic clock matching `enclave_core::clock::boot_clock_ns()` (CLOCK_MONOTONIC).
    private func bootClockNs() -> UInt64 {
        var ts = timespec()
        clock_gettime(CLOCK_MONOTONIC, &ts)
        return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
    }

    /// Present the sheet, run the occlusion loop and dwell gate, evaluate Touch ID, and invoke completion.
    public func present(completion: @escaping (BiometricOutcome) -> Void) {
        self.completion = completion
        guard let panel = window else {
            completion(.timedOut)
            return
        }

        panel.orderFrontRegardless()
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        let now = bootClockNs()
        let (deadline, overflow) = prompt.tStartNs.addingReportingOverflow(10_000_000_000)
        guard prompt.dJcs.count == 32, prompt.nonce.count == 32,
              !overflow, prompt.tStartNs <= now, now < deadline else {
            self.finish(with: .timedOut)
            return
        }
        self.ceremonyDeadline = deadline
        self.visibleAtNs = max(now, prompt.tStartNs + 1_000)

        if testOcclusion {
            // Spawn test overlay window to simulate occlusion
            let overlay = NSWindow(
                contentRect: NSRect(x: panel.frame.origin.x + 20, y: panel.frame.origin.y + 20, width: 200, height: 100),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            overlay.level = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.screenSaverWindow)))
            overlay.backgroundColor = NSColor.red.withAlphaComponent(0.8)
            overlay.orderFrontRegardless()
            self.testOverlayWindow = overlay

            // Test occlusion must trigger immediate occlusion abort (GAP-14)
            self.finish(with: .occluded)
            return
        }

        let testWinNum = testOverlayWindow?.windowNumber

        // 60 Hz (16.6 ms) occlusion loop across common runloop modes
        let timer = Timer(timeInterval: 0.016, repeats: true) { [weak self] t in
            guard let self = self, let win = self.window else {
                t.invalidate()
                return
            }
            if self.bootClockNs() >= self.ceremonyDeadline {
                self.finish(with: .timedOut)
                return
            }
            #if !MCPMAC_NATIVE_TESTING
            if !PeerIdentity.isCurrentConsole() {
                self.finish(with: .cancelled)
                return
            }
            #endif
            if OcclusionDetector.isOccluded(sheetWindowNumber: win.windowNumber, sheetFrame: win.frame, simulatedTestWindowNumber: testWinNum) {
                t.invalidate()
                self.finish(with: .occluded)
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.occlusionTimer = timer

        // 500 ms Dwell Gate: LAContext only arms after 500 ms unoccluded dwell (FS-703 §5.1.3)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.505) { [weak self] in
            guard let self = self, self.occlusionTimer?.isValid == true else { return }
            self.armTouchID()
        }
    }

    private func armTouchID() {
        let context = LAContext()
        activeContext = context
        context.touchIDAuthenticationAllowableReuseDuration = 0

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: prompt.localizedReason
        ) { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self = self, self.completion != nil else { return }
                guard self.bootClockNs() < self.ceremonyDeadline else {
                    self.finish(with: .timedOut)
                    return
                }

                if success {
                    let approvedAtNs = self.bootClockNs()
                    if self.prompt.bioKeyBlob.isEmpty {
                        if let created = self.createSepBioKeyAndSign(context: context) {
                            self.finish(with: .approved(
                                sepSignature: created.sig,
                                visibleAtNs: self.visibleAtNs,
                                approvedAtNs: approvedAtNs,
                                enrolledPubkey: created.pubkey,
                                enrolledBlob: created.blob
                            ))
                        } else {
                            fputs("enclave-intent: Secure Enclave key creation/signing failed\n", stderr)
                            self.finish(with: .cancelled)
                        }
                    } else if let sig = self.signWithSepKey(context: context) {
                        self.finish(with: .approved(
                            sepSignature: sig,
                            visibleAtNs: self.visibleAtNs,
                            approvedAtNs: approvedAtNs
                        ))
                    } else {
                        fputs("enclave-intent: Secure Enclave signing failed\n", stderr)
                        self.finish(with: .cancelled)
                    }
                } else if let laErr = error as? LAError {
                    switch laErr.code {
                    case .userCancel, .appCancel, .systemCancel:
                        self.finish(with: .cancelled)
                    case .touchIDLockout, .authenticationFailed:
                        self.finish(with: .cancelled)
                    default:
                        self.finish(with: .timedOut)
                    }
                } else {
                    self.finish(with: .cancelled)
                }
            }
        }
    }

    private func createSepBioKeyAndSign(context: LAContext) -> (sig: [UInt8], pubkey: [UInt8], blob: [UInt8])? {
        var aclErr: Unmanaged<CFError>?
        let acl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &aclErr
        )
        guard let acl = acl else { return nil }

        let privAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: false,
            kSecAttrAccessControl as String: acl,
            kSecUseAuthenticationContext as String: context
        ]
        let keyParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privAttrs
        ]

        var keyErr: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(keyParams as CFDictionary, &keyErr) else {
            return nil
        }

        guard let pubKey = SecKeyCopyPublicKey(secKey),
              let pubData = SecKeyCopyExternalRepresentation(pubKey, nil) as Data?,
              let attrs = SecKeyCopyAttributes(secKey) as? [String: Any],
              let toid = attrs["toid"] as? Data else {
            return nil
        }

        let msg = prompt.signedMessage()
        let msgData = Data(msg) as CFData
        var sigErr: Unmanaged<CFError>?
        guard let sigData = SecKeyCreateSignature(
            secKey,
            .ecdsaSignatureMessageX962SHA256,
            msgData,
            &sigErr
        ) as Data? else {
            return nil
        }

        return (sig: [UInt8](sigData), pubkey: [UInt8](pubData), blob: [UInt8](toid))
    }

    private func signWithSepKey(context: LAContext) -> [UInt8]? {
        guard !prompt.bioKeyBlob.isEmpty else { return nil }
        // Re-open the enrolled key by its token object ID ("toid", as custody
        // does for its own SEP keys). SecKeyCreateWithData does not re-open a
        // Secure Enclave object from its toid: it yields an unrelated key, so
        // every signature failed custody's check against the enrolled key.
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false],
            kSecUseAuthenticationContext as String: context,
            "toid": Data(prompt.bioKeyBlob)
        ]
        var cfErr: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr) else {
            return nil
        }
        let msg = prompt.signedMessage()
        let msgData = Data(msg) as CFData
        guard let sigData = SecKeyCreateSignature(
            secKey,
            .ecdsaSignatureMessageX962SHA256,
            msgData,
            &cfErr
        ) as Data? else {
            return nil
        }
        return [UInt8](sigData)
    }

    @objc private func onReportSuspicious() {
        occlusionTimer?.invalidate()
        occlusionTimer = nil
        finish(with: .reportSuspicious)
    }

    @objc private func onCancel() {
        occlusionTimer?.invalidate()
        occlusionTimer = nil
        finish(with: .cancelled)
    }

    /// Lock/logout/session switch invalidates the active proof operation.
    func cancelForSessionChange() {
        finish(with: .cancelled)
    }

    private func finish(with outcome: BiometricOutcome) {
        activeContext?.invalidate()
        activeContext = nil
        occlusionTimer?.invalidate()
        occlusionTimer = nil
        testOverlayWindow?.orderOut(nil)
        testOverlayWindow?.close()
        testOverlayWindow = nil
        window?.orderOut(nil)
        window?.close()
        let cb = completion
        completion = nil
        cb?(outcome)
    }
}
