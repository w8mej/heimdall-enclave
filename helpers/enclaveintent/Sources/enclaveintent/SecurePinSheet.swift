import AppKit
import Darwin
import Foundation

/// One explicitly owned PIN byte allocation. Callers borrow its bytes through
/// appendCBOR; by-value Array aliases never leave this owner and defeat wiping.
final class ExistingPinBytes {
    private var bytes: [UInt8]
    init(utf8: String.UTF8View) { bytes = Array(utf8) }
    var isValid: Bool { bytes.count >= 4 && bytes.count <= 63 && !bytes.contains(0) }
    func appendCBOR(to output: inout [UInt8]) {
        guard isValid else { output.append(0xf6); return }
        // PIN size is bounded to63 bytes; emit the byte-string header directly.
        if bytes.count < 24 { output.append(0x40 | UInt8(bytes.count)) }
        else { output += [0x58, UInt8(bytes.count)] }
        bytes.withUnsafeBytes { output.append(contentsOf: $0) }
    }
    func wipe() { _ = bytes.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
    deinit { wipe() }
}

/// Typed L3-only existing-PIN request from the mutually authenticated custodian.
struct ExistingPinPrompt {
    let nonce: [UInt8]
    let tStartNs: UInt64
    let reason: String
    static func decode(_ bytes: [UInt8]) throws -> ExistingPinPrompt {
        var reader = CBORReader(data: bytes)
        guard case .map(let fields) = try reader.readValue(), fields.count == 4,
              reader.offset == bytes.count else { throw HelperWire.Failure.protocolError }
        var nonce: [UInt8]?; var start: UInt64?; var reason: String?; var seen = Set<String>()
        for (key, value) in fields {
            guard case .textString(let name) = key, seen.insert(name).inserted else { throw HelperWire.Failure.protocolError }
            switch (name, value) {
            case ("pin_protocol", .textString("enclave.pin.v1")): break
            case ("nonce", .byteString(let bytes)) where bytes.count == 32: nonce = bytes
            case ("t_start_ns", .unsigned(let value)): start = value
            case ("reason", .textString(let text)) where !text.isEmpty && text.utf8.count <= 4096: reason = text
            default: throw HelperWire.Failure.protocolError
            }
        }
        guard seen.contains("pin_protocol"), let nonce, let start, let reason else { throw HelperWire.Failure.protocolError }
        return ExistingPinPrompt(nonce: nonce, tStartNs: start, reason: reason)
    }
    func reply(_ pin: ExistingPinBytes?) -> [UInt8] {
        var body: [UInt8] = [0xa3]
        body += CBOREncoder.encodeText("pin_protocol") + CBOREncoder.encodeText("enclave.pin.v1")
        body += CBOREncoder.encodeText("nonce") + CBOREncoder.encodeBytes(nonce)
        body += CBOREncoder.encodeText("pin")
        if let pin { pin.appendCBOR(to: &body) } else { body.append(0xf6) }
        return body
    }
}

/// The PIN remains in the GUI process and the verified UID703 local stream.
/// AppKit owns field/String copies; clearing them is not certified erasure.
final class SecurePinSheet: NSWindowController, NSWindowDelegate {
    private let prompt: ExistingPinPrompt
    private let field = NSSecureTextField(frame: NSRect(x: 24, y: 62, width: 432, height: 28))
    private var completion: ((ExistingPinBytes?) -> Void)?
    private var timer: Timer?
    private var deadline: UInt64 = 0
    private let connection: Int32

    init(prompt: ExistingPinPrompt, connection: Int32) {
        self.prompt = prompt
        self.connection = connection
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 480, height: 220), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init(window: panel)
        panel.delegate = self; panel.title = "L3 YubiKey authorization"
        panel.sharingType = .none; panel.level = .modalPanel; panel.center()
        let label = NSTextField(wrappingLabelWithString: "Enter the existing YubiKey FIDO2 PIN.\n" + prompt.reason)
        label.frame = NSRect(x: 24, y: 102, width: 432, height: 96)
        panel.contentView?.addSubview(label)
        field.placeholderString = "Existing FIDO2 PIN"; field.target = self; field.action = #selector(submit)
        panel.contentView?.addSubview(field)
        let approve = NSButton(title: "Continue", target: self, action: #selector(submit))
        approve.frame = NSRect(x: 352, y: 18, width: 104, height: 30); approve.keyEquivalent = "\r"
        panel.contentView?.addSubview(approve)
        let cancelButton = NSButton(title: "Cancel", target: self, action: #selector(cancel))
        cancelButton.frame = NSRect(x: 240, y: 18, width: 104, height: 30); cancelButton.keyEquivalent = "\u{1b}"
        panel.contentView?.addSubview(cancelButton)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func present(completion: @escaping (ExistingPinBytes?) -> Void) {
        self.completion = completion
        let (expires, overflow) = prompt.tStartNs.addingReportingOverflow(10_000_000_000)
        let now = HelperWire.nowNs()
        guard !overflow, prompt.tStartNs <= now, now < expires else { finish(nil); return }
        deadline = expires
        window?.makeKeyAndOrderFront(nil); window?.makeFirstResponder(field)
        NSApp.activate(ignoringOtherApps: true)
        let clock = Timer(timeInterval: 0.016, repeats: true) { [weak self] _ in
            guard let self, let panel = self.window else { return }
            // The daemon sends one request only; EOF or any further input
            // revokes this prompt. A lifecycle cancel closes its connection.
            let connectionChanged = HelperWire.connectionChanged(self.connection)
            if connectionChanged || HelperWire.nowNs() >= self.deadline || !PeerIdentity.isCurrentConsole()
                || OcclusionDetector.isOccluded(sheetWindowNumber: panel.windowNumber, sheetFrame: panel.frame, simulatedTestWindowNumber: nil) { self.finish(nil) }
        }
        timer = clock; RunLoop.main.add(clock, forMode: .common)
    }
    @objc private func submit() {
        guard let panel = window, panel.isVisible, HelperWire.nowNs() < deadline,
              !HelperWire.connectionChanged(connection), PeerIdentity.isCurrentConsole(),
              !OcclusionDetector.isOccluded(sheetWindowNumber: panel.windowNumber,
                sheetFrame: panel.frame, simulatedTestWindowNumber: nil) else { finish(nil); return }
        let pin = ExistingPinBytes(utf8: field.stringValue.utf8)
        defer { pin.wipe() }
        guard pin.isValid else { finish(nil); return }
        finish(pin)
    }
    @objc func cancel() { finish(nil) }
    private func finish(_ pin: ExistingPinBytes?) {
        guard let done = completion else { return }; completion = nil
        timer?.invalidate(); timer = nil
        field.stringValue = ""; window?.orderOut(nil); window?.close()
        done(pin)
    }
    func windowWillClose(_ notification: Notification) { finish(nil) }
}
