import AppKit
import Darwin
import Foundation

/// All fragments share a continuous-clock deadline; progress never renews it.
enum HelperWire {
    enum Failure: Error { case deadline, transport, protocolError }
    static func connectionChanged(_ fd: Int32) -> Bool {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        return poll(&descriptor, 1, 0) != 0
    }
    static func nowNs() -> UInt64 {
        var stamp = timespec()
        guard clock_gettime(CLOCK_MONOTONIC, &stamp) == 0,
              stamp.tv_sec >= 0, stamp.tv_nsec >= 0 else { return UInt64.max }
        return UInt64(stamp.tv_sec) * 1_000_000_000 + UInt64(stamp.tv_nsec)
    }
    static func wait(_ fd: Int32, _ events: Int16, _ deadline: UInt64) throws {
        while true {
            let now = nowNs()
            guard now < deadline else { throw Failure.deadline }
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&descriptor, 1, Int32(min((deadline - now + 999_999) / 1_000_000, 50)))
            guard nowNs() < deadline else { throw Failure.deadline }
            if result > 0 { return }
            if result < 0 && errno != EINTR { throw Failure.transport }
        }
    }
    static func readExact(_ fd: Int32, _ size: Int, _ deadline: UInt64) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: size)
        var complete = false
        defer {
            if !complete { _ = bytes.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        }
        var offset = 0
        while offset < size {
            try wait(fd, Int16(POLLIN), deadline)
            let count = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: offset), size - offset) }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { throw Failure.transport }
            offset += count
        }
        complete = true
        return bytes
    }
    static func readFrame(_ fd: Int32, max: Int, deadline: UInt64) throws -> [UInt8] {
        let size = try readExact(fd, 4, deadline).reduce(0) { ($0 << 8) | Int($1) }
        guard size > 0 && size <= max else { throw Failure.protocolError }
        return try readExact(fd, size, deadline)
    }
    static func writeFrame(_ fd: Int32, _ bytes: [UInt8], deadline: UInt64) throws {
        let size = UInt32(bytes.count)
        let header = [UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)]
        for part in [header, bytes] {
            var offset = 0
            while offset < part.count {
                try wait(fd, Int16(POLLOUT), deadline)
                let count = part.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), part.count - offset) }
                if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
                guard count > 0 else { throw Failure.transport }
                offset += count
            }
        }
    }
}

/// Exact no-plaintext preparation, then one bounded values frame on the same
/// mutually authenticated connection. This protocol cannot authorize a release.
enum SecureDisplayProtocol {
    static let ready = Array("depotMDISP/READY/1\0".utf8)
    static let shown = Array("depotMDISP/SHOWN/1\0".utf8)
    static func prepareNonce(_ bytes: [UInt8]) throws -> [UInt8] {
        var reader = CBORReader(data: bytes)
        guard case .map(let fields) = try reader.readValue(), reader.offset == bytes.count,
              fields.count == 2 else { throw HelperWire.Failure.protocolError }
        var seen = Set<String>(); var nonce: [UInt8]?
        for (key, value) in fields {
            guard case .textString(let name) = key, seen.insert(name).inserted else { throw HelperWire.Failure.protocolError }
            switch (name, value) {
            case ("display_protocol", .textString("enclave.display.v1")): break
            case ("nonce", .byteString(let bytes)) where bytes.count == 32: nonce = bytes
            default: throw HelperWire.Failure.protocolError
            }
        }
        guard let nonce, seen.contains("display_protocol") else { throw HelperWire.Failure.protocolError }
        return nonce
    }
    static func strings(_ bytes: [UInt8]) throws -> [String] {
        var reader = CBORReader(data: bytes, maxBytes: 1_048_576)
        guard case .array(let items) = try reader.readValue(), reader.offset == bytes.count,
              !items.isEmpty, items.count <= 64 else { throw HelperWire.Failure.protocolError }
        return try items.map {
            guard case .byteString(let data) = $0, let value = String(bytes: data, encoding: .utf8) else { throw HelperWire.Failure.protocolError }
            return value
        }
    }
}

/// Presentation lives only while custody holds its authenticated connection.
/// AppKit owns rendered text copies; clearing them is not physical erasure proof.
final class SecureDisplayPanel: NSObject, NSWindowDelegate {
    private let panel: NSPanel
    private let text: NSTextView
    private let fd: Int32
    private var receiver: DispatchSourceRead?
    private var timer: Timer?
    private var closed = false
    private let expires = HelperWire.nowNs() + 30_000_000_000
    private let completed: () -> Void

    init(values: [String], fd: Int32, completed: @escaping () -> Void) {
        self.fd = fd; self.completed = completed
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 540, height: 300), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        text = NSTextView(frame: NSRect(x: 0, y: 0, width: 540, height: 300))
        super.init()
        panel.delegate = self; panel.title = "Enclave protected values"
        panel.sharingType = .none; panel.level = .modalPanel
        text.isEditable = false; text.isSelectable = false
        text.string = values.joined(separator: "\n")
        panel.contentView = text; panel.center()
    }
    func present() {
        panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        source.setEventHandler { [weak self] in self?.dismiss() }
        source.setCancelHandler { [fd] in Darwin.close(fd) }
        receiver = source; source.resume()
        let clock = Timer(timeInterval: 0.05, repeats: true) { [weak self] _ in
            guard let self else { return }
            if HelperWire.nowNs() >= self.expires || !PeerIdentity.isCurrentConsole()
                || OcclusionDetector.isOccluded(sheetWindowNumber: self.panel.windowNumber, sheetFrame: self.panel.frame, simulatedTestWindowNumber: nil) { self.dismiss() }
        }
        timer = clock; RunLoop.main.add(clock, forMode: .common)
    }
    func dismiss() {
        guard !closed else { return }; closed = true
        timer?.invalidate(); timer = nil
        text.textStorage?.mutableString.setString("")
        panel.orderOut(nil); panel.close()
        receiver?.cancel(); receiver = nil
        completed()
    }
    func windowWillClose(_ notification: Notification) { dismiss() }
}
