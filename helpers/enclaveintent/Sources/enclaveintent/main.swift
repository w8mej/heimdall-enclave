import AppKit
import Foundation

class HelperDelegate: NSObject, NSApplicationDelegate {
    let socketPath: String?
    let supervisorSocketPath: String?
    let testOcclusion: Bool
    let idleExit: Bool
    let nativeTestMode: Bool
    var listenSource: DispatchSourceRead?
    var serverFd: Int32 = -1
    var activeSheet: IntentSheet?
    var activeDisplay: SecureDisplayPanel?
    var activePin: SecurePinSheet?
    var screenLockObserver: NSObjectProtocol?
    var sessionResignObserver: NSObjectProtocol?
    private let screenLockQueue = DispatchQueue(label: "enclave-intent.screen-lock")
    private let screenLockGuard = NSLock()
    private var screenLockPending = false

    init(socketPath: String?, supervisorSocketPath: String?, testOcclusion: Bool, idleExit: Bool, nativeTestMode: Bool) {
        self.socketPath = socketPath
        self.supervisorSocketPath = supervisorSocketPath
        self.testOcclusion = testOcclusion
        self.idleExit = idleExit
        self.nativeTestMode = nativeTestMode
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        // GAP-16: Observe Aqua GUI screen-lock notification and notify supervisor
        screenLockObserver = DistributedNotificationCenter.default().addObserver(
            forName: NSNotification.Name("com.apple.screenIsLocked"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.activeSheet?.cancelForSessionChange()
            self?.activeDisplay?.dismiss()
            self?.activePin?.cancel()
            let supPath: String
            if let target = DeploymentTargetContext.selected {
                // Lock notifications remain within the immutable selected target.
                supPath = target.supervisorSocket
            } else {
                supPath = self?.supervisorSocketPath ?? "/var/run/enclave/supervisor/supervisor.sock"
            }
            self?.queueSupervisorScreenLocked(supervisorSocketPath: supPath)
        }
        sessionResignObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            self?.activeSheet?.cancelForSessionChange()
            self?.activeDisplay?.dismiss()
            self?.activePin?.cancel()
        }

        if let path = socketPath {
            startServer(at: path)
        } else {
            fputs("enclave-intent: no --socket specified, exiting\n", stderr)
            exit(1)
        }
    }

    deinit {
        if let observer = screenLockObserver { DistributedNotificationCenter.default().removeObserver(observer) }
        if let observer = sessionResignObserver { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
    }

    func queueSupervisorScreenLocked(supervisorSocketPath: String) {
        screenLockGuard.lock()
        guard !screenLockPending else { screenLockGuard.unlock(); return }
        screenLockPending = true
        screenLockGuard.unlock()
        screenLockQueue.async { [self] in
            defer { screenLockGuard.lock(); screenLockPending = false; screenLockGuard.unlock() }
            do { try ScreenLockRelay.deliver(to: supervisorSocketPath) }
            catch { fputs("enclave-intent: SCREEN_LOCK_WIPE_UNCONFIRMED\n", stderr) }
        }
    }

    func startServer(at requestedPath: String) {
        // Root creates this per-session directory; a user may not create it.
        let path: String
        if let target = DeploymentTargetContext.selected {
            guard requestedPath == target.intentSocket(uid: getuid()) else { exit(2) }
            path = requestedPath
        } else {
            path = requestedPath == "/var/run/enclave/intent/intent.sock"
                ? "/var/run/enclave/intent/\(getuid())/intent.sock" : requestedPath
        }
        #if !MCPMAC_NATIVE_TESTING
        guard PeerIdentity.socketDirectoryIsProtected(path) else {
            fputs("enclave-intent: protected current-console socket directory required\n", stderr)
            exit(1)
        }
        #endif
        unlink(path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            perror("socket")
            exit(1)
        }
        self.serverFd = fd

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            fputs("socket path too long\n", stderr)
            exit(1)
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: UInt8.self)
            for (i, b) in pathBytes.enumerated() {
                raw[i] = b
            }
            raw[pathBytes.count] = 0
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, addrLen)
            }
        }
        guard bindRes == 0 else {
            perror("bind")
            exit(1)
        }

        // Mode 0660: accessible by owner and group
        chmod(path, 0o660)

        guard listen(fd, 5) == 0 else {
            perror("listen")
            exit(1)
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        source.setEventHandler { [weak self] in
            self?.acceptClient()
        }
        source.resume()
        self.listenSource = source
    }

    func acceptClient() {
        var clientAddr = sockaddr_un()
        var clientLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let clientFd = withUnsafeMutablePointer(to: &clientAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                accept(serverFd, $0, &clientLen)
            }
        }
        guard clientFd >= 0 else { return }

        // Reject concurrent requests: only 1 in-flight intent prompt globally (GAP-14)
        if self.activeSheet != nil || self.activePin != nil {
            fputs("enclave-intent: rejected concurrent request while sheet is active\n", stderr)
            close(clientFd)
            return
        }

        // Peer UID check: must be UID 703 (_piivault) (fail closed)
        var peerCred = xucred()
        var credLen = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(clientFd, 0, LOCAL_PEERCRED, &peerCred, &credLen) == 0 else {
            fputs("enclave-intent: getsockopt LOCAL_PEERCRED failed, closing connection\n", stderr)
            close(clientFd)
            return
        }

        let peerUid = peerCred.cr_uid
        var allowed = (peerUid == PeerIdentity.custodyUid)
        #if MCPMAC_NATIVE_TESTING
        if self.nativeTestMode && peerUid == geteuid() {
            allowed = true
        }
        #endif
        if !allowed {
            fputs("enclave-intent: rejected peer UID \(peerUid) (expected \(PeerIdentity.custodyUid))\n", stderr)
            close(clientFd)
            return
        }

        #if !MCPMAC_NATIVE_TESTING
        guard PeerIdentity.verifyCustody(clientFd) else {
            fputs("enclave-intent: rejected unverified custody code/session identity\n", stderr)
            close(clientFd)
            return
        }
        #endif

        // Only an authenticated new custody request may replace a presentation.
        self.activeDisplay?.dismiss()

        // Bound an authenticated but incomplete frame; never hang the Aqua
        // event loop forever on a disconnected/failed daemon.
        var ioTimeout = timeval(tv_sec: 2, tv_usec: 0)
        guard setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &ioTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &ioTimeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            close(clientFd)
            return
        }

        let flags = fcntl(clientFd, F_GETFL)
        guard flags >= 0, fcntl(clientFd, F_SETFL, flags | O_NONBLOCK) == 0,
              var payload = try? HelperWire.readFrame(clientFd, max: 16384,
                deadline: HelperWire.nowNs() + 2_000_000_000) else {
            close(clientFd)
            return
        }

        if let nonce = try? SecureDisplayProtocol.prepareNonce(payload) {
            receiveDisplay(clientFd, nonce: nonce)
            return
        }

        if let request = try? ExistingPinPrompt.decode(payload) {
            let sheet = SecurePinSheet(prompt: request, connection: clientFd); activePin = sheet
            sheet.present { [weak self] pin in
                self?.activePin = nil
                var reply = request.reply(pin)
                defer {
                    _ = reply.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) }
                    close(clientFd)
                }
                let (deadline, overflow) = request.tStartNs.addingReportingOverflow(10_000_000_000)
                if !overflow { try? HelperWire.writeFrame(clientFd, reply, deadline: deadline) }
            }
            return
        }

        // Decode prompt
        guard let prompt = try? BiometricPrompt.decode(from: payload) else {
            close(clientFd)
            return
        }

        let sheet = IntentSheet(prompt: prompt, testOcclusion: self.testOcclusion)
        self.activeSheet = sheet
        sheet.present { [weak self] outcome in
            self?.activeSheet = nil
            let encoded = outcome.encode()
            var encCopy = encoded
            let (deadline, overflow) = prompt.tStartNs.addingReportingOverflow(10_000_000_000)
            if !overflow { try? HelperWire.writeFrame(clientFd, encCopy, deadline: deadline) }
            close(clientFd)

            // Zeroize sensitive payload memory
            _ = payload.withUnsafeMutableBytes { ptr in
                memset_s(ptr.baseAddress, ptr.count, 0, ptr.count)
            }
            _ = encCopy.withUnsafeMutableBytes { ptr in
                memset_s(ptr.baseAddress, ptr.count, 0, ptr.count)
            }

            if self?.idleExit == true {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                    exit(0)
                }
            }
        }
    }

    private func receiveDisplay(_ fd: Int32, nonce: [UInt8]) {
        var presentation: SecureDisplayPanel?
        do {
            let deadline = HelperWire.nowNs() + 2_000_000_000
            try HelperWire.writeFrame(fd, SecureDisplayProtocol.ready + nonce, deadline: deadline)
            var values = try HelperWire.readFrame(fd, max: 1_048_576, deadline: deadline)
            defer { _ = values.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
            let strings = try SecureDisplayProtocol.strings(values)
            let panel = SecureDisplayPanel(values: strings, fd: fd) { [weak self] in self?.activeDisplay = nil }
            presentation = panel; activeDisplay = panel
            panel.present()
            try HelperWire.writeFrame(fd, SecureDisplayProtocol.shown + nonce, deadline: deadline)
        } catch {
            if let panel = presentation { panel.dismiss() } else { close(fd) }
            // No plaintext, parser detail or supplied data enters diagnostics.
            fputs("enclave-intent: protected display handoff unconfirmed\n", stderr)
        }
    }

    private func readExact(fd: Int32, buffer: inout [UInt8], count: Int) -> Bool {
        var bytesRead = 0
        while bytesRead < count {
            let res = buffer.withUnsafeMutableBytes { ptr -> Int in
                let target = ptr.baseAddress!.advanced(by: bytesRead)
                return read(fd, target, count - bytesRead)
            }
            if res <= 0 { return false }
            bytesRead += res
        }
        return true
    }

    private func writeAll(fd: Int32, buffer: inout [UInt8], count: Int) -> Bool {
        var bytesWritten = 0
        while bytesWritten < count {
            let res = buffer.withUnsafeBytes { ptr -> Int in
                let target = ptr.baseAddress!.advanced(by: bytesWritten)
                return write(fd, target, count - bytesWritten)
            }
            if res <= 0 { return false }
            bytesWritten += res
        }
        return true
    }
}

// Select protected configuration before NSApplication, test fixtures, sockets,
// notifications or peer actions. Selection also closes the configured argv set.
let selectedDeployment = DeploymentTargetContext.selected

// Main entry
var socketPath: String?
var supervisorSocketPath: String?
var testOcclusion = false
var idleExit = false
var nativeTestMode = false

var i = 1
while i < CommandLine.arguments.count {
    let arg = CommandLine.arguments[i]
    if arg == "--deployment-target" && i + 1 < CommandLine.arguments.count {
        i += 1 // already strictly checked and protected-loaded above
    } else if arg == "--socket" && i + 1 < CommandLine.arguments.count {
        socketPath = CommandLine.arguments[i + 1]
        i += 1
    } else if arg == "--supervisor-socket" && i + 1 < CommandLine.arguments.count {
        supervisorSocketPath = CommandLine.arguments[i + 1]
        i += 1
    } else if arg == "--test-occlusion" {
        testOcclusion = true
    } else if arg == "--idle-exit" {
        idleExit = true
    } else if arg == "--native-test" {
        #if MCPMAC_NATIVE_TESTING
        nativeTestMode = true
        #else
        fputs("--native-test requires a separately compiled native-test helper\n", stderr)
        exit(2)
        #endif
    }
    i += 1
}

if let target = selectedDeployment {
    socketPath = target.intentSocket(uid: getuid())
    supervisorSocketPath = target.supervisorSocket
}

#if MCPMAC_NATIVE_TESTING
guard nativeTestMode else {
    fputs("native-test helper requires --native-test; it cannot serve production requests\n", stderr)
    exit(2)
}
if CommandLine.arguments.contains("--deployment-target-self-test") {
    do { try DeploymentTargetContext.selfTest(); exit(0) }
    catch { fputs("deployment target private fixture failed\n", stderr); exit(1) }
}
if CommandLine.arguments.contains("--screen-lock-relay-self-test") {
    do { try ScreenLockRelay.selfTest(); exit(0) }
    catch { fputs("screen-lock relay private fixture failed\n", stderr); exit(1) }
}
if CommandLine.arguments.contains("--protocol-self-test") {
    do { try HelperProtocolSelfTest.run(); exit(0) }
    catch { fputs("helper protocol private fixture failed\n", stderr); exit(1) }
}
#endif

#if MCPMAC_DEV_SAME_UID
// Say so on every start: this helper trusts a custody peer at the user's UID.
fputs("enclave-intent: \(PeerIdentity.devSameUidMarker)\n", stderr)
#endif

let app = NSApplication.shared
let delegate = HelperDelegate(
    socketPath: socketPath,
    supervisorSocketPath: supervisorSocketPath,
    testOcclusion: testOcclusion,
    idleExit: idleExit,
    nativeTestMode: nativeTestMode
)
app.delegate = delegate
app.run()
