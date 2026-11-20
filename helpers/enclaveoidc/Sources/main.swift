import AppKit
import Darwin
import Foundation

final class BrokerDelegate: NSObject, NSApplicationDelegate {
    private let identityPath: String
    private let oauthPath: String
    private var server: Int32 = -1
    private var lock: Int32 = -1
    private var runtime: OIDCDeploymentTargetContext.RuntimeDirectory?
    private var listener: DispatchSourceRead?
    private var transaction: BrowserStepUp?
    private var accepting = false
    // Main-queue lifecycle generation covers the interval before a decoded
    // request becomes a transaction as well as the browser transaction itself.
    private var lifecycleEpoch: UInt64 = 0
    private var screenLocked = false
    private var sessionInactive = false
    private var observers = [NSObjectProtocol]()
    init(identityPath: String, oauthPath: String) { self.identityPath = identityPath; self.oauthPath = oauthPath }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        do {
            let (identity, _) = try BrokerIdentityConfig.load(identityPath)
            _ = try BrokerOAuthConfig.load(oauthPath)
            try startServer(identity.socket)
            observers.append(DistributedNotificationCenter.default().addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
                self?.screenLocked = true; self?.invalidateLifecycle()
            })
            observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
                self?.sessionInactive = true; self?.invalidateLifecycle()
            })
            observers.append(DistributedNotificationCenter.default().addObserver(forName: NSNotification.Name("com.apple.screenIsUnlocked"), object: nil, queue: .main) { [weak self] _ in self?.screenLocked = false })
            observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.sessionDidBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in self?.sessionInactive = false })
        } catch { fputs("enclave-oidc: protected current-session configuration required\n", stderr); exit(1) }
    }

    private func invalidateLifecycle() {
        if lifecycleEpoch == UInt64.max { exit(1) }
        lifecycleEpoch += 1
        transaction?.finish()
    }

    private func startServer(_ path: String) throws {
        let selected = OIDCDeploymentTargetContext.selected
        let parent = selected?.brokerParent ?? "/var/run/enclave/oidc"
        let child = parent + "/\(getuid())"
        if let target = selected {
            try OIDCDeploymentTargetContext.check(target)
            guard path == target.brokerSocket(uid: getuid()) else { throw BrokerFailure.refused }
            runtime = try OIDCDeploymentTargetContext.RuntimeDirectory.openSelected(target, uid: getuid())
        }
        var parentState = stat(); var childState = stat()
        let observedParent = try selected.map { _ in try OIDCDeploymentTargetContext.normalizedPath(parent) } ?? parent
        let observedChild = try selected.map { _ in try OIDCDeploymentTargetContext.normalizedPath(child) } ?? child
        guard path == child + "/broker.sock", lstat(observedParent, &parentState) == 0, lstat(observedChild, &childState) == 0,
              parentState.st_mode & S_IFMT == S_IFDIR, parentState.st_uid == 0,
              parentState.st_gid == 0, parentState.st_mode & 0o7777 == 0o755,
              childState.st_mode & S_IFMT == S_IFDIR, childState.st_uid == getuid(),
              childState.st_gid == 8703, childState.st_mode & 0o7777 == 0o2710 else { throw BrokerFailure.refused }
        if let runtime {
            try runtime.check()
            lock = openat(runtime.fd, "broker.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        } else { lock = open(child + "/broker.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600) }
        var lockState = stat()
        guard lock >= 0, fstat(lock, &lockState) == 0, lockState.st_mode & S_IFMT == S_IFREG,
              lockState.st_uid == getuid(), lockState.st_nlink == 1, lockState.st_mode & 0o077 == 0,
              flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw BrokerFailure.refused }
        if let runtime {
            var namedLock = stat()
            guard fstatat(runtime.fd, "broker.lock", &namedLock, AT_SYMLINK_NOFOLLOW) == 0,
                  namedLock.st_dev == lockState.st_dev, namedLock.st_ino == lockState.st_ino else { throw BrokerFailure.refused }
            try runtime.check()
        }
        var previous = stat()
        let previousResult: Int32
        if let runtime { previousResult = fstatat(runtime.fd, "broker.sock", &previous, AT_SYMLINK_NOFOLLOW) }
        else { previousResult = lstat(path, &previous) }
        if previousResult == 0 {
            guard previous.st_mode & S_IFMT == S_IFSOCK, previous.st_uid == getuid() else { throw BrokerFailure.refused }
            if let runtime { guard unlinkat(runtime.fd, "broker.sock", 0) == 0 else { throw BrokerFailure.refused } }
            else { guard unlink(path) == 0 else { throw BrokerFailure.refused } }
        } else if errno != ENOENT { throw BrokerFailure.refused }
        if let target = selected { try OIDCDeploymentTargetContext.check(target); try runtime?.check() }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw BrokerFailure.refused }; server = fd
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC); _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw BrokerFailure.refused }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: bytes); destination[bytes.count] = 0
        }
        let length = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, length) }
        }
        if let target = selected { try OIDCDeploymentTargetContext.check(target); try runtime?.check() }
        guard result == 0, chmod(path, 0o660) == 0, listen(fd, 4) == 0 else { throw BrokerFailure.refused }
        if let target = selected { try OIDCDeploymentTargetContext.check(target); try runtime?.check() }
        let listener = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        listener.setEventHandler { [weak self] in self?.acceptOne() }; self.listener = listener; listener.resume()
    }

    private func acceptOne() {
        let fd = accept(server, nil, nil)
        guard fd >= 0 else { return }
        guard !accepting, transaction == nil, !screenLocked, !sessionInactive else { close(fd); return }
        accepting = true
        let admittedEpoch = lifecycleEpoch
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC); _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        var yes: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0 else { close(fd); accepting = false; return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { close(fd); return }
            do {
                // Authenticate before reading any request, then recheck before
                // browser start and final token reply. No caller-selected URL.
                guard PeerIdentity.verifyCustody(fd) else { throw BrokerFailure.refused }
                let now = HelperWire.nowNs()
                let (admissionDeadline, overflow) = now.addingReportingOverflow(1_000_000_000)
                guard !overflow else { throw BrokerFailure.refused }
                var bytes = try HelperWire.readFrame(fd, max: 16384, deadline: admissionDeadline)
                defer { _ = bytes.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
                let request = try BrokerRequest.decode(bytes)
                let (identity, identityHash) = try BrokerIdentityConfig.load(self.identityPath)
                let (oauth, oauthHash) = try BrokerOAuthConfig.load(self.oauthPath)
                try request.validate(identity, oauth, now: HelperWire.nowNs())
                DispatchQueue.main.async { [weak self] in
                    guard let self else { close(fd); return }; self.accepting = false
                    guard self.lifecycleEpoch == admittedEpoch, !self.screenLocked, !self.sessionInactive else { shutdown(fd, SHUT_RDWR); close(fd); return }
                    let operation = BrowserStepUp(request: request, connection: fd, identityPath: self.identityPath,
                        oauthPath: self.oauthPath, identity: identity, oauth: oauth,
                        identityDigest: identityHash, oauthDigest: oauthHash) { [weak self] in self?.transaction = nil }
                    self.transaction = operation; operation.start()
                }
            } catch {
                shutdown(fd, SHUT_RDWR); close(fd)
                DispatchQueue.main.async { [weak self] in self?.accepting = false }
            }
        }
    }
}

#if depot_OIDC_NATIVE_TESTING
if CommandLine.arguments == [CommandLine.arguments[0], "--protocol-self-test"] {
    do { try BrokerProtocolSelfTest.run(); exit(0) }
    catch { fputs("enclave-oidc private protocol selftest FAILED\n", stderr); exit(1) }
}
if CommandLine.arguments == [CommandLine.arguments[0], "--deployment-target-self-test"] {
    do { try OIDCDeploymentTargetSelfTest.run(); exit(0) }
    catch { fputs("enclave-oidc private deployment selftest FAILED\n", stderr); exit(1) }
}
fputs("enclave-oidc: native-test executable supports pure selftests only\n", stderr); exit(2)
#else
let options: BrokerArguments
do {
    options = try BrokerArguments.parse(CommandLine.arguments)
    if let target = OIDCDeploymentTargetContext.selected { try PeerIdentity.validateSelectedSelf(target) }
} catch {
    fputs("usage: enclave-oidc --identity-config ROOT_FILE --oauth-config ROOT_FILE [--deployment-target DESCRIPTOR]\n", stderr); exit(2)
}
let application = NSApplication.shared
let delegate = BrokerDelegate(identityPath: options.identityPath, oauthPath: options.oauthPath)
application.delegate = delegate
application.run()
#endif
