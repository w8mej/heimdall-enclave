import Foundation
import Darwin

// No GUI state is changed here. One notification is sent to the already
// provisioned root supervisor and acknowledged only after all five wipe results.
enum ScreenLockRelay {
    enum Failure: Error { case unavailable, deadline, protocolError, wipeIncomplete }
    static let request = CBOREncoder.encodeText("SessionLocked")

    static func wait(_ fd: Int32, _ events: Int16, _ deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw Failure.deadline }
            let milliseconds = Int32(min((deadline - now + 999_999) / 1_000_000, UInt64(Int32.max)))
            var item = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&item, 1, milliseconds)
            if result < 0 && errno == EINTR { continue }
            guard result > 0 else { throw result == 0 ? Failure.deadline : Failure.unavailable }
            guard item.revents & events != 0 else { throw Failure.unavailable }
            return
        }
    }

    static func configure(_ fd: Int32) throws {
        var enabled: Int32 = 1
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0
        else { throw Failure.unavailable }
    }

    static func writeAll(_ fd: Int32, _ bytes: [UInt8], _ deadline: UInt64) throws {
        var offset = 0
        while offset < bytes.count {
            try wait(fd, Int16(POLLOUT), deadline)
            let count = bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!.advanced(by: offset), bytes.count - offset, 0) }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { throw Failure.unavailable }
            offset += count
        }
    }

    static func readExact(_ fd: Int32, _ size: Int, _ deadline: UInt64) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: size)
        var offset = 0
        while offset < size {
            try wait(fd, Int16(POLLIN), deadline)
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), size - offset) }
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { throw Failure.unavailable }
            offset += count
        }
        return bytes
    }

    static func frame(_ bytes: [UInt8]) -> [UInt8] {
        let count = UInt32(bytes.count)
        return [UInt8((count >> 24) & 255), UInt8((count >> 16) & 255), UInt8((count >> 8) & 255), UInt8(count & 255)] + bytes
    }

    static func validateAcknowledgement(_ bytes: [UInt8]) throws {
        var reader = CBORReader(data: bytes)
        let value = try reader.readValue()
        guard reader.offset == bytes.count,
              case .map(let outer) = value, outer.count == 1,
              case .textString("Ok") = outer[0].0,
              case .map(let response) = outer[0].1, response.count == 1,
              case .textString("WipeCompleted") = response[0].0,
              case .array(let receipts) = response[0].1, receipts.count == 5
        else { throw Failure.protocolError }
        var daemons = Set<UInt64>()
        for receipt in receipts {
            guard case .map(let fields) = receipt else { throw Failure.protocolError }
            let successes = fields.filter { if case .textString("success") = $0.0 { return true }; return false }
            let triggers = fields.filter { if case .textString("trigger") = $0.0 { return true }; return false }
            let identities = fields.filter { if case .textString("daemon_uid") = $0.0 { return true }; return false }
            guard successes.count == 1, triggers.count == 1, identities.count == 1,
                  case .boolean(true) = successes[0].1,
                  case .textString("SessionLocked") = triggers[0].1,
                  case .unsigned(let uid) = identities[0].1,
                  (701...705).contains(uid), daemons.insert(uid).inserted
            else { throw Failure.wipeIncomplete }
        }
        guard daemons == Set<UInt64>(701...705) else { throw Failure.wipeIncomplete }
    }

    static func exchange(_ fd: Int32, deadline: UInt64) throws {
        try writeAll(fd, frame(request), deadline)
        let header = try readExact(fd, 4, deadline)
        let size = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size > 0 && size <= 65536 else { throw Failure.protocolError }
        try validateAcknowledgement(readExact(fd, Int(size), deadline))
    }

    static func deliver(to path: String) throws {
        let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.unavailable }
        defer { close(fd) }
        try configure(fd)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard path.hasPrefix("/"), !bytes.contains(0), bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw Failure.unavailable }
        withUnsafeMutablePointer(to: &address.sun_path) {
            let target = UnsafeMutableRawPointer($0).assumingMemoryBound(to: UInt8.self)
            for (index, byte) in bytes.enumerated() { target[index] = byte }
            target[bytes.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        while true {
            guard DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.deadline }
            let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            if result == 0 || errno == EISCONN { break }
            if errno == EINTR { continue }
            guard errno == EINPROGRESS || errno == EALREADY || errno == EAGAIN else { throw Failure.unavailable }
            try wait(fd, Int16(POLLOUT), deadline)
            var error: Int32 = 0
            var length = socklen_t(MemoryLayout.size(ofValue: error))
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else { throw Failure.unavailable }
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == 0 else { throw Failure.unavailable }
        try exchange(fd, deadline: deadline)
    }

    #if MCPMAC_NATIVE_TESTING
    static func selfTest() throws {
        let receipts = (701...705).map { uid in
            [UInt8(0xa3)] + CBOREncoder.encodeText("trigger") + CBOREncoder.encodeText("SessionLocked") + CBOREncoder.encodeText("success") + [0xf5] + CBOREncoder.encodeText("daemon_uid") + CBOREncoder.encodeUInt(UInt64(uid))
        }
        let prefix = [UInt8(0xa1)] + CBOREncoder.encodeText("Ok") + [0xa1] + CBOREncoder.encodeText("WipeCompleted") + [0x85]
        let acknowledgement = prefix + receipts.flatMap { $0 }
        let duplicates = prefix + Array(repeating: receipts[0], count: 5).flatMap { $0 }
        let unidentified = [UInt8(0xa2)] + CBOREncoder.encodeText("trigger") + CBOREncoder.encodeText("SessionLocked") + CBOREncoder.encodeText("success") + [0xf5]
        let missingIdentities = prefix + Array(repeating: unidentified, count: 5).flatMap { $0 }
        try validateAcknowledgement(acknowledgement)
        for invalid in [duplicates, missingIdentities, acknowledgement + [0], [0x60], Array(acknowledgement.dropLast()), acknowledgement.map { $0 == 0xf5 ? 0xf4 : $0 }] {
            do { try validateAcknowledgement(invalid); preconditionFailure("invalid acknowledgement accepted") } catch {}
        }
        var pair = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw Failure.unavailable }
        defer { close(pair[0]); close(pair[1]) }
        try configure(pair[0]); try configure(pair[1])
        let client = pair[0], server = pair[1]
        let deadline = DispatchTime.now().uptimeNanoseconds + 1_000_000_000
        let done = DispatchGroup()
        done.enter()
        DispatchQueue.global().async {
            defer { done.leave() }
            do {
                let requestBytes = try readExact(server, frame(request).count, deadline)
                precondition(requestBytes == frame(request))
                for byte in frame(acknowledgement) { try writeAll(server, [byte], deadline) }
            } catch { preconditionFailure("private relay exchange failed") }
        }
        try exchange(client, deadline: deadline)
        precondition(done.wait(timeout: .now() + 1) == .success)
        let start = DispatchTime.now().uptimeNanoseconds
        do { try exchange(client, deadline: start + 25_000_000); preconditionFailure("missing reply accepted") }
        catch Failure.deadline {}
        precondition(DispatchTime.now().uptimeNanoseconds - start < 1_000_000_000)
        print("screen-lock relay private fixtures PASS; no host notifications or installed sockets")
    }
    #endif
}
