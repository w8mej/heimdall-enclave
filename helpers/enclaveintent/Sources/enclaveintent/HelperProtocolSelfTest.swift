#if depot_NATIVE_TESTING
import Foundation
import Darwin

/// Private nonceremony probes: no LAContext, key creation, PIN, or installation.
enum HelperProtocolSelfTest {
    enum Failure: Error { case acceptedMalformedInput, validInputRejected, peerAccepted }
    static func run() throws {
        let fields: [(String, [UInt8])] = [
            ("localized_reason", CBOREncoder.encodeText("[A3] Reveal one row | SAS: test")),
            ("d_jcs", CBOREncoder.encodeBytes([UInt8](repeating: 1, count: 32))),
            ("nonce", CBOREncoder.encodeBytes([UInt8](repeating: 2, count: 32))),
            ("t_start_ns", CBOREncoder.encodeUInt(123)),
            ("bio_key_blob", CBOREncoder.encodeBytes([]))
        ]
        func encode(_ values: [(String, [UInt8])]) -> [UInt8] {
            var bytes = [UInt8(0xa0 + values.count)]
            for (key, value) in values { bytes += CBOREncoder.encodeText(key); bytes += value }
            return bytes
        }
        let valid = encode(fields)
        let prompt = try BiometricPrompt.decode(from: valid)
        guard prompt.dJcs.count == 32, prompt.nonce.count == 32,
              prompt.signedMessage().count == 72 else { throw Failure.validInputRejected }
        var wrongDigest = fields; wrongDigest[1] = ("d_jcs", CBOREncoder.encodeBytes([1]))
        var unknown = fields; unknown[4] = ("unknown", CBOREncoder.encodeBytes([]))
        var deeplyNested = [UInt8](repeating: 0x81, count: 18); deeplyNested.append(0)
        for malformed in [valid + [0], encode(fields + [fields[0]]), encode(wrongDigest), encode(unknown), [0x5b] + [UInt8](repeating: 0xff, count: 8), deeplyNested] {
            do { _ = try BiometricPrompt.decode(from: malformed); throw Failure.acceptedMalformedInput }
            catch Failure.acceptedMalformedInput { throw Failure.acceptedMalformedInput }
            catch { /* Expected strict parser rejection, without a trap. */ }
        }
        guard !PeerIdentity.socketDirectoryIsProtected("/tmp/untrusted-intent.sock") else { throw Failure.peerAccepted }
        var pair = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw Failure.peerAccepted }
        defer { close(pair[0]); close(pair[1]) }
        guard !PeerIdentity.verifyCustody(pair[0]) else { throw Failure.peerAccepted }
        guard !HelperWire.connectionChanged(pair[0]), shutdown(pair[1], SHUT_RDWR) == 0,
              HelperWire.connectionChanged(pair[0]) else { throw Failure.validInputRejected }
        let display = encode([("display_protocol", CBOREncoder.encodeText("enclave.display.v1")),
                              ("nonce", CBOREncoder.encodeBytes([UInt8](repeating: 9, count: 32)))])
        guard try SecureDisplayProtocol.prepareNonce(display).count == 32,
              try SecureDisplayProtocol.strings([0x81] + CBOREncoder.encodeBytes(Array("synthetic".utf8))) == ["synthetic"] else { throw Failure.validInputRejected }
        for malformed in [display + [0], encode([("display_protocol", CBOREncoder.encodeText("enclave.display.v0")), ("nonce", CBOREncoder.encodeBytes([1]))])] {
            do { _ = try SecureDisplayProtocol.prepareNonce(malformed); throw Failure.acceptedMalformedInput }
            catch Failure.acceptedMalformedInput { throw Failure.acceptedMalformedInput }
            catch {}
        }
        for malformed in [[UInt8](arrayLiteral: 0x80), [0x81, 0x61, 0x61], [0x81, 0x41, 0xff], [0x81, 0x40, 0]] {
            do { _ = try SecureDisplayProtocol.strings(malformed); throw Failure.acceptedMalformedInput }
            catch Failure.acceptedMalformedInput { throw Failure.acceptedMalformedInput }
            catch {}
        }
        let pinFields: [(String, [UInt8])] = [
            ("pin_protocol", CBOREncoder.encodeText("enclave.pin.v1")),
            ("nonce", CBOREncoder.encodeBytes([UInt8](repeating: 9, count: 32))),
            ("t_start_ns", CBOREncoder.encodeUInt(123)),
            ("reason", CBOREncoder.encodeText("Synthetic protocol check"))
        ]
        let pinPrompt = try ExistingPinPrompt.decode(encode(pinFields))
        guard pinPrompt.nonce.count == 32, !pinPrompt.reply(nil).isEmpty else { throw Failure.validInputRejected }
        let syntheticPin = ExistingPinBytes(utf8: "synthetic-test-pin".utf8)
        var syntheticReply = pinPrompt.reply(syntheticPin)
        defer { _ = syntheticReply.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        var replyReader = CBORReader(data: syntheticReply)
        guard case .map(let replyFields) = try replyReader.readValue(), replyFields.count == 3 else { throw Failure.validInputRejected }
        syntheticPin.wipe()
        guard !syntheticPin.isValid else { throw Failure.acceptedMalformedInput }
        for malformed in [encode(pinFields) + [0], encode(pinFields + [pinFields[0]]), encode(Array(pinFields.dropFirst()))] {
            do { _ = try ExistingPinPrompt.decode(malformed); throw Failure.acceptedMalformedInput }
            catch Failure.acceptedMalformedInput { throw Failure.acceptedMalformedInput }
            catch {}
        }
        print("helper protocol private probes: valid frame PASS; malformed6 PASS; untrusted path/peer PASS; display positive2/reject6 PASS; PIN protocol positive/reject3 PASS (no PIN UI or authenticator)")
    }
}
#endif
