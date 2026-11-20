import Foundation

/// Minimal deterministic CBOR encoder and decoder for `_enclaveintent`.
/// Wire-compatible with `ciborium` in `enclave_custody_vaultd::biometric`.

public enum CBORValue {
    case unsigned(UInt64)
    case negative(UInt64)
    case byteString([UInt8])
    case textString(String)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])
    case boolean(Bool)
    case null
}

public struct CBOREncoder {
    public static func encodeUInt(_ val: UInt64) -> [UInt8] {
        if val < 24 {
            return [UInt8(val)]
        } else if val <= 0xff {
            return [0x18, UInt8(val)]
        } else if val <= 0xffff {
            return [0x19, UInt8((val >> 8) & 0xff), UInt8(val & 0xff)]
        } else if val <= 0xffff_ffff {
            var b = [UInt8](repeating: 0, count: 5)
            b[0] = 0x1a
            b[1] = UInt8((val >> 24) & 0xff)
            b[2] = UInt8((val >> 16) & 0xff)
            b[3] = UInt8((val >> 8) & 0xff)
            b[4] = UInt8(val & 0xff)
            return b
        } else {
            var b = [UInt8](repeating: 0, count: 9)
            b[0] = 0x1b
            for i in 0..<8 {
                b[1 + i] = UInt8((val >> (56 - 8 * i)) & 0xff)
            }
            return b
        }
    }

    public static func encodeText(_ s: String) -> [UInt8] {
        let utf8 = Array(s.utf8)
        var out = [UInt8]()
        let len = UInt64(utf8.count)
        if len < 24 {
            out.append(0x60 | UInt8(len))
        } else if len <= 0xff {
            out.append(contentsOf: [0x78, UInt8(len)])
        } else if len <= 0xffff {
            out.append(contentsOf: [0x79, UInt8((len >> 8) & 0xff), UInt8(len & 0xff)])
        } else if len <= 0xffff_ffff {
            out.append(contentsOf: [
                0x7a,
                UInt8((len >> 24) & 0xff),
                UInt8((len >> 16) & 0xff),
                UInt8((len >> 8) & 0xff),
                UInt8(len & 0xff)
            ])
        }
        out.append(contentsOf: utf8)
        return out
    }

    public static func encodeBytes(_ b: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        let len = UInt64(b.count)
        if len < 24 {
            out.append(0x40 | UInt8(len))
        } else if len <= 0xff {
            out.append(contentsOf: [0x58, UInt8(len)])
        } else if len <= 0xffff {
            out.append(contentsOf: [0x59, UInt8((len >> 8) & 0xff), UInt8(len & 0xff)])
        } else if len <= 0xffff_ffff {
            out.append(contentsOf: [
                0x5a,
                UInt8((len >> 24) & 0xff),
                UInt8((len >> 16) & 0xff),
                UInt8((len >> 8) & 0xff),
                UInt8(len & 0xff)
            ])
        }
        out.append(contentsOf: b)
        return out
    }
}

public struct CBORReader {
    public let data: [UInt8]
    public let maxBytes: Int
    public var offset: Int = 0

    public init(data: [UInt8], maxBytes: Int = 16384) {
        self.data = data
        self.maxBytes = maxBytes
        self.offset = 0
    }

    public mutating func readValue(depth: Int = 0) throws -> CBORValue {
        guard depth <= 16, data.count <= maxBytes, offset < data.count else {
            throw NSError(domain: "CBOR", code: 1, userInfo: [NSLocalizedDescriptionKey: "Unexpected EOF"])
        }
        let initial = data[offset]
        offset += 1
        let major = initial >> 5
        let info = initial & 0x1f

        let length: UInt64
        switch info {
        case 0...23:
            length = UInt64(info)
        case 24:
            guard offset < data.count else {
                throw NSError(domain: "CBOR", code: 2, userInfo: [NSLocalizedDescriptionKey: "EOF reading length"])
            }
            length = UInt64(data[offset])
            offset += 1
        case 25:
            guard offset + 1 < data.count else {
                throw NSError(domain: "CBOR", code: 3, userInfo: [NSLocalizedDescriptionKey: "EOF reading length"])
            }
            length = (UInt64(data[offset]) << 8) | UInt64(data[offset + 1])
            offset += 2
        case 26:
            guard offset + 3 < data.count else {
                throw NSError(domain: "CBOR", code: 4, userInfo: [NSLocalizedDescriptionKey: "EOF reading length"])
            }
            length = (UInt64(data[offset]) << 24) | (UInt64(data[offset + 1]) << 16) | (UInt64(data[offset + 2]) << 8) | UInt64(data[offset + 3])
            offset += 4
        case 27:
            guard offset + 7 < data.count else {
                throw NSError(domain: "CBOR", code: 5, userInfo: [NSLocalizedDescriptionKey: "EOF reading length"])
            }
            var val: UInt64 = 0
            for i in 0..<8 {
                val = (val << 8) | UInt64(data[offset + i])
            }
            offset += 8
            length = val
        default:
            throw NSError(domain: "CBOR", code: 6, userInfo: [NSLocalizedDescriptionKey: "Unsupported info field"])
        }

        switch major {
        case 0:
            return .unsigned(length)
        case 1:
            return .negative(length)
        case 2:
            guard let count = Int(exactly: length), count <= data.count - offset else {
                throw NSError(domain: "CBOR", code: 7, userInfo: [NSLocalizedDescriptionKey: "EOF reading byte string"])
            }
            let bytes = Array(data[offset..<(offset + count)])
            offset += count
            return .byteString(bytes)
        case 3:
            guard let count = Int(exactly: length), count <= data.count - offset else {
                throw NSError(domain: "CBOR", code: 8, userInfo: [NSLocalizedDescriptionKey: "EOF reading text string"])
            }
            let bytes = Array(data[offset..<(offset + count)])
            offset += count
            guard let str = String(bytes: bytes, encoding: .utf8) else {
                throw NSError(domain: "CBOR", code: 9, userInfo: [NSLocalizedDescriptionKey: "Invalid UTF-8 in text string"])
            }
            return .textString(str)
        case 4:
            guard let count = Int(exactly: length), count <= data.count - offset else {
                throw NSError(domain: "CBOR", code: 11)
            }
            var arr = [CBORValue]()
            for _ in 0..<count {
                arr.append(try readValue(depth: depth + 1))
            }
            return .array(arr)
        case 5:
            guard let count = Int(exactly: length), count <= (data.count - offset) / 2 else {
                throw NSError(domain: "CBOR", code: 11)
            }
            var pairs = [(CBORValue, CBORValue)]()
            for _ in 0..<count {
                let k = try readValue(depth: depth + 1)
                let v = try readValue(depth: depth + 1)
                pairs.append((k, v))
            }
            return .map(pairs)
        case 7:
            if info == 20 { return .boolean(false) }
            if info == 21 { return .boolean(true) }
            if info == 22 { return .null }
            return .unsigned(length)
        default:
            throw NSError(domain: "CBOR", code: 10, userInfo: [NSLocalizedDescriptionKey: "Unsupported major type \(major)"])
        }
    }
}

public struct BiometricPrompt {
    public let localizedReason: String
    public let dJcs: [UInt8]
    public let nonce: [UInt8]
    public let tStartNs: UInt64
    public let bioKeyBlob: [UInt8]

    public static func decode(from bytes: [UInt8]) throws -> BiometricPrompt {
        var reader = CBORReader(data: bytes)
        let root = try reader.readValue()
        guard reader.offset == bytes.count, case .map(let pairs) = root else {
            throw NSError(domain: "BiometricPrompt", code: 1, userInfo: [NSLocalizedDescriptionKey: "Expected map"])
        }
        var reason: String?
        var djcs: [UInt8]?
        var non: [UInt8]?
        var tStart: UInt64?
        var keyBlob = [UInt8]()
        var seen = Set<String>()

        for (k, v) in pairs {
            guard case .textString(let keyName) = k, seen.insert(keyName).inserted else {
                throw NSError(domain: "BiometricPrompt", code: 3)
            }
            switch keyName {
            case "localized_reason":
                if case .textString(let s) = v { reason = s }
            case "d_jcs":
                if case .byteString(let b) = v { djcs = b }
            case "nonce":
                if case .byteString(let b) = v { non = b }
            case "t_start_ns":
                if case .unsigned(let u) = v { tStart = u }
            case "bio_key_blob":
                if case .byteString(let b) = v { keyBlob = b }
            default:
                throw NSError(domain: "BiometricPrompt", code: 4)
            }
        }
        guard let r = reason, !r.isEmpty, r.utf8.count <= 4096,
              let d = djcs, d.count == 32, let n = non, n.count == 32, let t = tStart else {
            throw NSError(domain: "BiometricPrompt", code: 2, userInfo: [NSLocalizedDescriptionKey: "Missing required prompt field"])
        }
        return BiometricPrompt(localizedReason: r, dJcs: d, nonce: n, tStartNs: t, bioKeyBlob: keyBlob)
    }

    public func signedMessage() -> [UInt8] {
        var msg = dJcs
        msg.append(contentsOf: nonce)
        var tBigEndian = tStartNs.bigEndian
        withUnsafeBytes(of: &tBigEndian) { bytes in
            msg.append(contentsOf: bytes)
        }
        return msg
    }
}

public enum BiometricOutcome: Equatable {
    case approved(
        sepSignature: [UInt8],
        visibleAtNs: UInt64,
        approvedAtNs: UInt64,
        enrolledPubkey: [UInt8]? = nil,
        enrolledBlob: [UInt8]? = nil
    )
    case cancelled
    case timedOut
    case occluded
    case reportSuspicious

    public func encode() -> [UInt8] {
        switch self {
        case .cancelled:
            return CBOREncoder.encodeText("Cancelled")
        case .timedOut:
            return CBOREncoder.encodeText("TimedOut")
        case .occluded:
            return CBOREncoder.encodeText("Occluded")
        case .reportSuspicious:
            return CBOREncoder.encodeText("ReportSuspicious")
        case .approved(let sepSignature, let visibleAtNs, let approvedAtNs, let enrolledPubkey, let enrolledBlob):
            var out = [UInt8]()
            out.append(0xa1) // map of 1
            out.append(contentsOf: CBOREncoder.encodeText("Approved"))
            if let pub = enrolledPubkey, let blob = enrolledBlob {
                out.append(0xa5) // map of 5
                // 1. approved_at_ns
                out.append(contentsOf: CBOREncoder.encodeText("approved_at_ns"))
                out.append(contentsOf: CBOREncoder.encodeUInt(approvedAtNs))
                // 2. enrolled_blob
                out.append(contentsOf: CBOREncoder.encodeText("enrolled_blob"))
                out.append(contentsOf: CBOREncoder.encodeBytes(blob))
                // 3. enrolled_pubkey
                out.append(contentsOf: CBOREncoder.encodeText("enrolled_pubkey"))
                out.append(contentsOf: CBOREncoder.encodeBytes(pub))
                // 4. sep_signature
                out.append(contentsOf: CBOREncoder.encodeText("sep_signature"))
                out.append(contentsOf: CBOREncoder.encodeBytes(sepSignature))
                // 5. visible_at_ns
                out.append(contentsOf: CBOREncoder.encodeText("visible_at_ns"))
                out.append(contentsOf: CBOREncoder.encodeUInt(visibleAtNs))
            } else {
                out.append(0xa3) // map of 3
                // 1. approved_at_ns
                out.append(contentsOf: CBOREncoder.encodeText("approved_at_ns"))
                out.append(contentsOf: CBOREncoder.encodeUInt(approvedAtNs))
                // 2. sep_signature
                out.append(contentsOf: CBOREncoder.encodeText("sep_signature"))
                out.append(contentsOf: CBOREncoder.encodeBytes(sepSignature))
                // 3. visible_at_ns
                out.append(contentsOf: CBOREncoder.encodeText("visible_at_ns"))
                out.append(contentsOf: CBOREncoder.encodeUInt(visibleAtNs))
            }
            return out
        }
    }
}
