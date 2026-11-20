import Darwin
import Foundation

/// Foundation validates JSON syntax/UTF8. This bounded grammar walk separately
/// rejects duplicate names (including escaped aliases) in every nested object.
enum StrictJSONMembers {
    private struct Scanner {
        var bytes: [UInt8]
        var offset = 0
        mutating func wipe() { _ = bytes.withUnsafeMutableBytes { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        mutating func spaces() {
            while offset < bytes.count && [UInt8(9), 10, 13, 32].contains(bytes[offset]) { offset += 1 }
        }
        mutating func take(_ byte: UInt8) throws {
            spaces(); guard offset < bytes.count, bytes[offset] == byte else { throw BrokerFailure.refused }; offset += 1
        }
        mutating func string() throws -> Range<Int> {
            spaces(); let start = offset; try take(34)
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 34 { return start..<offset }
                guard byte >= 32 else { throw BrokerFailure.refused }
                if byte == 92 {
                    guard offset < bytes.count else { throw BrokerFailure.refused }
                    let escaped = bytes[offset]; offset += 1
                    if escaped == 117 {
                        guard offset + 4 <= bytes.count,
                              bytes[offset..<(offset + 4)].allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else { throw BrokerFailure.refused }
                        offset += 4
                    } else if ![UInt8(34), 47, 92, 98, 102, 110, 114, 116].contains(escaped) { throw BrokerFailure.refused }
                }
            }
            throw BrokerFailure.refused
        }
        mutating func value(_ depth: Int) throws {
            guard depth <= 16 else { throw BrokerFailure.refused }
            spaces(); guard offset < bytes.count else { throw BrokerFailure.refused }
            switch bytes[offset] {
            case 123:
                offset += 1; spaces(); var seen = Set<String>()
                if offset < bytes.count && bytes[offset] == 125 { offset += 1; return }
                while true {
                    let range = try string()
                    guard let key = try JSONSerialization.jsonObject(with: Data(bytes[range]), options: [.fragmentsAllowed]) as? String,
                          seen.insert(key).inserted else { throw BrokerFailure.refused }
                    try take(58); try value(depth + 1); spaces()
                    guard offset < bytes.count else { throw BrokerFailure.refused }
                    if bytes[offset] == 125 { offset += 1; return }
                    try take(44)
                }
            case 91:
                offset += 1; spaces()
                if offset < bytes.count && bytes[offset] == 93 { offset += 1; return }
                while true {
                    try value(depth + 1); spaces()
                    guard offset < bytes.count else { throw BrokerFailure.refused }
                    if bytes[offset] == 93 { offset += 1; return }
                    try take(44)
                }
            case 34: _ = try string()
            default:
                let start = offset
                while offset < bytes.count && ![UInt8(9), 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
                guard offset > start else { throw BrokerFailure.refused }
                // Complete scalar grammar is checked here as well as at root.
                _ = try JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: [.fragmentsAllowed])
            }
        }
    }
    static func check(_ data: Data) throws {
        guard !data.isEmpty, data.count <= 32768 else { throw BrokerFailure.refused }
        _ = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        var scanner = Scanner(bytes: Array(data))
        defer { scanner.wipe() }
        try scanner.value(0); scanner.spaces()
        guard scanner.offset == scanner.bytes.count else { throw BrokerFailure.refused }
    }
}
