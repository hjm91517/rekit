import Foundation

/// Bounds-checked little-endian reader over a byte buffer.
public struct ByteReader {
    public let bytes: [UInt8]

    public init(_ data: Data) { bytes = [UInt8](data) }
    public init(_ bytes: [UInt8]) { self.bytes = bytes }

    public var count: Int { bytes.count }
    public var isEmpty: Bool { bytes.isEmpty }

    public func has(_ off: Int, _ len: Int) -> Bool {
        off >= 0 && len >= 0 && off <= bytes.count && len <= bytes.count - off
    }

    public func u8(_ off: Int) -> UInt8 {
        guard has(off, 1) else { return 0 }
        return bytes[off]
    }

    public func u16(_ off: Int) -> UInt16 {
        guard has(off, 2) else { return 0 }
        return UInt16(bytes[off]) | (UInt16(bytes[off + 1]) << 8)
    }

    public func u32(_ off: Int) -> UInt32 {
        guard has(off, 4) else { return 0 }
        return UInt32(bytes[off]) | (UInt32(bytes[off + 1]) << 8)
            | (UInt32(bytes[off + 2]) << 16) | (UInt32(bytes[off + 3]) << 24)
    }

    public func u64(_ off: Int) -> UInt64 {
        guard has(off, 8) else { return 0 }
        var v: UInt64 = 0
        for i in (0..<8).reversed() { v = (v << 8) | UInt64(bytes[off + i]) }
        return v
    }

    public func i32(_ off: Int) -> Int32 { Int32(bitPattern: u32(off)) }
    public func i64(_ off: Int) -> Int64 { Int64(bitPattern: u64(off)) }
    public func be32(_ off: Int) -> UInt32 {
        guard has(off, 4) else { return 0 }
        return (UInt32(bytes[off]) << 24) | (UInt32(bytes[off + 1]) << 16)
            | (UInt32(bytes[off + 2]) << 8) | UInt32(bytes[off + 3])
    }

    public func slice(_ off: Int, _ len: Int) -> [UInt8] {
        guard has(off, len) else { return [] }
        return Array(bytes[off..<(off + len)])
    }

    public func data(_ off: Int, _ len: Int) -> Data { Data(slice(off, len)) }

    /// NUL-terminated C string, tolerant of bad offsets.
    public func cString(_ off: Int, limit: Int = 4096) -> String {
        guard off >= 0, off < bytes.count else { return "" }
        var out = [UInt8]()
        var i = off
        let end = min(bytes.count, off + limit)
        while i < end, bytes[i] != 0 {
            out.append(bytes[i])
            i += 1
        }
        return String(decoding: out, as: UTF8.self)
    }

    public func hex(_ off: Int, _ len: Int) -> String {
        slice(off, len).map { String(format: "%02x", $0) }.joined()
    }

    public func ascii(_ off: Int, _ len: Int) -> String {
        slice(off, len).map { ($0 >= 32 && $0 < 127) ? Character(UnicodeScalar($0)) : "." }.reduce(into: "") { $0.append($1) }
    }
}

public enum HexDump {
    public static func lines(_ data: Data, baseOffset: Int = 0, maxBytes: Int = 1 << 20) -> [String] {
        let bytes = [UInt8](data.prefix(maxBytes))
        var out: [String] = []
        out.reserveCapacity(bytes.count / 16 + 1)
        var i = 0
        while i < bytes.count {
            let chunk = Array(bytes[i..<min(i + 16, bytes.count)])
            let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
            let pad = String(repeating: " ", count: (16 - chunk.count) * 3)
            let ascii = chunk.map { ($0 >= 32 && $0 < 127) ? Character(UnicodeScalar($0)) : "." }
            out.append(String(format: "%08x", baseOffset + i) + "  " + hex + pad + "  |" + String(ascii) + "|")
            i += 16
        }
        return out
    }
}
