import Foundation

public enum Entropy {
    /// Shannon entropy in bits per byte (0...8).
    public static func shannon(_ bytes: ArraySlice<UInt8>) -> Double {
        guard !bytes.isEmpty else { return 0 }
        var counts = [Int](repeating: 0, count: 256)
        for b in bytes { counts[Int(b)] += 1 }
        let total = Double(bytes.count)
        var h = 0.0
        for c in counts where c > 0 {
            let p = Double(c) / total
            h -= p * log2(p)
        }
        return h
    }

    public static func shannon(_ data: Data) -> Double { shannon([UInt8](data)[...]) }

    public struct SectionEntropy: Identifiable, Hashable {
        public let id = UUID()
        public let section: String
        public let size: UInt64
        public let entropy: Double
        public var packed: Bool { entropy > 7.2 && size > 4096 }
    }

    public static func sectionMap(file: MachOFile, bytes: [UInt8], maxSample: Int = 2 << 20) -> [SectionEntropy] {
        let r = ByteReader(bytes)
        var out: [SectionEntropy] = []
        for sec in file.allSections where sec.size > 0 && sec.offset > 0 {
            let len = min(Int(sec.size), maxSample)
            guard r.has(Int(sec.offset), len) else { continue }
            let h = shannon(bytes[Int(sec.offset)..<(Int(sec.offset) + len)])
            out.append(SectionEntropy(section: sec.display, size: sec.size, entropy: h))
        }
        return out.sorted { $0.entropy > $1.entropy }
    }
}

public struct StringHit: Identifiable, Hashable {
    public let id = UUID()
    public let value: String
    public let offset: Int
    public let category: String
    public let utf16: Bool
}

public enum StringsScan {
    public enum Category: String, CaseIterable {
        case url = "URL"
        case path = "路径"
        case email = "邮箱"
        case ip = "IP"
        case base64 = "Base64"
        case token = "疑似密钥"
        case other = "文本"
    }

    public static func extract(_ data: Data, minLength: Int = 6, limit: Int = 60_000) -> [StringHit] {
        let bytes = [UInt8](data)
        var hits: [StringHit] = []
        hits.reserveCapacity(min(limit, 20_000))
        var current: [UInt8] = []
        var start = 0

        func flush() {
            defer { current.removeAll(keepingCapacity: true) }
            guard current.count >= minLength, current.count <= 4096 else { return }
            let s = String(decoding: current, as: UTF8.self)
            guard looksMeaningful(s) else { return }
            hits.append(StringHit(value: s, offset: start, category: classify(s).rawValue, utf16: false))
        }

        for (i, b) in bytes.enumerated() {
            if b >= 32 && b < 127 {
                if current.isEmpty { start = i }
                current.append(b)
            } else {
                flush()
            }
            if hits.count >= limit { break }
        }
        flush()

        // UTF-16LE pass (Objective-C / CoreFoundation literals)
        if hits.count < limit {
            var i = 0
            while i + 3 < bytes.count {
                guard bytes[i] >= 32, bytes[i] < 127, bytes[i + 1] == 0 else { i += 1; continue }
                var chars: [UInt8] = []
                let s0 = i
                while i + 1 < bytes.count, bytes[i] >= 32, bytes[i] < 127, bytes[i + 1] == 0 {
                    chars.append(bytes[i]); i += 2
                }
                if chars.count >= minLength {
                    let s = String(decoding: chars, as: UTF8.self)
                    if looksMeaningful(s), !s.isEmpty {
                        hits.append(StringHit(value: s, offset: s0, category: classify(s).rawValue, utf16: true))
                    }
                }
                i += 1
            }
        }
        return hits
    }

    static func looksMeaningful(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        var printable = 0
        for u in s.unicodeScalars where u.value >= 32 { printable += 1 }
        let ratio = Double(printable) / Double(max(s.unicodeScalars.count, 1))
        return ratio > 0.9
    }

    public static func classify(_ s: String) -> Category {
        let lower = s.lowercased()
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") || lower.hasPrefix("ws://") || lower.hasPrefix("wss://") { return .url }
        if s.hasPrefix("/") || lower.contains("/library/") || lower.contains("/var/") || lower.contains(".dylib") { return .path }
        if s.contains("@") && s.contains(".") && !s.contains(" ") { return .email }
        if isIPv4(s) { return .ip }
        if s.count >= 24, s.allSatisfy({ $0.isLetter || $0.isNumber || "+/=".contains($0) }), s.contains("=") || s.count > 40 { return .base64 }
        if SecretScan.looksLikeSecret(s) { return .token }
        return .other
    }

    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in Int(p).map { (0...255).contains($0) && p.count <= 3 } ?? false }
    }

    public static func filter(_ hits: [StringHit], category: Category?) -> [StringHit] {
        guard let category = category else { return hits }
        return hits.filter { $0.category == category.rawValue }
    }
}
