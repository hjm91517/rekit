import Foundation

public enum PlistTools {
    public static func load(url: URL) -> Any? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return load(data: data)
    }

    public static func load(data: Data) -> Any? {
        if let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) {
            return obj
        }
        return try? JSONSerialization.jsonObject(with: data)
    }

    public static func loadDictionary(url: URL) -> [String: Any]? {
        load(url: url) as? [String: Any]
    }

    /// Pretty, stable rendering for any plist/json value.
    public static func display(_ value: Any, indent: Int = 0) -> String {
        let pad = String(repeating: "  ", count: indent)
        if let dict = value as? [String: Any] {
            return dict.keys.sorted().map { key -> String in
                let v = dict[key]!
                if v is [String: Any] || v is [Any] {
                    return "\(pad)\(key):\n\(display(v, indent: indent + 1))"
                }
                return "\(pad)\(key): \(scalar(v))"
            }.joined(separator: "\n")
        }
        if let arr = value as? [Any] {
            return arr.enumerated().map { idx, v in
                if v is [String: Any] || v is [Any] {
                    return "\(pad)[\(idx)]:\n\(display(v, indent: indent + 1))"
                }
                return "\(pad)[\(idx)]: \(scalar(v))"
            }.joined(separator: "\n")
        }
        return pad + scalar(value)
    }

    static func scalar(_ v: Any) -> String {
        if let d = v as? Data { return "<data \(d.count) bytes>" }
        if let date = v as? Date { return ISO8601DateFormatter().string(from: date) }
        if let b = v as? Bool { return b ? "true" : "false" }
        return "\(v)"
    }

    public static func flatten(_ value: Any, prefix: String = "") -> [(String, String)] {
        if let dict = value as? [String: Any] {
            return dict.keys.sorted().flatMap { key -> [(String, String)] in
                let path = prefix.isEmpty ? key : "\(prefix).\(key)"
                return flatten(dict[key]!, prefix: path)
            }
        }
        if let arr = value as? [Any] {
            return arr.enumerated().flatMap { idx, v in flatten(v, prefix: "\(prefix)[\(idx)]") }
        }
        return [(prefix, scalar(value))]
    }
}

public enum Entitlements {
    /// Extracts the embedded entitlements plist from the code-signature blob.
    /// `bytes` must be the same slice the MachOFile was parsed from.
    public static func extract(file: MachOFile, bytes: [UInt8]) -> [String: Any]? {
        guard let sig = file.commands.first(where: { $0.cmd == 0x1D }) else { return nil }
        let r = ByteReader(bytes)
        let cmdOff = Int(sig.offset)
        guard r.has(cmdOff, 16) else { return nil }
        let dataoff = Int(r.u32(cmdOff + 8))
        let datasize = Int(r.u32(cmdOff + 12))
        guard dataoff > 0, datasize > 0, bytes.count >= dataoff + datasize else { return nil }
        let blob = Array(bytes[dataoff..<(dataoff + datasize)])
        guard let start = findSequence(blob, Array("<plist".utf8)) else { return nil }
        guard let end = findSequence(blob, Array("</plist>".utf8), from: start) else { return nil }
        let xml = Data(blob[start..<(end + 8)])
        return PlistTools.load(data: xml) as? [String: Any]
    }

    static func findSequence(_ haystack: [UInt8], _ needle: [UInt8], from: Int = 0) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        let limit = haystack.count - needle.count
        var i = max(0, from)
        while i <= limit {
            if haystack[i] == needle[0] {
                var ok = true
                for j in 1..<needle.count where haystack[i + j] != needle[j] { ok = false; break }
                if ok { return i }
            }
            i += 1
        }
        return nil
    }
}
