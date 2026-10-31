import Foundation

public struct ZipEntry: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let method: UInt16
    public let crc32: UInt32
    public let compressedSize: Int
    public let uncompressedSize: Int
    public let headerOffset: Int
    public var isDirectory: Bool { name.hasSuffix("/") }
    public var isDeflate: Bool { method == 8 }
}

public enum ZipError: Error, CustomStringConvertible {
    case noCentralDirectory
    case badLocalHeader
    case unsupportedMethod(UInt16)
    case truncated

    public var description: String {
        switch self {
        case .noCentralDirectory: return "找不到 ZIP 中央目录（EOCD）"
        case .badLocalHeader: return "本地文件头损坏"
        case .unsupportedMethod(let m): return "不支持压缩方式 \(m)"
        case .truncated: return "数据被截断"
        }
    }
}

public struct ZipArchive {
    public let data: Data
    public let entries: [ZipEntry]
    let cdOffset: Int

    public init(data: Data) throws {
        self.data = data
        let r = ByteReader(data)
        guard r.count > 22 else { throw ZipError.noCentralDirectory }

        var eocd = -1
        var i = r.count - 22
        let lowerBound = max(0, r.count - 22 - 65535)
        while i >= lowerBound {
            if r.u32(i) == 0x0605_4b50 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw ZipError.noCentralDirectory }

        let count = Int(r.u16(eocd + 10))
        let cdSize = Int(r.u32(eocd + 12))
        let cdStart = Int(r.u32(eocd + 16))
        guard cdStart > 0, cdStart + cdSize <= r.count else { throw ZipError.truncated }
        self.cdOffset = cdStart

        var list: [ZipEntry] = []
        var p = cdStart
        for _ in 0..<max(count, 0) {
            guard r.u32(p) == 0x0201_4b50 else { break }
            let method = r.u16(p + 10)
            let crc = r.u32(p + 16)
            let csize = Int(r.u32(p + 20))
            let usize = Int(r.u32(p + 24))
            let nameLen = Int(r.u16(p + 28))
            let extraLen = Int(r.u16(p + 30))
            let commentLen = Int(r.u16(p + 32))
            let localOffset = Int(r.u32(p + 42))
            let name = String(decoding: r.slice(p + 46, nameLen), as: UTF8.self)
            list.append(ZipEntry(name: name, method: method, crc32: crc,
                                 compressedSize: csize, uncompressedSize: usize,
                                 headerOffset: localOffset))
            p += 46 + nameLen + extraLen + commentLen
        }
        guard !list.isEmpty else { throw ZipError.noCentralDirectory }
        self.entries = list
    }

    public func read(_ entry: ZipEntry) throws -> Data {
        let r = ByteReader(data)
        let h = entry.headerOffset
        guard r.u32(h) == 0x0403_4b50 else { throw ZipError.badLocalHeader }
        let nameLen = Int(r.u16(h + 26))
        let extraLen = Int(r.u16(h + 28))
        let start = h + 30 + nameLen + extraLen
        guard start + entry.compressedSize <= r.count else { throw ZipError.truncated }
        let payload = data.subdata(in: start..<(start + entry.compressedSize))
        switch entry.method {
        case 0:
            return payload
        case 8:
            guard let out = REKInflateRaw(payload, UInt(entry.uncompressedSize)) else {
                throw ZipError.unsupportedMethod(8)
            }
            return out
        default:
            throw ZipError.unsupportedMethod(entry.method)
        }
    }

    /// Extracts everything under `prefix` into `directory`, returning written file URLs.
    @discardableResult
    public func extract(to directory: URL, prefix: String = "") throws -> [URL] {
        let fm = FileManager.default
        var written: [URL] = []
        for entry in entries {
            guard entry.name.hasPrefix(prefix) || prefix.isEmpty else { continue }
            let target = directory.appendingPathComponent(entry.name)
            if entry.isDirectory {
                try? fm.createDirectory(at: target, withIntermediateDirectories: true)
                continue
            }
            let parent = target.deletingLastPathComponent()
            try? fm.createDirectory(at: parent, withIntermediateDirectories: true)
            do {
                let content = try read(entry)
                try content.write(to: target, options: .atomic)
                written.append(target)
            } catch {
                continue
            }
        }
        return written
    }

    /// Finds the main .app bundle path prefix inside an IPA.
    public func appBundlePath() -> String? {
        for entry in entries where entry.name.hasPrefix("Payload/") && entry.name.contains(".app/") {
            let comps = entry.name.split(separator: "/")
            guard comps.count >= 2 else { continue }
            return "Payload/\(comps[1])/"
        }
        return nil
    }
}
