import Foundation

public enum MachOError: Error, CustomStringConvertible {
    case empty
    case badMagic(UInt32)
    case truncated(String)

    public var description: String {
        switch self {
        case .empty: return "文件为空"
        case .badMagic(let m): return String(format: "不是 Mach-O 魔数: 0x%08x", m)
        case .truncated(let what): return "文件被截断: \(what)"
        }
    }
}

public enum MachOConstants {
    public static let MH_MAGIC: UInt32 = 0xfeed_face
    public static let MH_CIGAM: UInt32 = 0xcefa_edfe
    public static let MH_MAGIC_64: UInt32 = 0xfeed_facf
    public static let MH_CIGAM_64: UInt32 = 0xcffa_edfe
    public static let FAT_MAGIC: UInt32 = 0xcafe_babe
    public static let FAT_MAGIC_64: UInt32 = 0xcafe_babf
    public static let FAT_CIGAM: UInt32 = 0xbeba_feca
    public static let FAT_CIGAM_64: UInt32 = 0xbfba_feca
    // java class files share 0xcafebabe; Mach-O fat has small nfat_arch
    public static let maxFatArch = 64
}

public enum MachOParser {

    public static func parse(url: URL) throws -> MachOFile {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        var file = try parse(data: data)
        file.url = url
        return file
    }

    public static func parse(data: Data) throws -> MachOFile {
        guard !data.isEmpty else { throw MachOError.empty }
        let reader = ByteReader(data)
        var file = MachOFile()
        let magic = reader.u32(0)

        if magic == MachOConstants.FAT_MAGIC || magic == MachOConstants.FAT_MAGIC_64
            || magic == MachOConstants.FAT_CIGAM || magic == MachOConstants.FAT_CIGAM_64 {
            let is64 = magic == MachOConstants.FAT_MAGIC_64 || magic == MachOConstants.FAT_CIGAM_64
            let swapped = magic == MachOConstants.FAT_CIGAM || magic == MachOConstants.FAT_CIGAM_64
            let nfat = Int(swapped ? reader.be32(4) : reader.u32(4))
            guard nfat > 0, nfat <= MachOConstants.maxFatArch else { throw MachOError.truncated("fat_arch 数量异常") }
            let entrySize = is64 ? 32 : 20
            var slices: [SliceInfo] = []
            for i in 0..<nfat {
                let base = 8 + i * entrySize
                guard reader.has(base, entrySize) else { break }
                let cpu: UInt32
                let sub: UInt32
                let off: UInt32
                let size: UInt32
                if swapped {
                    cpu = reader.be32(base); sub = reader.be32(base + 4)
                    off = reader.be32(base + 8); size = reader.be32(base + 12)
                } else {
                    cpu = reader.u32(base); sub = reader.u32(base + 4)
                    off = reader.u32(base + 8); size = reader.u32(base + 12)
                }
                slices.append(SliceInfo(cpuType: cpu, cpuSubtype: sub, offset: Int(off), size: Int(size), isFat: true))
            }
            guard !slices.isEmpty else { throw MachOError.truncated("fat 无有效切片") }
            file.slices = slices
            let best = slices.max { $0.size < $1.size } ?? slices[0]
            var slice = try parseThin(reader.slice(best.offset, best.size))
            slice.url = nil
            slice.slices = slices
            return slice
        }

        var thin = try parseThin([UInt8](data))
        thin.slices = [SliceInfo(cpuType: thin.header.cpuType, cpuSubtype: thin.header.cpuSubtype,
                                 offset: 0, size: data.count, isFat: false)]
        return thin
    }

    static func parseThin(_ bytes: [UInt8]) throws -> MachOFile {
        let r = ByteReader(bytes)
        guard r.count >= 28 else { throw MachOError.truncated("header") }
        let magic = r.u32(0)
        guard magic == MachOConstants.MH_MAGIC || magic == MachOConstants.MH_MAGIC_64 else {
            throw MachOError.badMagic(magic)
        }
        let is64 = magic == MachOConstants.MH_MAGIC_64
        var file = MachOFile()
        var h = MachOHeaderInfo()
        h.is64 = is64
        h.cpuType = r.u32(4)
        h.cpuSubtype = r.u32(8)
        h.fileType = r.u32(12)
        h.ncmds = r.u32(16)
        h.sizeofcmds = r.u32(20)
        h.flags = r.u32(24)
        h.headerSize = is64 ? 32 : 28
        file.header = h

        var offset = h.headerSize
        var commands: [LoadCommandInfo] = []
        var segments: [SegmentInfo] = []
        var dylibs: [LinkedLibInfo] = []
        var rpaths: [String] = []

        for idx in 0..<Int(h.ncmds) {
            guard r.has(offset, 8) else { break }
            let cmd = r.u32(offset)
            let size = r.u32(offset + 4)
            guard size >= 8, r.has(offset, Int(size)) else { break }
            let detail = describe(cmd: cmd, at: offset, r: r, is64: is64, header: &h)
            commands.append(LoadCommandInfo(index: idx, cmd: cmd, size: size,
                                            offset: UInt64(offset), detail: detail))
            switch cmd {
            case 0x1 where !is64, 0x19 where is64:
                if let seg = parseSegment(r, at: offset, is64: is64) {
                    segments.append(seg)
                }
            case 0xC, 0xD, 0x8000_0018, 0x8000_001F, 0x20, 0x8000_0023:
                let nameOff = r.u32(offset + 8)
                let name = r.cString(offset + Int(nameOff))
                let kind: String
                switch cmd {
                case 0xC: kind = "load"
                case 0xD: kind = "id"
                case 0x8000_0018: kind = "weak"
                case 0x8000_001F: kind = "reexport"
                case 0x8000_0023: kind = "upward"
                default: kind = "lazy"
                }
                dylibs.append(LinkedLibInfo(path: name, kind: kind,
                                            currentVersion: MachOName.version(r.u32(offset + 12)),
                                            compatibilityVersion: MachOName.version(r.u32(offset + 16))))
            case 0x8000_001C:
                let nameOff = r.u32(offset + 8)
                rpaths.append(r.cString(offset + Int(nameOff)))
            case 0x2:
                let symoff = Int(r.u32(offset + 8))
                let nsyms = Int(r.u32(offset + 12))
                let stroff = Int(r.u32(offset + 16))
                let strsize = Int(r.u32(offset + 20))
                file.symbols = parseSymbols(r, symoff: symoff, nsyms: nsyms, stroff: stroff,
                                            strsize: strsize, startIndex: symoff, is64: is64, segs: segments)
                file.stringTableCount = strsize
            default:
                break
            }
            offset += Int(size)
        }

        // second pass: symbols may be parsed before segments are all known -> rerun if needed
        if file.symbols.isEmpty {
            for cmd in commands where cmd.cmd == 0x2 {
                let base = Int(cmd.offset)
                let symoff = Int(r.u32(base + 8))
                let nsyms = Int(r.u32(base + 12))
                let stroff = Int(r.u32(base + 16))
                let strsize = Int(r.u32(base + 20))
                file.symbols = parseSymbols(r, symoff: symoff, nsyms: nsyms, stroff: stroff,
                                            strsize: strsize, startIndex: symoff, is64: is64, segs: segments)
            }
        }

        file.header = h
        file.commands = commands
        file.segments = segments
        file.dylibs = dylibs
        file.rpaths = rpaths
        return file
    }

    static func parseSymbols(_ r: ByteReader, symoff: Int, nsyms: Int, stroff: Int, strsize: Int,
                             startIndex: Int, is64: Bool, segs: [SegmentInfo]) -> [SymbolInfo] {
        guard symoff > 0, nsyms > 0, r.has(symoff, min(nsyms, 1_000_000) * (is64 ? 16 : 12)),
              r.has(stroff, min(strsize, 64 * 1024 * 1024)) else { return [] }
        let count = min(nsyms, 200_000)
        var out: [SymbolInfo] = []
        out.reserveCapacity(count)
        let entry = is64 ? 16 : 12
        for i in 0..<count {
            let base = symoff + i * entry
            let strx = Int(r.u32(base))
            let type = r.u8(base + 4)
            let sect = r.u8(base + 5)
            let desc = r.u16(base + 6)
            let value: UInt64 = is64 ? r.u64(base + 8) : UInt64(r.u32(base + 8))
            let name = r.cString(stroff + strx, limit: 2048)
            if name.isEmpty { continue }
            let external = (type & 0x01) != 0
            let undefined = (type & 0x0E) == 0
            out.append(SymbolInfo(name: name, value: value, sect: sect, desc: desc,
                                  external: external, undefined: undefined))
        }
        return out
    }

    static func parseSegment(_ r: ByteReader, at off: Int, is64: Bool) -> SegmentInfo? {
        let name = r.cString(off + 8, limit: 16)
        if is64 {
            let vmaddr = r.u64(off + 24)
            let vmsize = r.u64(off + 32)
            let fileoff = r.u64(off + 40)
            let filesize = r.u64(off + 48)
            let maxprot = r.i32(off + 56)
            let initprot = r.i32(off + 60)
            let nsects = Int(r.u32(off + 64))
            var sections: [SectionInfo] = []
            var p = off + 72
            for i in 0..<min(nsects, 4000) {
                guard r.has(p, 80) else { break }
                let sectname = r.cString(p, limit: 16)
                let segname = r.cString(p + 16, limit: 16)
                sections.append(SectionInfo(index: i, segname: segname, name: sectname,
                                            addr: r.u64(p + 32), size: r.u64(p + 40),
                                            offset: r.u32(p + 48), alignment: r.u32(p + 52),
                                            flags: r.u32(p + 64)))
                p += 80
            }
            return SegmentInfo(name: name, vmaddr: vmaddr, vmsize: vmsize, fileoff: fileoff,
                               filesize: filesize, maxprot: maxprot, initprot: initprot, sections: sections)
        } else {
            let vmaddr = UInt64(r.u32(off + 24))
            let vmsize = UInt64(r.u32(off + 28))
            let fileoff = UInt64(r.u32(off + 32))
            let filesize = UInt64(r.u32(off + 36))
            let maxprot = r.i32(off + 40)
            let initprot = r.i32(off + 44)
            let nsects = Int(r.u32(off + 48))
            var sections: [SectionInfo] = []
            var p = off + 56
            for i in 0..<min(nsects, 4000) {
                guard r.has(p, 68) else { break }
                sections.append(SectionInfo(index: i, segname: r.cString(p + 16, limit: 16),
                                            name: r.cString(p, limit: 16),
                                            addr: UInt64(r.u32(p + 32)), size: UInt64(r.u32(p + 36)),
                                            offset: r.u32(p + 40), alignment: r.u32(p + 44),
                                            flags: r.u32(p + 56)))
                p += 68
            }
            return SegmentInfo(name: name, vmaddr: vmaddr, vmsize: vmsize, fileoff: fileoff,
                               filesize: filesize, maxprot: maxprot, initprot: initprot, sections: sections)
        }
    }

    static func describe(cmd: UInt32, at off: Int, r: ByteReader, is64: Bool,
                         header: inout MachOHeaderInfo) -> String {
        switch cmd {
        case 0x1B:
            header.uuid = MachOName.uuid(r.slice(off + 8, 16))
            return header.uuid
        case 0x32:
            let platform = r.u32(off + 8)
            header.platform = MachOName.platform(platform)
            header.minOS = MachOName.version(r.u32(off + 12))
            header.sdk = MachOName.version(r.u32(off + 16))
            let ntools = r.u32(off + 20)
            if ntools > 0 {
                let tool = r.u32(off + 24)
                let ver = MachOName.version(r.u32(off + 28))
                header.buildTool = "tool \(tool) \(ver)"
            }
            return "\(header.platform) min=\(header.minOS) sdk=\(header.sdk)"
        case 0x25, 0x24, 0x2F, 0x30:
            header.minOS = MachOName.version(r.u32(off + 8))
            header.sdk = MachOName.version(r.u32(off + 12))
            header.platform = header.platform.isEmpty ? MachOName.loadCommand(cmd) : header.platform
            return "min=\(header.minOS) sdk=\(header.sdk)"
        case 0x21, 0x2C:
            header.cryptoff = r.u32(off + 8)
            header.cryptsize = r.u32(off + 12)
            header.cryptid = r.u32(off + 16)
            return "cryptoff=\(header.cryptoff) cryptsize=\(header.cryptsize) cryptid=\(header.cryptid)"
        case 0x8000_0028:
            let entry = r.u64(off + 8)
            header.entryPoint = entry
            return String(format: "entryoff=0x%llx stacksize=0x%llx", entry, r.u64(off + 16))
        case 0x2A:
            let v = r.u64(off + 8)
            header.sourceVersion = "\(v >> 40).\((v >> 30) & 0x3FF).\((v >> 20) & 0x3FF).\((v >> 10) & 0x3FF).\(v & 0x3FF)"
            return header.sourceVersion ?? ""
        case 0x8000_0034:
            header.hasChainedFixups = true
            return "dataoff=\(r.u32(off + 8)) datasize=\(r.u32(off + 12))"
        case 0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x8000_0033, 0x22, 0x8000_0022:
            return "dataoff=\(r.u32(off + 8)) datasize=\(r.u32(off + 12))"
        case 0x19, 0x1:
            return r.cString(off + 8, limit: 16) + " nsects=\(r.u32(off + (is64 ? 64 : 48)))"
        case 0xC, 0xD, 0x8000_0018, 0x8000_001F, 0x20, 0x8000_0023, 0x8000_001C:
            return r.cString(off + Int(r.u32(off + 8)))
        case 0xB:
            return "nlocalsym=\(r.u32(off + 8)) nextdefsym=\(r.u32(off + 12)) nundefsym=\(r.u32(off + 24))"
        case 0x2:
            return "nsyms=\(r.u32(off + 12)) strsize=\(r.u32(off + 20))"
        default:
            return "size=\(r.u32(off + 4))"
        }
    }
}
