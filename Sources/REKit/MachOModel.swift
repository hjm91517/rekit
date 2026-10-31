import Foundation

public enum MachOName {
    public static func arch(_ cpuType: UInt32, _ subtype: UInt32 = 0) -> String {
        switch cpuType {
        case 7: return "i386"
        case 0x0100_0007: return "x86_64"
        case 12: return "arm"
        case 0x0100_000C: return subtype == 2 ? "arm64e" : "arm64"
        case 0x0200_000C: return "arm64_32"
        default: return String(format: "cpu_0x%x", cpuType)
        }
    }

    public static func fileType(_ t: UInt32) -> String {
        switch t {
        case 1: return "MH_OBJECT"
        case 2: return "MH_EXECUTE"
        case 3: return "MH_FVMLIB"
        case 4: return "MH_CORE"
        case 5: return "MH_PRELOAD"
        case 6: return "MH_DYLIB"
        case 7: return "MH_DYLINKER"
        case 8: return "MH_BUNDLE"
        case 9: return "MH_DYLIB_STUB"
        case 10: return "MH_DSYM"
        case 11: return "MH_KEXT_BUNDLE"
        case 12: return "MH_FILESET"
        default: return "MH_UNKNOWN(\(t))"
        }
    }

    public static func flags(_ f: UInt32) -> [String] {
        let table: [(UInt32, String)] = [
            (0x0000_0001, "MH_NOUNDEFS"), (0x0000_0002, "MH_INCRLINK"),
            (0x0000_0004, "MH_DYLDLINK"), (0x0000_0008, "MH_BINDATLOAD"),
            (0x0000_0010, "MH_PREBOUND"), (0x0000_0020, "MH_SPLIT_SEGS"),
            (0x0000_0080, "MH_TWOLEVEL"), (0x0000_0100, "MH_FORCE_FLAT"),
            (0x0000_2000, "MH_SUBSECTIONS_VIA_SYMBOLS"), (0x0000_8000, "MH_DEAD_STRIPPABLE_DYLIB"),
            (0x0001_0000, "MH_HAS_TLV_DESCRIPTORS"), (0x0002_0000, "MH_NO_HEAP_EXECUTION"),
            (0x0020_0000, "MH_PIE"), (0x0040_0000, "MH_LOAD_DYLIB_PREBOUND"),
            (0x0080_0000, "MH_NOMULTIDEFS"), (0x0200_0000, "MH_APP_EXTENSION_SAFE"),
            (0x0400_0000, "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO"), (0x0800_0000, "MH_SIM_SUPPORT"),
            (0x8000_0000, "MH_DYLIB_IN_CACHE"),
        ]
        var out = table.filter { (f & $0.0) != 0 }.map { $0.1 }
        if (f & 0x0000_0010) != 0 && (f & 0x0000_0020) != 0 { out.append("MH_FIXVM64") }
        return out
    }

    public static func loadCommand(_ cmd: UInt32) -> String {
        switch cmd {
        case 0x1: return "LC_SEGMENT"
        case 0x2: return "LC_SYMTAB"
        case 0x3: return "LC_SYMSEG"
        case 0x4: return "LC_THREAD"
        case 0x5: return "LC_UNIXTHREAD"
        case 0x6: return "LC_LOADFVMLIB"
        case 0x7: return "LC_IDFVMLIB"
        case 0x8: return "LC_IDENT"
        case 0x9: return "LC_FVMFILE"
        case 0xA: return "LC_PREPAGE"
        case 0xB: return "LC_DYSYMTAB"
        case 0xC: return "LC_LOAD_DYLIB"
        case 0xD: return "LC_ID_DYLIB"
        case 0xE: return "LC_LOAD_DYLINKER"
        case 0xF: return "LC_ID_DYLINKER"
        case 0x10: return "LC_PREBOUND_DYLIB"
        case 0x11: return "LC_ROUTINES"
        case 0x12: return "LC_SUB_FRAMEWORK"
        case 0x13: return "LC_SUB_UMBRELLA"
        case 0x14: return "LC_SUB_CLIENT"
        case 0x15: return "LC_SUB_LIBRARY"
        case 0x16: return "LC_TWOLEVEL_HINTS"
        case 0x17: return "LC_PREBIND_CKSUM"
        case 0x8000_0018: return "LC_LOAD_WEAK_DYLIB"
        case 0x19: return "LC_SEGMENT_64"
        case 0x1A: return "LC_ROUTINES_64"
        case 0x1B: return "LC_UUID"
        case 0x8000_001C: return "LC_RPATH"
        case 0x1D: return "LC_CODE_SIGNATURE"
        case 0x1E: return "LC_SEGMENT_SPLIT_INFO"
        case 0x8000_001F: return "LC_REEXPORT_DYLIB"
        case 0x20: return "LC_LAZY_LOAD_DYLIB"
        case 0x21: return "LC_ENCRYPTION_INFO"
        case 0x22: return "LC_DYLD_INFO"
        case 0x8000_0022: return "LC_DYLD_INFO_ONLY"
        case 0x8000_0023: return "LC_LOAD_UPWARD_DYLIB"
        case 0x24: return "LC_VERSION_MIN_MACOSX"
        case 0x25: return "LC_VERSION_MIN_IPHONEOS"
        case 0x26: return "LC_FUNCTION_STARTS"
        case 0x27: return "LC_DYLD_ENVIRONMENT"
        case 0x8000_0028: return "LC_MAIN"
        case 0x29: return "LC_DATA_IN_CODE"
        case 0x2A: return "LC_SOURCE_VERSION"
        case 0x2B: return "LC_DYLIB_CODE_SIGN_DRS"
        case 0x2C: return "LC_ENCRYPTION_INFO_64"
        case 0x2D: return "LC_LINKER_OPTION"
        case 0x2E: return "LC_LINKER_OPTIMIZATION_HINT"
        case 0x2F: return "LC_VERSION_MIN_TVOS"
        case 0x30: return "LC_VERSION_MIN_WATCHOS"
        case 0x31: return "LC_NOTE"
        case 0x32: return "LC_BUILD_VERSION"
        case 0x8000_0033: return "LC_DYLD_EXPORTS_TRIE"
        case 0x8000_0034: return "LC_DYLD_CHAINED_FIXUPS"
        case 0x35: return "LC_FILESET_ENTRY"
        default: return String(format: "LC_0x%x", cmd)
        }
    }

    public static func protection(_ prot: Int32) -> String {
        var s = ""
        s += (prot & 1) != 0 ? "r" : "-"
        s += (prot & 2) != 0 ? "w" : "-"
        s += (prot & 4) != 0 ? "x" : "-"
        return s
    }

    public static func version(_ v: UInt32) -> String {
        "\(v >> 16).\((v >> 8) & 0xFF).\(v & 0xFF)"
    }

    public static func platform(_ p: UInt32) -> String {
        switch p {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 5: return "bridgeOS"
        case 6: return "Mac Catalyst"
        case 7: return "iOS Simulator"
        case 8: return "tvOS Simulator"
        case 9: return "watchOS Simulator"
        case 10: return "DriverKit"
        case 11: return "visionOS"
        default: return "platform_\(p)"
        }
    }

    public static func uuid(_ bytes: [UInt8]) -> String {
        guard bytes.count >= 16 else { return "" }
        let hex = bytes.prefix(16).map { String(format: "%02X", $0) }.joined()
        let idx = hex.index(hex.startIndex, offsetBy: 8)
        let i2 = hex.index(hex.startIndex, offsetBy: 12)
        let i3 = hex.index(hex.startIndex, offsetBy: 16)
        let i4 = hex.index(hex.startIndex, offsetBy: 20)
        return "\(hex[hex.startIndex..<idx])-\(hex[idx..<i2])-\(hex[i2..<i3])-\(hex[i3..<i4])-\(hex[i4...])"
    }
}

public struct SliceInfo: Identifiable, Hashable {
    public let id = UUID()
    public let cpuType: UInt32
    public let cpuSubtype: UInt32
    public let offset: Int
    public let size: Int
    public let isFat: Bool
    public var arch: String { MachOName.arch(cpuType, cpuSubtype) }
}

public struct SectionInfo: Identifiable, Hashable {
    public let id = UUID()
    public let index: Int
    public let segname: String
    public let name: String
    public let addr: UInt64
    public let size: UInt64
    public let offset: UInt32
    public let alignment: UInt32
    public let flags: UInt32
    public var typeName: String {
        switch flags & 0xFF {
        case 0x0: return "S_REGULAR"
        case 0x1: return "S_ZEROFILL"
        case 0x2: return "S_CSTRING_LITERALS"
        case 0x3: return "S_4BYTE_LITERALS"
        case 0x4: return "S_8BYTE_LITERALS"
        case 0x5: return "S_LITERAL_POINTERS"
        case 0x6: return "S_NON_LAZY_SYMBOL_POINTERS"
        case 0x7: return "S_LAZY_SYMBOL_POINTERS"
        case 0x8: return "S_SYMBOL_STUBS"
        case 0x9: return "S_MOD_INIT_FUNC_POINTERS"
        case 0xB: return "S_COALESCED"
        case 0xC: return "S_GB_ZEROFILL"
        case 0xD: return "S_INTERPOSING"
        case 0xF: return "S_DTRACE_DOF"
        case 0x10: return "S_LAZY_DYLIB_SYMBOL_POINTERS"
        case 0x13: return "S_THREAD_LOCAL_VARIABLES"
        case 0x14: return "S_THREAD_LOCAL_VARIABLE_POINTERS"
        case 0x15: return "S_LOCAL_RELOCS"
        default: return String(format: "section_type_0x%x", flags & 0xFF)
        }
    }
    public var display: String { "\(segname),\(name)" }
}

public struct SegmentInfo: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let vmaddr: UInt64
    public let vmsize: UInt64
    public let fileoff: UInt64
    public let filesize: UInt64
    public let maxprot: Int32
    public let initprot: Int32
    public let sections: [SectionInfo]
    public var prot: String { MachOName.protection(initprot) + "/" + MachOName.protection(maxprot) }
}

public struct LoadCommandInfo: Identifiable, Hashable {
    public let id = UUID()
    public let index: Int
    public let cmd: UInt32
    public let size: UInt32
    public let offset: UInt64
    public let detail: String
    public var name: String { MachOName.loadCommand(cmd) }
}

public struct LinkedLibInfo: Identifiable, Hashable {
    public let id = UUID()
    public let path: String
    public let kind: String
    public let currentVersion: String
    public let compatibilityVersion: String
}

public struct SymbolInfo: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let value: UInt64
    public let sect: UInt8
    public let desc: UInt16
    public let external: Bool
    public let undefined: Bool
    public var kind: String {
        if undefined { return external ? "import" : "undef" }
        return external ? "export" : "local"
    }
    public var display: String {
        String(format: "0x%llx", value) + "  " + name
    }
}

public struct MachOHeaderInfo: Hashable {
    public var cpuType: UInt32 = 0
    public var cpuSubtype: UInt32 = 0
    public var fileType: UInt32 = 0
    public var ncmds: UInt32 = 0
    public var sizeofcmds: UInt32 = 0
    public var flags: UInt32 = 0
    public var is64 = true
    public var headerSize = 32
    public var uuid = ""
    public var platform = ""
    public var minOS = ""
    public var sdk = ""
    public var cryptid: UInt32 = 0
    public var cryptoff: UInt32 = 0
    public var cryptsize: UInt32 = 0
    public var entryPoint: UInt64?
    public var sourceVersion: String?
    public var hasChainedFixups = false
    public var buildTool = ""

    public var arch: String { MachOName.arch(cpuType, cpuSubtype) }
    public var typeName: String { MachOName.fileType(fileType) }
    public var flagNames: [String] { MachOName.flags(flags) }
    public var isPIE: Bool { (flags & 0x0020_0000) != 0 }
    public var isEncrypted: Bool { cryptid != 0 }
}

public struct MachOFile {
    public var url: URL?
    public var slices: [SliceInfo] = []
    public var header = MachOHeaderInfo()
    public var segments: [SegmentInfo] = []
    public var commands: [LoadCommandInfo] = []
    public var dylibs: [LinkedLibInfo] = []
    public var symbols: [SymbolInfo] = []
    public var rpaths: [String] = []
    public var stringTableCount: Int = 0
    public var isFat: Bool { slices.count > 1 }

    public var allSections: [SectionInfo] { segments.flatMap { $0.sections } }
    public var exportedCount: Int { symbols.filter { $0.external && !$0.undefined }.count }
    public var importedCount: Int { symbols.filter { $0.undefined }.count }

    /// vmaddr -> file offset translation for static parsing.
    public func fileOffset(forVMAddress addr: UInt64) -> Int? {
        for seg in segments {
            guard addr >= seg.vmaddr, addr < seg.vmaddr + seg.vmsize else { continue }
            let delta = addr - seg.vmaddr
            guard delta < seg.filesize else { return nil }
            return Int(seg.fileoff + delta)
        }
        return nil
    }
}
