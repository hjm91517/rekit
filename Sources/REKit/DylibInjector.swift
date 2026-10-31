import Foundation

public struct PatchResult: Identifiable {
    public let id = UUID()
    public var success: Bool
    public var message: String
    public var outputURL: URL?
    public var patchOffset: Int
    public var freeBytes: Int
    public var sliceArch: String
}

public enum DylibInjector {
    /// Injects `LC_LOAD_DYLIB` for `dylibPath` into an arm64/arm64e Mach-O slice, in place
    /// inside the file's existing header padding (file size never changes).
    public static func inject(dylibPath: String, binary: URL, output: URL) throws -> PatchResult {
        var data = try Data(contentsOf: binary)
        var bytes = [UInt8](data)
        let r = ByteReader(bytes)
        let magic = r.u32(0)
        var sliceStart = 0
        var sliceEnd = bytes.count
        var arch = "thin"

        if magic == MachOConstants.FAT_MAGIC || magic == MachOConstants.FAT_MAGIC_64 {
            let is64Fat = magic == MachOConstants.FAT_MAGIC_64
            let n = Int(r.u32(4))
            let entry = is64Fat ? 32 : 20
            var chosen = -1
            for i in 0..<n {
                let base = 8 + i * entry
                let cpu = r.u32(base)
                if cpu == 0x0100_000C { chosen = i; break }
            }
            guard chosen >= 0 else {
                return PatchResult(success: false, message: "fat 文件里没有 arm64 切片", outputURL: nil,
                                   patchOffset: 0, freeBytes: 0, sliceArch: "none")
            }
            let base = 8 + chosen * entry
            let off = Int(r.u32(base + 8))
            let size = Int(r.u32(base + 12))
            sliceStart = off
            sliceEnd = min(bytes.count, off + size)
            arch = MachOName.arch(r.u32(base), r.u32(base + 4))
        }

        let headerOff = sliceStart
        let h = ByteReader(bytes)
        guard h.u32(headerOff) == MachOConstants.MH_MAGIC_64 else {
            return PatchResult(success: false, message: "只支持 64 位 Mach-O 切片（arm64/arm64e）",
                               outputURL: nil, patchOffset: 0, freeBytes: 0, sliceArch: arch)
        }
        let ncmds = h.u32(headerOff + 16)
        let sizeofcmds = Int(h.u32(headerOff + 20))
        let endOfCommands = headerOff + 32 + sizeofcmds

        // find the first section's file offset: that is the usable header padding ceiling
        var firstSection = sliceEnd
        var p = headerOff + 32
        for _ in 0..<ncmds {
            let cmd = h.u32(p)
            let size = Int(h.u32(p + 4))
            guard size >= 8 else { break }
            if cmd == 0x19 {
                let nsects = Int(h.u32(p + 64))
                var sOff = p + 72
                for _ in 0..<nsects {
                    let secOffset = Int(h.u32(sOff + 48))
                    let secSize = Int(h.u32(sOff + 40))
                    if secOffset > 0 && secSize > 0 && secOffset < firstSection { firstSection = secOffset }
                    sOff += 80
                }
            }
            p += size
        }
        if firstSection == sliceEnd { firstSection = sliceEnd }
        let free = firstSection - endOfCommands

        var name = dylibPath
        if !name.hasPrefix("@") && !name.hasPrefix("/") { name = "@executable_path/Frameworks/\(name)" }
        var pathBytes = Array(name.utf8) + [0]
        while pathBytes.count % 8 != 0 { pathBytes.append(0) }
        let cmdSize = 24 + pathBytes.count
        guard free >= cmdSize else {
            return PatchResult(success: false,
                               message: "头部填充只有 \(free) 字节，装不下 \(cmdSize) 字节的 LC_LOAD_DYLIB",
                               outputURL: nil, patchOffset: endOfCommands, freeBytes: free, sliceArch: arch)
        }

        func put32(_ off: Int, _ v: UInt32) {
            bytes[off] = UInt8(v & 0xFF)
            bytes[off + 1] = UInt8((v >> 8) & 0xFF)
            bytes[off + 2] = UInt8((v >> 16) & 0xFF)
            bytes[off + 3] = UInt8((v >> 24) & 0xFF)
        }
        func put64(_ off: Int, _ v: UInt64) {
            for i in 0..<8 { bytes[off + i] = UInt8((v >> UInt64(i * 8)) & 0xFF) }
        }

        let lcOff = endOfCommands
        put32(lcOff, 0xC)
        put32(lcOff + 4, UInt32(cmdSize))
        put32(lcOff + 8, 24)
        put32(lcOff + 12, 2)
        put32(lcOff + 16, 0x0001_0000)
        put32(lcOff + 20, 0x0001_0000)
        for (i, b) in pathBytes.enumerated() { bytes[lcOff + 24 + i] = b }

        // keep 8-byte alignment padding zeroed
        var pad = lcOff + cmdSize
        while pad < lcOff + ((cmdSize + 7) / 8) * 8 && pad < bytes.count { bytes[pad] = 0; pad += 1 }

        put32(headerOff + 16, ncmds + 1)
        put32(headerOff + 20, UInt32(sizeofcmds + cmdSize))

        // strip stale code signature blob so it cannot claim a now-invalid hash
        // (re-sign afterwards with ldid / codesign)
        data = Data(bytes)
        try data.write(to: output, options: .atomic)

        return PatchResult(success: true,
                           message: "已写入 LC_LOAD_DYLIB(\(name))，占用 \(cmdSize) 字节填充，剩余 \(free - cmdSize) 字节。签名已失效，必须重新签名。",
                           outputURL: output, patchOffset: lcOff, freeBytes: free, sliceArch: arch)
    }

    public static func suggestedDylibName(from path: String) -> String {
        (path as NSString).lastPathComponent.replacingOccurrences(of: ".dylib", with: "")
    }
}
