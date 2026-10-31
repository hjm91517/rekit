import Foundation
import Darwin

public struct InterposeStatus: Identifiable {
    public let id = UUID()
    public let name: String
    public let images: Int
    public let chainedImages: Int
    public let skipped: Int
    public let rebound: Int
    public var summary: String {
        "重绑定 \(rebound) 处 · 扫描 \(images) 个 image · 链式 \(chainedImages) · 跳过 \(skipped)"
    }
}

typealias PtraceFn = @convention(c) (Int32, pid_t, UnsafeMutableRawPointer?, Int32) -> Int32
typealias SysctlFn = @convention(c) (UnsafeMutablePointer<Int32>?, UInt32, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?, UnsafeMutableRawPointer?, Int) -> Int32
typealias StatFn = @convention(c) (UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Int32
typealias AccessFn = @convention(c) (UnsafePointer<CChar>?, Int32) -> Int32
typealias FopenFn = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> UnsafeMutableRawPointer?

private var origPtrace: PtraceFn?
private var origSysctl: SysctlFn?
private var origStat: StatFn?
private var origLstat: StatFn?
private var origAccess: AccessFn?
private var origFopen: FopenFn?

private var maskedPaths: [String] = ["/Applications/Cydia.app", "/var/jb", "/usr/sbin/sshd",
                                     "/etc/apt", "/private/etc/apt", "/Library/MobileSubstrate"]

public func rek_ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: Int32) -> Int32 {
    if request == 31 { return 0 } // PT_DENY_ATTACH
    if let original = origPtrace { return original(request, pid, addr, data) }
    return 0
}

public func rek_sysctl(_ name: UnsafeMutablePointer<Int32>?, _ namelen: UInt32, _ oldp: UnsafeMutableRawPointer?,
                       _ oldlenp: UnsafeMutablePointer<Int>?, _ newp: UnsafeMutableRawPointer?, _ newlen: Int) -> Int32 {
    let result = origSysctl?(name, namelen, oldp, oldlenp, newp, newlen) ?? -1
    if result == 0, let name = name, namelen == 4,
       name[0] == CTL_KERN, name[1] == KERN_PROC, name[2] == KERN_PROC_PID,
       let oldp = oldp, let oldlenp = oldlenp, oldlenp.pointee >= 4 {
        // clear P_TRACED (0x800) from the returned kinfo_proc flags slot
        let flagsOffset = 32
        if oldlenp.pointee > flagsOffset {
            let flagsPtr = oldp.advanced(by: flagsOffset).assumingMemoryBound(to: Int32.self)
            flagsPtr.pointee &= ~0x800
        }
    }
    return result
}

private func pathMasked(_ path: UnsafePointer<CChar>?) -> Bool {
    guard let path = path else { return false }
    let s = String(cString: path)
    return maskedPaths.contains { s.hasPrefix($0) }
}

public func rek_stat(_ path: UnsafePointer<CChar>?, _ buf: UnsafeMutableRawPointer?) -> Int32 {
    if pathMasked(path) { errno = ENOENT; return -1 }
    return origStat?(path, buf) ?? -1
}

public func rek_lstat(_ path: UnsafePointer<CChar>?, _ buf: UnsafeMutableRawPointer?) -> Int32 {
    if pathMasked(path) { errno = ENOENT; return -1 }
    return origLstat?(path, buf) ?? -1
}

public func rek_access(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> Int32 {
    if pathMasked(path) { errno = ENOENT; return -1 }
    return origAccess?(path, mode) ?? -1
}

public func rek_fopen(_ path: UnsafePointer<CChar>?, _ mode: UnsafePointer<CChar>?) -> UnsafeMutableRawPointer? {
    if pathMasked(path) { errno = ENOENT; return nil }
    return origFopen?(path, mode)
}

public enum Interpose {
    public static func setMaskedPaths(_ paths: [String]) { maskedPaths = paths }

    static func rebind(_ table: [(String, UnsafeMutableRawPointer)]) -> (Int, Int, Int, Int) {
        var rebindings = table.map { REKRebinding(name: strdup($0.0), replacement: $0.1, replaced: nil) }
        let count = rek_rebind_symbols(&rebindings, table.count)
        for r in rebindings { if let n = r.name { free(UnsafeMutablePointer(mutating: n)) } }
        return (count, Int(rek_last_image_count()), Int(rek_chained_fixup_image_count()), Int(rek_last_skipped_count()))
    }

    /// Disables ptrace(PT_DENY_ATTACH) and clears P_TRACED in sysctl replies.
    public static func installAntiDebug() -> InterposeStatus {
        if origPtrace == nil {
            origPtrace = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace"), to: PtraceFn.self)
        }
        if origSysctl == nil {
            origSysctl = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "sysctl"), to: SysctlFn.self)
        }
        let r = rebind([("ptrace", unsafeBitCast(rek_ptrace as PtraceFn, to: UnsafeMutableRawPointer.self)),
                        ("sysctl", unsafeBitCast(rek_sysctl as SysctlFn, to: UnsafeMutableRawPointer.self))])
        return InterposeStatus(name: "反调试绕过", images: r.1, chainedImages: r.2, skipped: r.3, rebound: r.0)
    }

    /// Hides jailbreak artifacts from stat/lstat/access/fopen.
    public static func installJailbreakMask(paths: [String]? = nil) -> InterposeStatus {
        if let paths = paths { maskedPaths = paths }
        if origStat == nil {
            origStat = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "stat"), to: StatFn.self)
            origLstat = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "lstat"), to: StatFn.self)
            origAccess = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "access"), to: AccessFn.self)
            origFopen = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "fopen"), to: FopenFn.self)
        }
        let r = rebind([("stat", unsafeBitCast(rek_stat as StatFn, to: UnsafeMutableRawPointer.self)),
                        ("lstat", unsafeBitCast(rek_lstat as StatFn, to: UnsafeMutableRawPointer.self)),
                        ("access", unsafeBitCast(rek_access as AccessFn, to: UnsafeMutableRawPointer.self)),
                        ("fopen", unsafeBitCast(rek_fopen as FopenFn, to: UnsafeMutableRawPointer.self))])
        return InterposeStatus(name: "越狱检测屏蔽", images: r.1, chainedImages: r.2, skipped: r.3, rebound: r.0)
    }

    public static var mainBinaryHasChainedFixups: Bool { rek_main_has_chained_fixups() != 0 }
}
