import Foundation

public struct ObjCMethodInfo: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let types: String
    public let address: UInt64
    public let isClassMethod: Bool

    public var signature: String {
        let typeEnc = types.trimmingCharacters(in: .whitespaces)
        return typeEnc.isEmpty ? name : "\(name)  [\(typeEnc.prefix(120))]"
    }
}

public struct ObjCIvarInfo: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let type: String
    public let offset: UInt64
}

public struct ObjCPropertyInfo: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let attributes: String
}

public struct ObjCClassInfo: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let superName: String
    public let address: UInt64
    public let isSwift: Bool
    public let methods: [ObjCMethodInfo]
    public let classMethods: [ObjCMethodInfo]
    public let ivars: [ObjCIvarInfo]
    public let properties: [ObjCPropertyInfo]

    public var methodCount: Int { methods.count + classMethods.count }
    public var headerDump: String {
        var lines: [String] = []
        lines.append("@interface \(name) : \(superName.isEmpty ? "NSObject" : superName)")
        for iv in ivars {
            lines.append("    \(iv.type) \(iv.name);  // offset \(iv.offset)")
        }
        for p in properties {
            lines.append("    @property \(p.attributes) \(p.name);")
        }
        for m in classMethods { lines.append("+ \(m.name);") }
        for m in methods { lines.append("- \(m.name);") }
        lines.append("@end")
        return lines.joined(separator: "\n")
    }
}

public enum ObjCDump {
    static let ptr = 8

    public static func classes(from file: MachOFile, bytes: [UInt8]) -> [ObjCClassInfo] {
        let r = ByteReader(bytes)
        guard file.header.is64 else { return [] }
        var byAddr: [UInt64: ObjCClassInfo] = [:]
        var order: [UInt64] = []

        func vmToFile(_ addr: UInt64) -> Int? { file.fileOffset(forVMAddress: addr) }
        func readPtr(_ vm: UInt64) -> UInt64 {
            guard let f = vmToFile(vm) else { return 0 }
            return r.u64(f)
        }
        func readString(_ vm: UInt64) -> String {
            guard vm != 0, let f = vmToFile(vm) else { return "" }
            return r.cString(f, limit: 512)
        }
        func readI32(_ vm: UInt64) -> Int32 {
            guard let f = vmToFile(vm) else { return 0 }
            return r.i32(f)
        }

        func parseMethods(_ listVM: UInt64, isClassMethod: Bool) -> [ObjCMethodInfo] {
            guard listVM != 0, let listOff = vmToFile(listVM) else { return [] }
            let entsize = r.u32(listOff)
            let count = Int(r.u32(listOff + 4))
            guard count > 0, count < 5000 else { return [] }
            let isRelative = (entsize & 0x8000_0000) != 0
            let entrySize = Int(entsize & 0x0000_FFFC)
            let step = isRelative ? max(entrySize, 12) : max(entrySize, 24)
            var out: [ObjCMethodInfo] = []
            for i in 0..<count {
                let entryVM = listVM + 8 + UInt64(i * step)
                guard let entryOff = vmToFile(entryVM), r.has(entryOff, step) else { break }
                var nameVM: UInt64 = 0
                var typesVM: UInt64 = 0
                var imp: UInt64 = 0
                if isRelative {
                    nameVM = entryVM &+ UInt64(bitPattern: Int64(r.i32(entryOff)))
                    typesVM = entryVM &+ UInt64(bitPattern: Int64(r.i32(entryOff + 4)))
                    imp = entryVM &+ UInt64(bitPattern: Int64(r.i32(entryOff + 8)))
                } else {
                    nameVM = r.u64(entryOff)
                    typesVM = r.u64(entryOff + 8)
                    imp = r.u64(entryOff + 16)
                }
                let sel = readString(nameVM)
                if sel.isEmpty { continue }
                out.append(ObjCMethodInfo(name: sel, types: readString(typesVM), address: imp,
                                          isClassMethod: isClassMethod))
            }
            return out.sorted { $0.name < $1.name }
        }

        func parseIvars(_ listVM: UInt64) -> [ObjCIvarInfo] {
            guard listVM != 0, let off = vmToFile(listVM) else { return [] }
            let entsize = r.u32(off)
            let count = Int(r.u32(off + 4))
            guard count > 0, count < 2000 else { return [] }
            let step = max(Int(entsize & 0x0000_FFFC), 32)
            var out: [ObjCIvarInfo] = []
            for i in 0..<count {
                guard let e = vmToFile(listVM + 8 + UInt64(i * step)), r.has(e, step) else { break }
                let offsetPtr = r.u64(e)
                let name = readString(r.u64(e + 8))
                let type = readString(r.u64(e + 16))
                if name.isEmpty { continue }
                out.append(ObjCIvarInfo(name: name, type: type, offset: UInt64(max(readI32(offsetPtr), 0))))
            }
            return out
        }

        func parseProps(_ listVM: UInt64) -> [ObjCPropertyInfo] {
            guard listVM != 0, let off = vmToFile(listVM) else { return [] }
            let entsize = r.u32(off)
            let count = Int(r.u32(off + 4))
            guard count > 0, count < 2000 else { return [] }
            let step = max(Int(entsize & 0x0000_FFFC), 16)
            var out: [ObjCPropertyInfo] = []
            for i in 0..<count {
                guard let e = vmToFile(listVM + 8 + UInt64(i * step)), r.has(e, step) else { break }
                let name = readString(r.u64(e))
                if name.isEmpty { continue }
                out.append(ObjCPropertyInfo(name: name, attributes: readString(r.u64(e + 8))))
            }
            return out
        }

        func className(at addr: UInt64) -> String {
            if let known = byAddr[addr] { return known.name }
            let dataPtr = readPtr(addr + 32)
            let roVM = dataPtr & 0x0000_07FF_FFFF_FFFF
            guard roVM != 0 else { return "" }
            return readString(readPtr(roVM + 24))
        }

        func buildClass(_ addr: UInt64) -> ObjCClassInfo? {
            let dataPtr = readPtr(addr + 32)
            if dataPtr == 0 { return nil }
            let isSwift = (dataPtr & 0x3) != 0
            let roVM = dataPtr & 0x0000_07FF_FFFF_FFFF
            guard let roOff = vmToFile(roVM) else { return nil }
            let name = readString(r.u64(roOff + 24))
            if name.isEmpty { return nil }
            let superAddr = readPtr(addr + 8)
            let superName = superAddr == 0 ? "NSObject" : className(at: superAddr)
            let methods = parseMethods(r.u64(roOff + 32), isClassMethod: false)
            let ivars = parseIvars(r.u64(roOff + 48))
            let props = parseProps(r.u64(roOff + 64))
            let metaAddr = readPtr(addr)
            var classMethods: [ObjCMethodInfo] = []
            if metaAddr != 0 {
                let metaData = readPtr(metaAddr + 32)
                if metaData != 0 {
                    let metaRO = metaData & 0x0000_07FF_FFFF_FFFF
                    if let mo = vmToFile(metaRO) {
                        classMethods = parseMethods(r.u64(mo + 32), isClassMethod: true)
                    }
                }
            }
            return ObjCClassInfo(name: name, superName: superName, address: addr, isSwift: isSwift,
                                 methods: methods, classMethods: classMethods,
                                 ivars: ivars, properties: props)
        }

        // categories first, so class-body parse can merge
        var extraMethods: [String: [ObjCMethodInfo]] = [:]
        var extraClassMethods: [String: [ObjCMethodInfo]] = [:]
        for sec in file.allSections where sec.name == "__objc_catlist" {
            let n = Int(sec.size) / ptr
            for i in 0..<min(n, 5000) {
                let catVM = r.u64(Int(sec.offset) + i * ptr)
                guard catVM != 0, let co = vmToFile(catVM) else { continue }
                let clsVM = r.u64(co + 8)
                guard clsVM != 0 else { continue }
                let clsName = className(at: clsVM)
                let im = parseMethods(r.u64(co + 16), isClassMethod: false)
                let cm = parseMethods(r.u64(co + 24), isClassMethod: true)
                if clsName.isEmpty { continue }
                extraMethods[clsName, default: []].append(contentsOf: im)
                extraClassMethods[clsName, default: []].append(contentsOf: cm)
            }
        }

        for sec in file.allSections where sec.name == "__objc_classlist" {
            let n = Int(sec.size) / ptr
            for i in 0..<min(n, 40_000) {
                let clsVM = r.u64(Int(sec.offset) + i * ptr)
                guard clsVM != 0 else { continue }
                if let info = buildClass(clsVM) {
                    if byAddr[clsVM] == nil { order.append(clsVM) }
                    byAddr[clsVM] = info
                }
            }
        }

        var result: [ObjCClassInfo] = []
        for addr in order {
            guard var info = byAddr[addr] else { continue }
            if let m = extraMethods[info.name], !m.isEmpty {
                info = ObjCClassInfo(name: info.name, superName: info.superName, address: info.address,
                                     isSwift: info.isSwift,
                                     methods: (info.methods + m).sorted { $0.name < $1.name },
                                     classMethods: info.classMethods, ivars: info.ivars,
                                     properties: info.properties)
            }
            if let m = extraClassMethods[info.name], !m.isEmpty {
                info = ObjCClassInfo(name: info.name, superName: info.superName, address: info.address,
                                     isSwift: info.isSwift, methods: info.methods,
                                     classMethods: (info.classMethods + m).sorted { $0.name < $1.name },
                                     ivars: info.ivars, properties: info.properties)
            }
            result.append(info)
        }
        return result.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
}
