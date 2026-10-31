import Foundation
import ObjectiveC

public struct LiveClass: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let superName: String
    public let methodCount: Int
    public let ivarCount: Int
    public let protocolCount: Int
    public let isSwift: Bool
}

public struct LiveMethod: Identifiable, Hashable {
    public let id = UUID()
    public let selector: String
    public let types: String
    public let isClassMethod: Bool
}

public struct LiveIvar: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let type: String
    public let offset: Int
}

public enum Runtime {
    public static var loadedImages: [String] {
        var out: [String] = []
        let count = _dyld_image_count()
        for i in 0..<count {
            if let name = _dyld_get_image_name(i) { out.append(String(cString: name)) }
        }
        return out
    }

    static func typeEncoding(_ m: Method) -> String {
        guard let enc = method_getTypeEncoding(m) else { return "" }
        return String(cString: enc)
    }

    public static func classes(limit: Int = 20000) -> [LiveClass] {
        let count = Int(objc_getClassList(nil, 0))
        guard count > 0 else { return [] }
        let buffer = UnsafeMutablePointer<AnyClass>.allocate(capacity: count)
        defer { buffer.deallocate() }
        let real = Int(objc_getClassList(AutoreleasingUnsafeMutablePointer<AnyClass>(buffer), Int32(count)))
        var out: [LiveClass] = []
        out.reserveCapacity(real)
        for i in 0..<real {
            let cls: AnyClass = buffer[i]
            let name = String(cString: class_getName(cls))
            if name.hasPrefix("_") && name.count > 48 { continue }
            let superName = class_getSuperclass(cls).map { String(cString: class_getName($0)) } ?? ""

            var mCount: UInt32 = 0
            if let methods = class_copyMethodList(cls, &mCount) { free(methods) }
            var iCount: UInt32 = 0
            if let ivars = class_copyIvarList(cls, &iCount) { free(ivars) }
            var pCount: UInt32 = 0
            if let protos = class_copyProtocolList(cls, &pCount) { free(protos) }

            out.append(LiveClass(name: name, superName: superName, methodCount: Int(mCount),
                                 ivarCount: Int(iCount), protocolCount: Int(pCount),
                                 isSwift: name.contains(".") || name.hasPrefix("_Tt")))
            if out.count >= limit { break }
        }
        return out.sorted { $0.name < $1.name }
    }

    public static func methods(of className: String) -> [LiveMethod] {
        guard let cls = NSClassFromString(className) else { return [] }
        var out: [LiveMethod] = []
        func collect(_ c: AnyClass, isClassMethod: Bool) {
            var n: UInt32 = 0
            guard let list = class_copyMethodList(c, &n) else { return }
            for i in 0..<Int(n) {
                let m = list[i]
                out.append(LiveMethod(selector: NSStringFromSelector(method_getName(m)),
                                      types: typeEncoding(m), isClassMethod: isClassMethod))
            }
            free(list)
        }
        collect(cls, isClassMethod: false)
        if let meta = object_getClass(cls) { collect(meta, isClassMethod: true) }
        return out.sorted { $0.selector < $1.selector }
    }

    public static func ivars(of className: String) -> [LiveIvar] {
        guard let cls = NSClassFromString(className) else { return [] }
        var n: UInt32 = 0
        guard let list = class_copyIvarList(cls, &n) else { return [] }
        var out: [LiveIvar] = []
        for i in 0..<Int(n) {
            let iv = list[i]
            let name = ivar_getName(iv).map { String(cString: $0) } ?? ""
            let type = ivar_getTypeEncoding(iv).map { String(cString: $0) } ?? ""
            out.append(LiveIvar(name: name, type: type, offset: ivar_getOffset(iv)))
        }
        free(list)
        return out.sorted { $0.name < $1.name }
    }

    public static func resolve(symbol: String) -> UInt64? {
        guard let p = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else { return nil }
        return UInt64(UInt(bitPattern: p))
    }

    /// Best-effort 0-argument invocation, instance method first, then class method.
    public static func invoke(className: String, selector: String) -> String {
        guard let cls = NSClassFromString(className) else { return "类不存在: \(className)" }
        let sel = NSSelectorFromString(selector)
        if let meta = object_getClass(cls), class_getClassMethod(cls, sel) != nil,
           let imp = class_getMethodImplementation(meta, sel) {
            typealias ClassFn = @convention(c) (AnyObject, Selector) -> Unmanaged<AnyObject>?
            let fn = unsafeBitCast(imp, to: ClassFn.self)
            if let result = fn(cls, sel) { return "返回: \(result.takeUnretainedValue())" }
            return "调用完成（无返回对象）"
        }
        guard class_getInstanceMethod(cls, sel) != nil else { return "方法不存在: \(selector)" }
        guard let type = cls as? NSObject.Type, let instance = type.init() as? NSObject else {
            return "无法实例化 \(className)"
        }
        guard let result = instance.perform(sel) else { return "调用完成（无返回对象）" }
        return "返回: \(result.takeUnretainedValue())"
    }
}

public struct TraceEvent: Identifiable, Hashable {
    public let id = UUID()
    public let time = Date()
    public let className: String
    public let selector: String
}

public enum SwizzleTracer {
    private static var events: [TraceEvent] = []
    private static let lock = NSLock()

    public static var log: [TraceEvent] {
        lock.lock(); defer { lock.unlock() }
        return events
    }

    public static func clear() {
        lock.lock(); events.removeAll(); lock.unlock()
    }

    static func record(_ cls: String, _ sel: String) {
        lock.lock()
        if events.count < 2000 { events.append(TraceEvent(className: cls, selector: sel)) }
        lock.unlock()
    }

    /// Only 0-argument methods: the trampoline keeps the ABI byte-identical.
    public static func trace(className: String, selector: String) -> (Bool, String) {
        guard let cls = NSClassFromString(className) else { return (false, "类不存在: \(className)") }
        let sel = NSSelectorFromString(selector)
        guard let method = class_getInstanceMethod(cls, sel) else { return (false, "实例方法不存在: \(selector)") }
        let types = Runtime.typeEncoding(method)
        let isVoidReturn = types.hasPrefix("v")
        let objectArgs = types.filter { $0 == "@" }.count
        guard objectArgs <= 1 else {
            return (false, "仅支持 0 参数方法（当前编码 \(types) 含参数）")
        }
        let original = class_getMethodImplementation(cls, sel)

        if isVoidReturn {
            typealias VoidFn = @convention(c) (AnyObject, Selector) -> Void
            let block: @convention(block) (AnyObject) -> Void = { obj in
                SwizzleTracer.record(className, selector)
                if let original = original {
                    unsafeBitCast(original, to: VoidFn.self)(obj, sel)
                }
            }
            class_replaceMethod(cls, sel, imp_implementationWithBlock(block), types)
        } else {
            typealias ObjFn = @convention(c) (AnyObject, Selector) -> Unmanaged<AnyObject>?
            let block: @convention(block) (AnyObject) -> AnyObject? = { obj in
                SwizzleTracer.record(className, selector)
                guard let original = original else { return nil }
                return unsafeBitCast(original, to: ObjFn.self)(obj, sel)?.takeUnretainedValue()
            }
            class_replaceMethod(cls, sel, imp_implementationWithBlock(block), types)
        }
        return (true, "跟踪蹦床已挂载: -[\(className) \(selector)]  \(types)")
    }
}
