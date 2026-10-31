import Foundation

/// Shared file plumbing for the app: imports land here, reports go out from here.
public enum Workspace {
    public static var root: URL {
        let base = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("REKit", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var imports: URL {
        let dir = root.appendingPathComponent("imports", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var reports: URL {
        let dir = root.appendingPathComponent("reports", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static func copyIntoImports(_ url: URL) throws -> URL {
        let target = imports.appendingPathComponent(url.lastPathComponent)
        let fm = FileManager.default
        if url.path == target.path { return target }
        if fm.fileExists(atPath: target.path) { try? fm.removeItem(at: target) }
        try fm.copyItem(at: url, to: target)
        return target
    }

    public static func knownBinaries() -> [URL] {
        var urls: [URL] = []
        for dir in [imports, root] {
            let items = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey])) ?? []
            urls += items.filter { !$0.hasDirectoryPath }
        }
        return urls.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    public static func saveReport(_ text: String, name: String, ext: String) -> URL? {
        let safe = name.replacingOccurrences(of: "/", with: "_")
        let url = reports.appendingPathComponent("\(safe)-\(Int(Date().timeIntervalSince1970)).\(ext)")
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch { return nil }
    }

    /// Common jailbroken / developer locations worth probing on a real device.
    public static var probeRoots: [String] {
        ["/var/containers/Bundle/Application", "/var/mobile/Containers/Bundle/Application",
         "/var/jb/Applications", "/Applications", "/usr/lib", Bundle.main.bundlePath]
    }
}
