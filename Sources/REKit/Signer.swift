import Foundation
import Darwin

public enum Signer {
    public static let searchPaths = [
        "/usr/bin/ldid", "/usr/local/bin/ldid", "/opt/homebrew/bin/ldid",
        "/var/jb/usr/bin/ldid", "/opt/procursus/bin/ldid", "/usr/bin/codesign",
    ]

    public static func findTool(_ names: [String] = ["ldid", "codesign"]) -> String? {
        let bundle = Bundle.main.bundlePath
        for name in names {
            let bundled = "\(bundle)/\(name)"
            if FileManager.default.isExecutableFile(atPath: bundled) { return bundled }
        }
        if let path = ProcessInfo.processInfo.environment["PATH"] {
            for dir in path.split(separator: ":") {
                for name in names {
                    let candidate = "\(dir)/\(name)"
                    if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
                }
            }
        }
        for p in searchPaths {
            if FileManager.default.isExecutableFile(atPath: p) { return p }
        }
        return nil
    }

    public struct Result {
        public var code: Int32
        public var log: String
        public var invoked: String
        public var ok: Bool { code == 0 }
    }

    /// Re-signs a binary/mach-o with ldid (or codesign as fallback).
    public static func sign(binary: URL, entitlements: URL? = nil) -> Result {
        guard let tool = findTool() else {
            return Result(code: -1, log: "未找到 ldid / codesign。把 ldid 放进 App 沙盒或 /usr/bin 后再试。", invoked: "")
        }
        var args: [String] = []
        if (tool as NSString).lastPathComponent == "codesign" {
            args = ["-f", "-s", "-"]
            if let ent = entitlements { args += ["--entitlements", ent.path] }
            args.append(binary.path)
        } else {
            args = ["-S"]
            if let ent = entitlements { args += [ent.path] }
            args.append(binary.path)
        }
        let r = run(tool, args)
        return Result(code: r.0, log: r.1, invoked: ([tool] + args).joined(separator: " "))
    }

    /// Writes entitlements dictionary to a temp plist for signing.
    public static func writeEntitlements(_ dict: [String: Any]) -> URL? {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rekit-ent-\(UUID().uuidString).plist")
        guard let data = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0) else { return nil }
        do {
            try data.write(to: url)
            return url
        } catch { return nil }
    }

    /// posix_spawn wrapper: iOS has no Foundation.Process.
    static func run(_ executable: String, _ args: [String]) -> (Int32, String) {
        let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("rekit-exec-\(UUID().uuidString).log")
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
        let fd = open(logURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard fd >= 0 else { return (-1, "无法创建输出文件") }
        defer { close(fd) }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        posix_spawn_file_actions_adddup2(&actions, fd, 1)
        posix_spawn_file_actions_adddup2(&actions, fd, 2)
        defer { posix_spawn_file_actions_destroy(&actions) }

        var cArgs: [UnsafeMutablePointer<CChar>?] = ([executable] + args).map { strdup($0) }
        cArgs.append(nil)
        defer { for p in cArgs { free(p) } }

        var pid: pid_t = 0
        let rc = cArgs.withUnsafeBufferPointer { buf -> Int32 in
            posix_spawn(&pid, executable, &actions, nil, UnsafeMutablePointer(mutating: buf.baseAddress!), environ)
        }
        if rc != 0 { return (rc, "posix_spawn 失败: \(String(cString: strerror(rc)))") }

        var status: Int32 = 0
        waitpid(pid, &status, 0)
        let out = (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
        return (status, out.isEmpty ? "(无输出)" : out)
    }
}
