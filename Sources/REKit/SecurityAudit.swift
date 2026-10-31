import Foundation

public struct AuditFinding: Identifiable, Hashable {
    public let id = UUID()
    public let title: String
    public let severity: Severity
    public let category: String
    public let evidence: String
    public let impact: String
}

public enum SecurityAudit {
    public static func audit(file: MachOFile, bytes: [UInt8], strings: [StringHit],
                             stringsByCategory: [StringsScan.Category: [StringHit]] = [:],
                             infoPlist: [String: Any]? = nil) -> [AuditFinding] {
        var out: [AuditFinding] = []
        let text = strings.map { $0.value }.joined(separator: "\n").lowercased()
        func add(_ title: String, _ severity: Severity, _ category: String,
                 _ evidence: String, _ impact: String) {
            out.append(AuditFinding(title: title, severity: severity, category: category,
                                    evidence: evidence, impact: impact))
        }

        if !file.header.isPIE {
            add("未开启 PIE（ASLR 缺失）", .high, "二进制加固",
                "MH_PIE 未设置",
                "代码段固定加载地址，ROP/固定地址利用难度大幅降低")
        }
        if file.header.isEncrypted {
            add("App Store 加密（FairPlay cryptid=\(file.header.cryptid)）", .info, "二进制加固",
                String(format: "cryptoff=0x%x cryptsize=0x%x", file.header.cryptoff, file.header.cryptsize),
                "文本段不可直接静态反汇编，需先 dump 解密")
        }
        if file.header.hasChainedFixups {
            add("使用 dyld chained fixups", .info, "二进制加固",
                "存在 LC_DYLD_CHAINED_FIXUPS",
                "经典 import 指针已改为链式编码，运行时重绑定需解码 bind 链")
        }
        if file.segments.contains(where: { $0.name == "__RESTRICT" }) {
            add("__RESTRICT 段存在", .medium, "注入防护",
                "__RESTRICT segment",
                "阻止 DYLD_INSERT_LIBRARIES 注入系统级校验")
        }

        if let ats = infoPlist?["NSAppTransportSecurity"] as? [String: Any],
           (ats["NSAllowsArbitraryLoads"] as? Bool) == true {
            add("ATS 被全局关闭", .medium, "传输安全",
                "NSAllowsArbitraryLoads = true",
                "任意明文 HTTP 可用，可被中间人改写请求与下载内容")
        }
        if let schemes = infoPlist?["CFBundleURLTypes"] as? [[String: Any]], !schemes.isEmpty {
            let names = schemes.flatMap { ($0["CFBundleURLSchemes"] as? [String]) ?? [] }
            add("自定义 URL Scheme 暴露", .low, "深度链接",
                names.joined(separator: ", "),
                "任意 App / Web 可唤起本应用并传入参数，需校验调用来源")
        }
        if (infoPlist?["UIFileSharingEnabled"] as? Bool) == true {
            add("Documents 目录对外可见", .low, "本地存储",
                "UIFileSharingEnabled = true",
                "文件 App / Finder 可读写应用文档，敏感缓存可能被导出")
        }

        let antiDebug = ["ptrace", "pt_deny_attach", "sysctl", "p_traced"]
        if antiDebug.contains(where: { text.contains($0) }) {
            add("疑似反调试逻辑", .info, "反调试",
                antiDebug.filter { text.contains($0) }.joined(separator: ", "),
                "存在调试器检测，动态分析前需绕过")
        }
        let jbMarkers = ["/applications/cydia.app", "cydia://", "/bin/bash", "/usr/sbin/sshd",
                         "jailbreak", "sileo", "/var/lib/dpkg"]
        let jbHits = jbMarkers.filter { text.contains($0) }
        if !jbHits.isEmpty {
            add("越狱检测特征", .info, "越狱检测",
                jbHits.joined(separator: ", "),
                "检测到越狱环境可拒绝运行，需 hook 对应检查点")
        }

        if text.contains("uikeyboardtypewebview") || text.contains("uiwebview") {
            add("UIWebView 残留", .high, "WebView",
                "UIWebView / WebView 字符串",
                "旧 WebView 已废弃且存在已知 JSC 逃逸链")
        }
        if text.contains("allowuniversalaccessfromfileurls") {
            add("WebView 允许文件域访问任意来源", .high, "WebView",
                "allowUniversalAccessFromFileURLs",
                "本地 HTML 可读取任意本地文件并外发")
        }
        if text.contains("ksecattraccessiblealways") {
            add("钥匙串条目永久可读", .medium, "密钥存储",
                "kSecAttrAccessibleAlways",
                "设备锁屏状态下也能读取该钥匙串条目")
        }
        let weakCrypto = ["ccmd5", "cc_md5", "ccsha1", "cc_sha1", "kccoptionecbmode", "md5"]
        let weakHits = weakCrypto.filter { text.contains($0) }
        if !weakHits.isEmpty {
            add("弱加密原语使用", .medium, "密码学",
                weakHits.joined(separator: ", "),
                "MD5/SHA1/ECB 易被碰撞或模式分析破解")
        }
        if let urls = stringsByCategory[.url], urls.contains(where: { $0.value.hasPrefix("http://") }) {
            add("存在明文 HTTP 端点", .medium, "传输安全",
                urls.filter { $0.value.hasPrefix("http://") }.prefix(3).map { $0.value }.joined(separator: " "),
                "证书校验缺席，请求与响应可被篡改")
        }
        let dangerous = ["_sqlite3_open", "_sqlite3_exec", "dlopen", "dlsym"]
        let imported = Set(file.symbols.filter { $0.undefined }.map { $0.name })
        let present = dangerous.filter { imported.contains($0) || imported.contains("_" + $0) }
        if !present.isEmpty {
            add("敏感符号导入", .low, "攻击面",
                present.joined(separator: ", "),
                "运行期加载/查询类接口扩大攻击面")
        }
        if file.dylibs.contains(where: { $0.path.contains("/usr/lib/libSystem.B.dylib") }) == false {
            add("未链接 libSystem", .info, "二进制结构",
                "缺少 libSystem.B.dylib",
                "可能为静态链接或精简构建，运行时行为需单独确认")
        }
        return out.sorted { $0.severity < $1.severity }
    }

    public static func score(_ findings: [AuditFinding]) -> Int {
        let weights: [Severity: Int] = [.critical: 8, .high: 5, .medium: 3, .low: 1, .info: 0]
        let raw = findings.reduce(0) { $0 + (weights[$1.severity] ?? 0) }
        return min(raw, 100)
    }
}
