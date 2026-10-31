import Foundation

public struct AnalysisReport {
    public var sourceName: String = ""
    public var fileSize: Int = 0
    public var macho = MachOFile()
    public var strings: [StringHit] = []
    public var classes: [ObjCClassInfo] = []
    public var secrets: [SecretFinding] = []
    public var endpoints: [EndpointHit] = []
    public var audit: [AuditFinding] = []
    public var sdks: [SDKHit] = []
    public var entropy: [Entropy.SectionEntropy] = []
    public var entitlements: [String: Any]?
    public var infoPlist: [String: Any]?
    public var swiftTypeCount: Int = 0
    public var warnings: [String] = []
    public var sourceBytes: [UInt8] = []
    public var binaryURL: URL?

    public var auditScore: Int { SecurityAudit.score(audit) }
    public var riskLevel: String {
        if audit.contains(where: { $0.severity == .critical }) { return "严重" }
        if audit.contains(where: { $0.severity == .high }) { return "高" }
        if auditScore > 10 { return "中" }
        return "低"
    }

    public var markdown: String {
        var md = "# 逆向报告 · \(sourceName)\n\n"
        md += "- 文件大小：\(fileSize) bytes\n"
        md += "- 架构：\(macho.header.arch)（\(macho.header.typeName)）\n"
        md += "- UUID：\(macho.header.uuid)\n"
        md += "- 最低系统：\(macho.header.minOS) SDK：\(macho.header.sdk)\n"
        md += "- PIE：\(macho.header.isPIE ? "是" : "否") 加密：\(macho.header.isEncrypted ? "cryptid \(macho.header.cryptid)" : "无")\n"
        md += "- 风险评分：\(auditScore)/100（\(riskLevel)）\n"
        md += "- 依赖库：\(macho.dylibs.count) 导出符号：\(macho.exportedCount) 导入符号：\(macho.importedCount)\n"
        md += "- ObjC 类：\(classes.count) Swift 类型：\(swiftTypeCount)\n"
        md += "- 字符串：\(strings.count) 端点：\(endpoints.count) 密钥命中：\(secrets.count) SDK：\(sdks.count)\n\n"

        if !warnings.isEmpty {
            md += "## 警告\n" + warnings.map { "- \($0)" }.joined(separator: "\n") + "\n\n"
        }
        if !audit.isEmpty {
            md += "## 安全审计\n"
            for f in audit {
                md += "- [\(f.severity.rawValue)] \(f.title) — \(f.evidence)\n"
            }
            md += "\n"
        }
        if !secrets.isEmpty {
            md += "## 密钥扫描\n"
            for s in secrets {
                md += "- [\(s.severity.rawValue)] \(s.provider) \(s.kind) `\(s.masked)` 熵=\(String(format: "%.2f", s.entropy)) clientSafe=\(s.clientSafe ? "yes" : "no") FP=\(s.falsePositive.rawValue)\n"
            }
            md += "\n"
        }
        if !endpoints.isEmpty {
            md += "## 端点\n"
            for (host, items) in Endpoints.grouped(endpoints) {
                md += "### \(host)\n" + items.map { "- `\($0.display)`" }.joined(separator: "\n") + "\n"
            }
            md += "\n"
        }
        if !sdks.isEmpty {
            md += "## 第三方 SDK\n" + sdks.map { "- \($0.name)（\($0.category)）\($0.evidence)" }.joined(separator: "\n") + "\n\n"
        }
        if !classes.isEmpty {
            md += "## ObjC 类（前 80）\n"
            for c in classes.prefix(80) {
                md += "- `\(c.name)` : \(c.superName) · 方法 \(c.methodCount) · 属性 \(c.properties.count)\n"
            }
            md += "\n"
        }
        if let ent = entitlements {
            md += "## Entitlements\n```\n" + PlistTools.display(ent) + "\n```\n\n"
        }
        md += "## 依赖库\n" + macho.dylibs.map { "- [\($0.kind)] \($0.path)" }.joined(separator: "\n") + "\n"
        return md
    }

    public var json: String {
        var dict: [String: Any] = [
            "source": sourceName,
            "size": fileSize,
            "arch": macho.header.arch,
            "type": macho.header.typeName,
            "uuid": macho.header.uuid,
            "minOS": macho.header.minOS,
            "sdk": macho.header.sdk,
            "pie": macho.header.isPIE,
            "cryptid": macho.header.cryptid,
            "riskScore": auditScore,
            "riskLevel": riskLevel,
            "dylibs": macho.dylibs.map { $0.path },
            "exported": macho.exportedCount,
            "imported": macho.importedCount,
            "objcClasses": classes.count,
            "swiftTypes": swiftTypeCount,
            "strings": strings.count,
            "secrets": secrets.map { ["provider": $0.provider, "kind": $0.kind, "masked": $0.masked,
                                      "severity": $0.severity.rawValue, "clientSafe": $0.clientSafe,
                                      "entropy": $0.entropy] },
            "endpoints": endpoints.map { $0.display },
            "audit": audit.map { ["title": $0.title, "severity": $0.severity.rawValue, "evidence": $0.evidence] },
            "sdks": sdks.map { ["name": $0.name, "category": $0.category, "evidence": $0.evidence] },
            "warnings": warnings
        ]
        if let ent = entitlements { dict["entitlements"] = PlistTools.flatten(ent).reduce(into: [String: String]()) { $0[$1.0] = $1.1 } }
        if let info = infoPlist {
            dict["bundleId"] = info["CFBundleIdentifier"] as? String ?? ""
            dict["executable"] = info["CFBundleExecutable"] as? String ?? ""
        }
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}

public enum Analyzer {
    public static func analyze(url: URL, progress: ((String) -> Void)? = nil) throws -> AnalysisReport {
        var report = AnalysisReport()
        report.sourceName = url.lastPathComponent
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        report.fileSize = (attrs?[.size] as? NSNumber)?.intValue ?? 0

        var root = url
        var binaryURL: URL?
        let ext = url.pathExtension.lowercased()

        if ext == "ipa" || ext == "zip" {
            progress?("解包归档…")
            let data = try Data(contentsOf: url)
            let zip = try ZipArchive(data: data)
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("rekit-\(UUID().uuidString)", isDirectory: true)
            try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            try zip.extract(to: tmp)
            if let appPrefix = zip.appBundlePath() {
                let appDir = tmp.appendingPathComponent(String(appPrefix.dropLast()))
                root = appDir
                report.infoPlist = PlistTools.loadDictionary(url: appDir.appendingPathComponent("Info.plist"))
                if let exe = report.infoPlist?["CFBundleExecutable"] as? String {
                    let candidate = appDir.appendingPathComponent(exe)
                    if FileManager.default.fileExists(atPath: candidate.path) { binaryURL = candidate }
                }
                progress?("已解出 \(appDir.lastPathComponent)")
            } else {
                report.warnings.append("归档内未找到 Payload/*.app 结构")
            }
        } else if ext == "app" || (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
            report.infoPlist = PlistTools.loadDictionary(url: url.appendingPathComponent("Info.plist"))
            if let exe = report.infoPlist?["CFBundleExecutable"] as? String {
                let candidate = url.appendingPathComponent(exe)
                if FileManager.default.fileExists(atPath: candidate.path) { binaryURL = candidate }
            }
            if binaryURL == nil {
                let contents = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
                for name in contents where !name.contains(".") {
                    let candidate = url.appendingPathComponent(name)
                    if let head = try? Data(contentsOf: candidate, options: .mappedIfSafe), head.count >= 4 {
                        let magic = ByteReader(head).u32(0)
                        if magic == MachOConstants.MH_MAGIC || magic == MachOConstants.MH_MAGIC_64
                            || magic == MachOConstants.FAT_MAGIC || magic == MachOConstants.FAT_MAGIC_64 {
                            binaryURL = candidate
                            break
                        }
                    }
                }
            }
        } else {
            binaryURL = url
        }

        guard let bin = binaryURL else {
            throw MachOError.truncated("未定位到主 Mach-O 二进制")
        }
        report.binaryURL = bin
        progress?("解析 Mach-O…")
        let data = try Data(contentsOf: bin, options: .mappedIfSafe)
        var macho = try MachOParser.parse(data: data)
        macho.url = bin
        report.macho = macho

        // Re-read the exact slice the parser used so vm offsets line up for ObjC / entitlements.
        var sliceBytes = [UInt8](data)
        if macho.slices.count > 1, let best = macho.slices.max(by: { $0.size < $1.size }) {
            let r = ByteReader(data)
            sliceBytes = r.slice(best.offset, best.size)
        }
        report.sourceBytes = sliceBytes
        if !macho.header.is64 { report.warnings.append("32 位二进制：ObjC 元数据静态解析已跳过") }

        progress?("提取字符串…")
        report.strings = StringsScan.extract(data, minLength: 6, limit: 80_000)

        if macho.header.is64 {
            progress?("解析 ObjC 元数据…")
            report.classes = ObjCDump.classes(from: macho, bytes: sliceBytes)
            report.swiftTypeCount = macho.allSections
                .filter { $0.name == "__swift5_types" }.reduce(0) { $0 + Int($1.size) / 4 }
        }

        progress?("扫描密钥…")
        report.secrets = SecretScan.scan(data, strings: report.strings)

        progress?("汇总端点与 SDK…")
        report.endpoints = Endpoints.extract(from: report.strings)
        report.sdks = SDKFingerprint.detect(file: macho, classes: report.classes, strings: report.strings)

        progress?("熵值分析…")
        report.entropy = Entropy.sectionMap(file: macho, bytes: sliceBytes)

        progress?("解析签名与 Entitlements…")
        report.entitlements = Entitlements.extract(file: macho, bytes: sliceBytes)
        if report.infoPlist == nil, let dir = bin.deletingLastPathComponent() as URL? {
            report.infoPlist = PlistTools.loadDictionary(url: dir.appendingPathComponent("Info.plist"))
        }

        progress?("安全审计…")
        let byCategory = Dictionary(grouping: report.strings) { StringsScan.Category(rawValue: $0.category) ?? .other }
        report.audit = SecurityAudit.audit(file: macho, bytes: sliceBytes, strings: report.strings,
                                           stringsByCategory: byCategory, infoPlist: report.infoPlist)
        progress?("完成")
        return report
    }
}
