import SwiftUI
import REKit

struct StringsView: View {
    let report: AnalysisReport
    @State private var category: StringsScan.Category?
    @State private var query = ""

    var items: [StringHit] {
        var list = StringsScan.filter(report.strings, category: category)
        if !query.isEmpty { list = list.filter { $0.value.localizedCaseInsensitiveContains(query) } }
        return Array(list.prefix(1500))
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    chip(nil, "全部")
                    ForEach(StringsScan.Category.allCases, id: \.self) { c in chip(c, c.rawValue) }
                }
                .padding(.horizontal)
                .padding(.vertical, 6)
            }
            List(items) { hit in
                VStack(alignment: .leading, spacing: 2) {
                    Text(hit.value).font(.system(size: 11, design: .monospaced)).lineLimit(3)
                    Text("0x\(String(hit.offset, radix: 16)) · \(hit.category)\(hit.utf16 ? " · UTF16" : "")")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .searchable(text: $query, prompt: "字符串内容")
        .navigationTitle("字符串 \(StringsScan.filter(report.strings, category: category).count)")
    }

    func chip(_ value: StringsScan.Category?, _ title: String) -> some View {
        Button {
            category = value
        } label: {
            Text(title)
                .font(.caption)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(category == value ? Color.accentColor.opacity(0.25) : Color(UIColor.secondarySystemBackground))
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

struct EndpointsView: View {
    let report: AnalysisReport
    @State private var query = ""

    var groups: [(host: String, items: [EndpointHit])] {
        let base = query.isEmpty ? report.endpoints
            : report.endpoints.filter { $0.url.localizedCaseInsensitiveContains(query) }
        return Endpoints.grouped(base)
    }

    var body: some View {
        List {
            ForEach(groups, id: \.host) { group in
                Section(header: Text("\(group.host)  (\(group.items.count))")) {
                    ForEach(group.items) { ep in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ep.display).font(.system(size: 11, design: .monospaced))
                            if !ep.scheme.lowercased().hasPrefix("https") {
                                Text("非 HTTPS").font(.caption2).foregroundColor(.orange)
                            }
                        }
                    }
                }
            }
        }
        .searchable(text: $query, prompt: "host / path")
        .navigationTitle("端点")
    }
}

struct SecretsView: View {
    let report: AnalysisReport

    var body: some View {
        List {
            ForEach(Severity.allCases, id: \.self) { sev in
                let items = report.secrets.filter { $0.severity == sev }
                if !items.isEmpty {
                    Section(header: HStack { SeverityBadge(severity: sev); Text("\(items.count) 条") }) {
                        ForEach(items) { s in
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(s.provider) · \(s.kind)")
                                    .font(.callout)
                                Text(s.masked).font(.system(size: 11, design: .monospaced))
                                Text("熵 \(String(format: "%.2f", s.entropy)) · 客户端安全 \(s.clientSafe ? "是" : "否") · 误报倾向 \(s.falsePositive.rawValue) · offset 0x\(String(s.offset, radix: 16))")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("密钥扫描")
    }
}

struct SDKView: View {
    let report: AnalysisReport

    var body: some View {
        List(report.sdks) { sdk in
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(sdk.name).font(.callout.bold())
                    Text(sdk.category).font(.caption2).foregroundColor(.secondary)
                }
                Text(sdk.evidence).font(.caption2).foregroundColor(.secondary)
                Text(sdk.note).font(.caption2)
            }
        }
        .navigationTitle("第三方 SDK")
    }
}

struct AuditView: View {
    let report: AnalysisReport

    var body: some View {
        List {
            Section(header: Text("风险评分 \(report.auditScore)/100 · \(report.riskLevel)")) {
                ProgressView(value: min(Double(report.auditScore) / 100.0, 1.0))
            }
            ForEach(Severity.allCases, id: \.self) { sev in
                let items = report.audit.filter { $0.severity == sev }
                if !items.isEmpty {
                    Section(header: Text(sev.rawValue)) {
                        ForEach(items) { f in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    SeverityBadge(severity: f.severity)
                                    Text(f.title).font(.callout)
                                }
                                Text(f.evidence).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary)
                                Text(f.impact).font(.caption2)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("安全审计")
    }
}

struct EntitlementsView: View {
    let report: AnalysisReport

    var body: some View {
        Group {
            if let ent = report.entitlements {
                MonoBlock(text: PlistTools.display(ent))
            } else {
                Text("未找到嵌入的 entitlements（可能未签名或签名已剥离）")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding()
            }
        }
        .navigationTitle("Entitlements")
    }
}

struct InfoPlistView: View {
    let report: AnalysisReport

    var body: some View {
        Group {
            if let info = report.infoPlist {
                MonoBlock(text: PlistTools.display(info))
            } else {
                Text("未找到 Info.plist").font(.caption).foregroundColor(.secondary).padding()
            }
        }
        .navigationTitle("Info.plist")
    }
}

struct DylibsView: View {
    let report: AnalysisReport

    var body: some View {
        List(report.macho.dylibs) { lib in
            VStack(alignment: .leading, spacing: 2) {
                Text(lib.path).font(.system(size: 11, design: .monospaced))
                Text("[\(lib.kind)] cur \(lib.currentVersion) compat \(lib.compatibilityVersion)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("依赖库")
    }
}
