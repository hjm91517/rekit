import SwiftUI
import REKit

struct ReportHomeView: View {
    let report: AnalysisReport

    var body: some View {
        List {
            Section(header: Text("概览")) {
                NavigationLink("Mach-O 头", destination: MachODetailView(report: report))
                NavigationLink("加载命令 (\(report.macho.commands.count))", destination: CommandsView(report: report))
                NavigationLink("段与节 (\(report.macho.allSections.count))", destination: SegmentsView(report: report))
                NavigationLink("符号 (导出 \(report.macho.exportedCount) / 导入 \(report.macho.importedCount))",
                               destination: SymbolsView(report: report))
                NavigationLink("ObjC 类 (\(report.classes.count))", destination: ClassesView(report: report))
                NavigationLink("Swift 类型 (\(report.swiftTypeCount))", destination: SwiftTypesView(report: report))
                NavigationLink("熵值地图", destination: EntropyView(report: report))
                NavigationLink("Hex 查看", destination: HexViewer(url: report.binaryURL, data: Data(report.sourceBytes.prefix(4 << 20)),
                                                                title: report.sourceName))
            }
            Section(header: Text("情报")) {
                NavigationLink("字符串 (\(report.strings.count))", destination: StringsView(report: report))
                NavigationLink("端点 (\(report.endpoints.count))", destination: EndpointsView(report: report))
                NavigationLink("密钥 (\(report.secrets.count))", destination: SecretsView(report: report))
                NavigationLink("第三方 SDK (\(report.sdks.count))", destination: SDKView(report: report))
            }
            Section(header: Text("审计")) {
                NavigationLink("安全检查 (\(report.audit.count)) · 评分 \(report.auditScore)", destination: AuditView(report: report))
                NavigationLink("Entitlements", destination: EntitlementsView(report: report))
                NavigationLink("Info.plist", destination: InfoPlistView(report: report))
                NavigationLink("依赖库 (\(report.macho.dylibs.count))", destination: DylibsView(report: report))
            }
            if !report.warnings.isEmpty {
                Section(header: Text("警告")) {
                    ForEach(report.warnings, id: \.self) { Text($0).font(.caption) }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(report.sourceName)
    }
}

struct MachODetailView: View {
    let report: AnalysisReport

    var rows: [(String, String)] {
        let h = report.macho.header
        return [
            ("架构", h.arch),
            ("类型", h.typeName),
            ("CPU", String(format: "0x%x / 0x%x", h.cpuType, h.cpuSubtype)),
            ("Flags", String(format: "0x%x", h.flags)),
            ("PIE", h.isPIE ? "开启" : "关闭"),
            ("加密", h.isEncrypted ? "cryptid \(h.cryptid) @0x\(String(h.cryptoff, radix: 16))" : "无"),
            ("UUID", h.uuid),
            ("平台", h.platform),
            ("最低系统 / SDK", "\(h.minOS) / \(h.sdk)"),
            ("链式重绑定", h.hasChainedFixups ? "LC_DYLD_CHAINED_FIXUPS" : "无"),
            ("入口", h.entryPoint.map { "0x" + String($0, radix: 16) } ?? "-"),
            ("构建", h.buildTool.isEmpty ? "-" : h.buildTool),
            ("加载命令 / 大小", "\(h.ncmds) / \(h.sizeofcmds) bytes"),
            ("切片", report.macho.slices.map { "\($0.arch)(\($0.size))" }.joined(separator: ", ")),
        ]
    }

    var body: some View {
        List {
            Section(header: Text("头信息")) {
                ForEach(rows, id: \.0) { KVRow(key: $0.0, value: $0.1) }
            }
            Section(header: Text("Flags")) {
                ForEach(report.macho.header.flagNames, id: \.self) { Text($0).font(.caption.monospaced()) }
            }
            if !report.macho.rpaths.isEmpty {
                Section(header: Text("RPATH")) {
                    ForEach(report.macho.rpaths, id: \.self) { Text($0).font(.caption.monospaced()) }
                }
            }
        }
        .navigationTitle("Mach-O")
    }
}

struct CommandsView: View {
    let report: AnalysisReport
    @State private var query = ""

    var filtered: [LoadCommandInfo] {
        guard !query.isEmpty else { return report.macho.commands }
        return report.macho.commands.filter { $0.name.lowercased().contains(query.lowercased()) || $0.detail.lowercased().contains(query.lowercased()) }
    }

    var body: some View {
        List(filtered) { cmd in
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text("#\(cmd.index)").font(.caption2).foregroundColor(.secondary)
                    Text(cmd.name).font(.system(.callout, design: .monospaced))
                    Spacer()
                    Text("\(cmd.size)B").font(.caption2).foregroundColor(.secondary)
                }
                Text(cmd.detail).font(.caption2).foregroundColor(.secondary)
            }
        }
        .searchable(text: $query, prompt: "过滤命令")
        .navigationTitle("加载命令")
    }
}

struct SegmentsView: View {
    let report: AnalysisReport

    var body: some View {
        List {
            ForEach(report.macho.segments) { seg in
                Section(header: Text("\(seg.name)  \(seg.prot)  vm 0x\(String(seg.vmaddr, radix: 16))")) {
                    ForEach(seg.sections) { sec in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sec.display).font(.system(.caption, design: .monospaced))
                            Text("addr 0x\(String(sec.addr, radix: 16)) size \(sec.size) off 0x\(String(sec.offset, radix: 16)) \(sec.typeName)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
        }
        .navigationTitle("段与节")
    }
}

struct SymbolsView: View {
    let report: AnalysisReport
    @State private var query = ""
    @State private var onlyImports = false

    var filtered: [SymbolInfo] {
        var list = report.macho.symbols
        if onlyImports { list = list.filter { $0.undefined } }
        if !query.isEmpty {
            list = list.filter { $0.name.localizedCaseInsensitiveContains(query) }
        }
        return Array(list.prefix(1000))
    }

    var body: some View {
        List {
            Toggle("只看未定义（导入）", isOn: $onlyImports)
            ForEach(filtered) { sym in
                VStack(alignment: .leading, spacing: 2) {
                    Text(sym.name).font(.system(size: 11, design: .monospaced))
                    Text("\(sym.kind) · 0x\(String(sym.value, radix: 16)) · sect \(sym.sect)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .searchable(text: $query, prompt: "符号名")
        .navigationTitle("符号（最多 1000 条）")
    }
}

struct ClassesView: View {
    let report: AnalysisReport
    @State private var query = ""

    var filtered: [ObjCClassInfo] {
        guard !query.isEmpty else { return report.classes }
        return report.classes.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        List(filtered) { cls in
            NavigationLink(destination: ClassDetailView(cls: cls)) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(cls.name).font(.callout)
                    Text(": \(cls.superName) · 方法 \(cls.methodCount) · 实例变量 \(cls.ivars.count) · 属性 \(cls.properties.count)\(cls.isSwift ? " · Swift" : "")")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .searchable(text: $query, prompt: "类名")
        .navigationTitle("ObjC 类")
    }
}

struct ClassDetailView: View {
    let cls: ObjCClassInfo

    var body: some View {
        List {
            Section(header: Text("头文件导出")) {
                ScrollView(.horizontal) {
                    Text(cls.headerDump)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            if !cls.classMethods.isEmpty {
                Section(header: Text("类方法")) {
                    ForEach(cls.classMethods) { m in Text("+ \(m.name)").font(.system(size: 11, design: .monospaced)) }
                }
            }
            Section(header: Text("实例方法")) {
                ForEach(cls.methods) { m in
                    VStack(alignment: .leading, spacing: 1) {
                        Text("- \(m.name)").font(.system(size: 11, design: .monospaced))
                        Text(m.types).font(.system(size: 9, design: .monospaced)).foregroundColor(.secondary)
                    }
                }
            }
            if !cls.ivars.isEmpty {
                Section(header: Text("实例变量")) {
                    ForEach(cls.ivars) { iv in
                        Text("\(iv.type) \(iv.name)  // \(iv.offset)").font(.system(size: 10, design: .monospaced))
                    }
                }
            }
            if !cls.properties.isEmpty {
                Section(header: Text("属性")) {
                    ForEach(cls.properties) { p in
                        Text("\(p.name)  \(p.attributes)").font(.system(size: 10, design: .monospaced))
                    }
                }
            }
        }
        .navigationTitle(cls.name)
    }
}

struct SwiftTypesView: View {
    let report: AnalysisReport

    var sections: [SectionInfo] {
        report.macho.allSections.filter { $0.name.hasPrefix("__swift5") }
    }

    var body: some View {
        List(sections) { sec in
            VStack(alignment: .leading, spacing: 2) {
                Text(sec.display).font(.system(.callout, design: .monospaced))
                Text("size \(sec.size) · 约 \(sec.name == "__swift5_types" ? Int(sec.size) / 4 : 0) 个元数据条目")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("Swift 元数据")
    }
}

struct EntropyView: View {
    let report: AnalysisReport

    var body: some View {
        List(report.entropy) { item in
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(item.section).font(.system(.caption, design: .monospaced))
                    Spacer()
                    Text(String(format: "%.2f", item.entropy))
                        .font(.caption.bold())
                        .foregroundColor(item.packed ? .red : .secondary)
                }
                ProgressView(value: min(item.entropy / 8.0, 1.0))
                    .tint(item.packed ? .red : .green)
                Text("size \(item.size)\(item.packed ? " · 疑似压缩/加密" : "")")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .navigationTitle("熵值")
    }
}
