import SwiftUI
import REKit

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @State private var tab: Int = 0

    var body: some View {
        TabView(selection: $tab) {
            AnalyzeView()
                .tabItem { Label("静态", systemImage: "doc.viewfinder") }
                .tag(0)
            RuntimeView()
                .tabItem { Label("运行时", systemImage: "bolt.horizontal") }
                .tag(1)
            InjectView()
                .tabItem { Label("注入", systemImage: "syringe") }
                .tag(2)
            FridaView()
                .tabItem { Label("Frida", systemImage: "wand.and.stars") }
                .tag(3)
            ToolsView()
                .tabItem { Label("工具", systemImage: "square.grid.2x2") }
                .tag(4)
        }
    }
}

struct AnalyzeView: View {
    @EnvironmentObject var model: AppModel
    @State private var showPicker = false
    @State private var shareURL: URL?
    @State private var textInput: String = ""

    var body: some View {
        NavigationView {
            List {
                Section {
                    Button {
                        showPicker = true
                    } label: {
                        HStack {
                            Image(systemName: "tray.and.arrow.down")
                            Text("导入 IPA / .app / Mach-O / dylib")
                        }
                    }
                    if model.busy {
                        HStack {
                            ProgressView()
                            Text(model.status).font(.caption)
                        }
                    } else {
                        Text(model.status).font(.caption).foregroundColor(.secondary)
                    }
                    if let error = model.errorMessage {
                        Text(error).font(.caption).foregroundColor(.red)
                    }
                }

                Section(header: Text("沙盒路径（输入绝对路径直接分析）")) {
                    TextField("/var/containers/Bundle/Application/.../Payload/App.app", text: $textInput)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button("分析该路径") {
                        model.analyze(URL(fileURLWithPath: textInput))
                    }
                    .disabled(textInput.isEmpty)
                    ForEach(Workspace.probeRoots, id: \.self) { root in
                        HStack {
                            Text(root).font(.caption2).foregroundColor(.secondary)
                            Spacer()
                            Text(FileManager.default.fileExists(atPath: root) ? "可读" : "不可达")
                                .font(.caption2)
                                .foregroundColor(FileManager.default.fileExists(atPath: root) ? .green : .gray)
                        }
                    }
                }

                if let report = model.report {
                    Section(header: Text("报告")) {
                        NavigationLink(destination: ReportHomeView(report: report)) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(report.sourceName).font(.headline)
                                Text("\(report.macho.header.arch) · \(report.macho.header.typeName) · 风险 \(report.riskLevel)")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                HStack(spacing: 6) {
                                    SeverityBadge(severity: report.auditScore > 20 ? .high : .info)
                                    Text("类 \(report.classes.count) · 字符串 \(report.strings.count) · 密钥 \(report.secrets.count)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        Button("导出 Markdown") {
                            shareURL = model.saveReport(ext: "md")
                        }
                        Button("导出 JSON") {
                            shareURL = model.saveReport(ext: "json")
                        }
                    }
                }

                Section(header: Text("最近文件")) {
                    ForEach(model.recent, id: \.self) { url in
                        Button {
                            model.analyze(url)
                        } label: {
                            VStack(alignment: .leading) {
                                Text(url.lastPathComponent).font(.callout)
                                Text(url.path).font(.caption2).foregroundColor(.secondary).lineLimit(1)
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("REKit")
            .sheet(isPresented: $showPicker) {
                DocumentPicker { urls in
                    if let first = urls.first { model.analyze(first) }
                }
            }
            .sheet(item: Binding(get: { shareURL.map(ShareItem.init) }, set: { _ in shareURL = nil })) { item in
                ShareSheet(items: [item.url])
            }
            .onAppear { model.refreshRecent() }
        }
        .navigationViewStyle(.stack)
    }
}

struct ShareItem: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}
