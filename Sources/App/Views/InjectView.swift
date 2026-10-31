import SwiftUI
import REKit

struct InjectView: View {
    @EnvironmentObject var model: AppModel
    @State private var binaryPath = ""
    @State private var dylibPath = "@executable_path/Frameworks/REKitHook.dylib"
    @State private var outputName = "patched-binary"
    @State private var result = ""
    @State private var signed = ""
    @State private var showPicker = false
    @State private var lastOutput: URL?

    var patchedURL: URL {
        Workspace.root.appendingPathComponent(outputName)
    }

    var deployScript: String {
        """
        # 1. 打补丁（本 App 内完成）
        #    输入二进制: \(binaryPath.isEmpty ? "<未选>" : binaryPath)
        #    注入 dylib : \(dylibPath)
        # 2. 重新签名（ldid）
        ldid -S \(outputName)            # 带 entitlements: ldid -S ent.plist \(outputName)
        # 3. 推回设备/打包
        cp \(outputName) "Payload/App.app/App"
        cp \(DylibInjector.suggestedDylibName(from: dylibPath)).dylib "Payload/App.app/Frameworks/"
        zip -r repacked.ipa Payload
        # 4. 安装（越狱设备 / 自签工具）
        #   Filza 覆盖 · TrollStore 安装 · ideviceinstaller -i repacked.ipa
        """
    }

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("目标二进制")) {
                    TextField("/path/to/App.app/App", text: $binaryPath)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button("从文件选择") { showPicker = true }
                }

                Section(header: Text("注入项")) {
                    TextField("dylib 路径", text: $dylibPath)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("输出文件名", text: $outputName)
                        .font(.system(.caption, design: .monospaced))
                    Button("写入 LC_LOAD_DYLIB") {
                        do {
                            let r = try DylibInjector.inject(dylibPath: dylibPath,
                                                            binary: URL(fileURLWithPath: binaryPath),
                                                            output: patchedURL)
                            lastOutput = r.outputURL
                            result = (r.success ? "✅ " : "❌ ") + r.message + "  [切片 \(r.sliceArch)]"
                        } catch {
                            result = "❌ \(error)"
                        }
                    }
                    if !result.isEmpty {
                        Text(result).font(.caption)
                    }
                }

                Section(header: Text("签名")) {
                    KVRow(key: "签名工具", value: Signer.findTool() ?? "未找到")
                    Button("ldid 重新签名补丁产物") {
                        guard let out = lastOutput else { signed = "先生成补丁产物"; return }
                        let r = Signer.sign(binary: out)
                        signed = "exit=\(r.code)\n\(r.invoked)\n\(r.log)"
                    }
                    if !signed.isEmpty {
                        Text(signed).font(.system(size: 10, design: .monospaced))
                    }
                }

                Section(header: Text("部署步骤")) {
                    MonoBlock(text: deployScript)
                        .frame(height: 220)
                }

                Section(header: Text("能力说明")) {
                    Text("""
                    只做头填充内写入 LC_LOAD_DYLIB，文件大小不变，不会破坏段偏移。
                    头填充不足时会明确报出还差多少字节，不会生成坏文件。
                    补丁会让原签名失效，必须重新签名；签名工具缺失时不会假装成功。
                    """)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Dylib 注入")
            .sheet(isPresented: $showPicker) {
                DocumentPicker { urls in
                    if let first = urls.first { binaryPath = first.path }
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}

struct FridaView: View {
    @State private var bundleID = "com.example.app"
    @State private var className = "NSString"
    @State private var selector = "- length"
    @State private var logBacktrace = false
    @State private var logObject = false
    @State private var script = ""
    @State private var shareURL: URL?

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("目标")) {
                    TextField("bundle id", text: $bundleID)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("类名", text: $className)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("选择器（- 或 + 前缀）", text: $selector)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Toggle("打印对象", isOn: $logObject)
                    Toggle("打印调用栈", isOn: $logBacktrace)
                }

                Section {
                    Button("生成 agent.js") {
                        script = FridaGen.script(bundleID: bundleID,
                                                 requests: [.init(className: className, selector: selector,
                                                                  logBacktrace: logBacktrace, logObject: logObject)])
                    }
                    Button("保存并分享") {
                        if script.isEmpty { script = FridaGen.script(bundleID: bundleID, requests: [.init(className: className, selector: selector, logBacktrace: logBacktrace, logObject: logObject)]) }
                        shareURL = Workspace.saveReport(script, name: "rekit-agent", ext: "js")
                    }
                }

                if !script.isEmpty {
                    Section(header: Text("预览")) {
                        MonoBlock(text: script).frame(height: 300)
                        Text(FridaGen.command(bundleID: bundleID, scriptPath: "agent.js"))
                            .font(.system(size: 10, design: .monospaced))
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Frida")
            .sheet(item: Binding(get: { shareURL.map(ShareItem.init) }, set: { _ in shareURL = nil })) { item in
                ShareSheet(items: [item.url])
            }
        }
        .navigationViewStyle(.stack)
    }
}
