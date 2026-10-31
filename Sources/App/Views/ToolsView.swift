import SwiftUI
import CryptoKit
import REKit

struct ToolsView: View {
    @State private var text = "hello rekit"
    @State private var hexInput = ""
    @State private var filePath = ""
    @State private var showPicker = false
    @State private var pickedData: Data?
    @State private var shareURL: URL?

    var sha256: String {
        let digest = SHA256.hash(data: Data(text.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    var md5: String {
        let digest = Insecure.MD5.hash(data: Data(text.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("编码")) {
                    TextField("文本", text: $text)
                        .font(.system(.caption, design: .monospaced))
                    Text("base64: \(Data(text.utf8).base64EncodedString())")
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                    Text("hex: \(Data(text.utf8).map { String(format: "%02x", $0) }.joined())")
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                    Text("SHA256: \(sha256)").font(.system(size: 9, design: .monospaced)).textSelection(.enabled)
                    Text("MD5: \(md5)").font(.system(size: 9, design: .monospaced)).textSelection(.enabled)
                }

                Section(header: Text("Hex 解码")) {
                    TextField("如 68656c6c6f", text: $hexInput)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Text(decodedHex).font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                }

                Section(header: Text("文件")) {
                    TextField("/path/to/binary", text: $filePath)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button("从文件选择") { showPicker = true }
                    if let data = pickedData {
                        KVRow(key: "大小", value: "\(data.count) bytes")
                        KVRow(key: "SHA256", value: String(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined().prefix(24)) + "…")
                        NavigationLink("Hex 查看") {
                            HexViewer(url: URL(fileURLWithPath: filePath), data: data, title: "Hex")
                        }
                    }
                }

                Section(header: Text("模块")) {
                    NavigationLink("REKit 能力清单", destination: CapabilityView())
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("工具")
            .sheet(isPresented: $showPicker) {
                DocumentPicker { urls in
                    guard let first = urls.first else { return }
                    filePath = first.path
                    pickedData = try? Data(contentsOf: first, options: .mappedIfSafe)
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    var decodedHex: String {
        var bytes: [UInt8] = []
        var i = hexInput.startIndex
        while i < hexInput.endIndex {
            let next = hexInput.index(i, offsetBy: 2, limitedBy: hexInput.endIndex) ?? hexInput.endIndex
            if let b = UInt8(hexInput[i..<next], radix: 16) { bytes.append(b) }
            i = next
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

struct HexViewer: View {
    let url: URL?
    let data: Data
    let title: String
    @State private var page = 0
    private let pageSize = 64 * 1024

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if data.count > pageSize {
                HStack {
                    Button("上一页") { page = max(0, page - 1) }
                    Spacer()
                    Text("\(page + 1)/\(max(1, (data.count + pageSize - 1) / pageSize))")
                        .font(.caption)
                    Spacer()
                    Button("下一页") { page = min((data.count - 1) / pageSize, page + 1) }
                }
                .padding(.horizontal)
            }
            MonoBlock(text: HexDump.lines(slice, baseOffset: page * pageSize, maxBytes: pageSize).joined(separator: "\n"))
        }
        .navigationTitle(title)
    }

    var slice: Data {
        let start = min(page * pageSize, max(0, data.count - 1))
        let end = min(start + pageSize, data.count)
        return data.subdata(in: start..<end)
    }
}

struct CapabilityView: View {
    let items: [(String, String)] = [
        ("Mach-O 解析", "瘦/胖二进制、切片选择、头字段、加载命令、段与节、RPATH、UUID、构建版本"),
        ("符号", "LC_SYMTAB 全量符号、导入/导出分类、地址与 section 归属"),
        ("ObjC 静态", "__objc_classlist / __objc_catlist：类、父类、方法（含相对方法表）、ivar、属性，导出 @interface"),
        ("Swift", "__swift5_types 元数据规模统计与节扫描"),
        ("字符串", "ASCII + UTF-16LE 双通道，自动归类 URL/路径/邮箱/IP/Base64/密钥"),
        ("端点", "按 host 归组，标记非 HTTPS 端点"),
        ("密钥审计", "18 条规则 + 熵值 + 占位符白名单 + clientSafe 标记 + 误报倾向"),
        ("安全审计", "PIE、FairPlay、__RESTRICT、ATS、URL Scheme、弱加密、WebView、越狱检测、反调试特征"),
        ("SDK 指纹", "20 个常见 SDK：网络/支付/统计/广告/推送/音视频/安全"),
        ("熵值地图", "逐节 Shannon 熵，标记疑似压缩/加密节"),
        ("签名", "LC_CODE_SIGNATURE 中提取 entitlements XML"),
        ("归档", "自研 ZIP 读取（stored + raw deflate），支持 IPA 直接解包分析"),
        ("注入", "头填充内写入 LC_LOAD_DYLIB，校验剩余空间，失败不产出坏文件"),
        ("签名工具", "ldid / codesign 探测与 posix_spawn 调用（iOS 无 Process）"),
        ("运行时", "类表/方法/ivar/协议枚举、dlsym 解析、0 参数方法调用与跟踪"),
        ("Interpose", "经典 __la_symbol_ptr/__got 重绑定 + chained fixups bind 链解码"),
        ("Frida", "按需生成带 guard 的 agent.js，事件预算 1000 条"),
        ("报告", "Markdown / JSON 双格式导出"),
    ]

    var body: some View {
        List(items, id: \.0) { item in
            VStack(alignment: .leading, spacing: 2) {
                Text(item.0).font(.callout.bold())
                Text(item.1).font(.caption2).foregroundColor(.secondary)
            }
        }
        .navigationTitle("能力清单")
    }
}
