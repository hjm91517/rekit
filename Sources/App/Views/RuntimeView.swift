import SwiftUI
import REKit

struct RuntimeView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""
    @State private var images: [String] = []
    @State private var symbol = "_objc_msgSend"
    @State private var symbolResult = ""
    @State private var targetClass = ""
    @State private var targetSelector = ""
    @State private var status = ""
    @State private var showImages = false

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("运行时状态")) {
                    KVRow(key: "已加载 image", value: "\(images.count)")
                    KVRow(key: "主二进制 chained fixups", value: Interpose.mainBinaryHasChainedFixups ? "有" : "无")
                    Button("刷新 image 列表与类表") {
                        images = Runtime.loadedImages
                        model.loadLiveClasses(filter: query)
                        status = "已刷新"
                    }
                }

                Section(header: Text("类浏览 (\(model.liveClasses.count))")) {
                    TextField("按类名过滤（留空取前 4000）", text: $query)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button("应用过滤") { model.loadLiveClasses(filter: query) }
                    ForEach(model.liveClasses.prefix(300)) { cls in
                        NavigationLink(destination: LiveClassDetailView(cls: cls)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(cls.name).font(.system(size: 12, design: .monospaced))
                                Text("方法 \(cls.methodCount) · ivar \(cls.ivarCount) · 协议 \(cls.protocolCount)\(cls.isSwift ? " · Swift" : "")")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }

                Section(header: Text("符号解析")) {
                    TextField("符号名，如 _objc_msgSend", text: $symbol)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button("dlsym") {
                        if let addr = Runtime.resolve(symbol: symbol) {
                            symbolResult = "0x" + String(addr, radix: 16)
                        } else {
                            symbolResult = "未解析到符号"
                        }
                    }
                    if !symbolResult.isEmpty { Text(symbolResult).font(.system(.caption, design: .monospaced)) }
                }

                Section(header: Text("方法调用跟踪（0 参数）")) {
                    TextField("类名", text: $targetClass)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("选择器，如 description", text: $targetSelector)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    HStack {
                        Button("挂跟踪") {
                            let r = SwizzleTracer.trace(className: targetClass, selector: targetSelector)
                            status = r.1
                        }
                        Button("调用一次") {
                            status = Runtime.invoke(className: targetClass, selector: targetSelector)
                        }
                    }
                    Text(status).font(.caption).foregroundColor(.secondary)
                }

                Section(header: Text("跟踪日志 (\(SwizzleTracer.log.count))")) {
                    Button("清空") { SwizzleTracer.clear(); status = "已清空" }
                    ForEach(SwizzleTracer.log.suffix(60)) { e in
                        Text("\(e.className) -\(e.selector)").font(.system(size: 10, design: .monospaced))
                    }
                }

                Section(header: Text("反调试 / 越狱屏蔽")) {
                    Button("安装 ptrace + sysctl 绕过") {
                        let s = Interpose.installAntiDebug()
                        model.append("\(s.name): \(s.summary)")
                    }
                    Button("安装路径屏蔽（stat/lstat/access/fopen）") {
                        let s = Interpose.installJailbreakMask()
                        model.append("\(s.name): \(s.summary)")
                    }
                    ForEach(model.interposeLog, id: \.self) { line in
                        Text(line).font(.caption2)
                    }
                }

                Section {
                    Toggle("image 列表", isOn: $showImages)
                    if showImages {
                        ForEach(images.prefix(200), id: \.self) { img in
                            Text(img).font(.system(size: 9, design: .monospaced))
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("运行时")
            .onAppear {
                if images.isEmpty {
                    images = Runtime.loadedImages
                    model.loadLiveClasses(filter: "")
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}

struct LiveClassDetailView: View {
    let cls: LiveClass
    @State private var methods: [LiveMethod] = []
    @State private var ivars: [LiveIvar] = []

    var body: some View {
        List {
            Section(header: Text("类信息")) {
                KVRow(key: "父类", value: cls.superName)
                KVRow(key: "方法", value: "\(cls.methodCount)")
                KVRow(key: "实例变量", value: "\(cls.ivarCount)")
                KVRow(key: "协议", value: "\(cls.protocolCount)")
            }
            if !ivars.isEmpty {
                Section(header: Text("实例变量")) {
                    ForEach(ivars) { iv in
                        Text("\(iv.type) \(iv.name) @ \(iv.offset)").font(.system(size: 10, design: .monospaced))
                    }
                }
            }
            Section(header: Text("方法")) {
                ForEach(methods) { m in
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(m.isClassMethod ? "+" : "-") \(m.selector)").font(.system(size: 11, design: .monospaced))
                        Text(m.types).font(.system(size: 9, design: .monospaced)).foregroundColor(.secondary)
                    }
                }
            }
        }
        .navigationTitle(cls.name)
        .onAppear {
            methods = Runtime.methods(of: cls.name)
            ivars = Runtime.ivars(of: cls.name)
        }
    }
}
