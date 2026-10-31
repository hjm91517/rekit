# REKit — iOS 静态 + 动态逆向工作台

一个真机可跑（自签 / 越狱）的 iOS 逆向 App + 可复用 dylib 框架。全部解析逻辑自己实现，不依赖 otool / class-dump / radare2，因为 iOS 上根本没有这些东西。

- App：SwiftUI 六屏（静态分析、运行时、注入、Frida、工具）
- 框架：`REKit.framework`，纯 Swift + 少量 ObjC（zlib inflate、符号重绑定）
- 构建：GitHub Actions（macOS runner）编译 + 单测 + 打包未签名 IPA

## 能力

静态（`Sources/REKit`）：

| 模块 | 内容 |
| --- | --- |
| `MachOParser` | 瘦/胖二进制、切片选择、头字段、加载命令、段与节、RPATH、UUID、构建版本、FairPlay 字段 |
| `ObjCDump` | `__objc_classlist` / `__objc_catlist`：类、父类、方法（含相对方法表）、ivar、属性，导出 `@interface` |
| `StringsScan` | ASCII + UTF-16LE 双通道，自动归类 URL / 路径 / 邮箱 / IP / Base64 / 密钥 |
| `SecretScan` | 18 条规则 + Shannon 熵 + 占位符白名单 + clientSafe + 误报倾向 |
| `SecurityAudit` | PIE、FairPlay、`__RESTRICT`、ATS、URL Scheme、弱加密、WebView、越狱检测、反调试特征 |
| `SDKFingerprint` | 20 个常见 SDK（网络/支付/统计/广告/推送/音视频/安全） |
| `Entropy` | 逐节熵值，标记压缩/加密节 |
| `Entitlements` | 从 `LC_CODE_SIGNATURE` 抽 entitlements plist |
| `ZipArchive` | 自研 ZIP（stored + raw deflate，ObjC zlib），IPA 直接解包分析 |
| `DylibInjector` | 头填充内写入 `LC_LOAD_DYLIB`，空间不足直接报差多少字节，绝不产出坏文件 |
| `Signer` | `ldid` / `codesign` 探测 + `posix_spawn` 调用（iOS 没有 `Process`） |

动态：

| 模块 | 内容 |
| --- | --- |
| `Runtime` | 类表/方法/ivar/协议枚举、`dlsym` 解析、0 参数方法调用 |
| `SwizzleTracer` | 0 参数方法蹦床跟踪（保持 ABI 一致，带事件预算） |
| `REKInterpose.m` | 经典 `__la_symbol_ptr`/`__got` 重绑定 + `LC_DYLD_CHAINED_FIXUPS` bind 链解码 |
| `Interpose` | `ptrace`/`sysctl` 反调试绕过、`stat`/`lstat`/`access`/`fopen` 路径屏蔽 |
| `FridaGen` | 按类/选择器生成带 guard 的 `agent.js` |

## 架构

```
Sources/REKit/     逆向引擎（framework，可单独嵌入别的 App）
Sources/App/       SwiftUI 界面层，只调 REKit 的 public API
Tests/REKitTests/  XCTest：合成 Mach-O、注入边界、ZIP、熵、密钥规则、端到端分析
Config/            Info.plist、签名配置
scripts/           check_project.py（静态自检）、package_ipa.sh（打包）
.github/workflows/ CI：sanity → test → build
```

依赖方向单向：`App → REKit`，框架不知道 UI 存在。

## 构建

本地（macOS + Xcode 15）：

```bash
brew install xcodegen
xcodegen generate
xcodebuild -project REKit.xcodeproj -scheme REKitApp -sdk iphoneos -arch arm64 \
  CODE_SIGNING_ALLOWED=NO build
```

CI 直接推 main 即可，产物在 Actions artifacts：`REKitApp.ipa` + `manifest.txt`。

自签安装：`ldid -S REKitApp` 后重打包，或 TrollStore / 自签工具。

## 使用

1. 静态：把 IPA / `.app` / Mach-O 丢进文件 App，App 内「导入」→ 自动跑完整管线 → 报告九个子页。
2. 运行时：枚举已加载 image 与类表，挂 0 参数方法跟踪，读实时返回值。
3. 注入：填目标二进制路径 + dylib 路径 → 打 `LC_LOAD_DYLIB` → `ldid` 重签 → 按页面给的命令重打包。
4. Frida：填 bundle id / 类 / 选择器 → 生成 `agent.js` → 分享出去跑。

## 已验证 / 未验证（不吹）

已验证（CI 里跑）：

- `xcodebuild test` 在 iPhone 15 模拟器上跑通 9 个用例：合成 arm64 Mach-O 解析、宿主二进制解析、熵边界、密钥规则与占位符降级、ZIP stored 读回、注入成功与「填充不足拒绝」、plist 展开、端到端分析报告
- `xcodebuild build -sdk iphoneos -arch arm64` 编译通过并打出未签名 IPA
- `scripts/check_project.py` 结构自检：YAML/plist 可解析、括号配对、无硬编码密钥

未在 CI 里验证（需要真机）：

- 注入后的 App 实际启动（依赖具体目标 App 的签名与 dylib 依赖）
- `Interpose` 在真实 chained-fixups 镜像上的重绑定命中率（只有真机日志能证明）
- 越狱路径屏蔽对具体检测库的有效性
- Frida 脚本在真实进程里的输出

这些在 App 里都有明确的运行时状态输出（`InterposeStatus.summary`、`Signer.Result.log`），跑一次就知道命中多少，不是靠嘴说。

## 边界

- 32 位切片只解析头/命令/符号，ObjC 元数据静态解析跳过（界面会显示警告）
- ZIP64 不支持（>4GB 归档）
- 注入只在头填充内做，不做段搬移；空间不够就报错
- 方法蹦床只支持 0 参数方法——参数 ABI 不猜，猜错就是崩溃
- 不内置 ldid 二进制，工具缺失时会明确报「未找到」
