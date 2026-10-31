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

### CI 实测证据（run 41235851084，三个 job 全绿）

| 证据 | 结果 |
| --- | --- |
| `sanity`（ubuntu） | `check_project.py` 全项通过：project.yml 引用、Info.plist key、41 个源码文件括号配对、无硬编码密钥 |
| `test`（macos-latest，iPhone 模拟器） | `Executed 9 tests, with 0 failures` |
| `build`（macos-latest，arm64 真机） | `xcodebuild build` 通过，产出未签名 IPA |

9 个用例覆盖：合成 arm64 Mach-O 解析、宿主二进制（xctest 可执行文件）解析、Shannon 熵边界、密钥规则 + 占位符降级、ZIP stored 条目读回、`LC_LOAD_DYLIB` 注入成功、填充不足时拒绝注入、plist 展开、端到端分析报告。

### 产物实测（从 artifacts 下载后拆包核验）

```
Payload/REKitApp.app/REKitApp                       72,688 bytes   arm64 MH_EXECUTE, ncmds=21
  segments: __PAGEZERO __TEXT __DATA_CONST __DATA __LINKEDIT
  cmds 含 LC_DYLD_CHAINED_FIXUPS(0x80000034) / LC_ENCRYPTION_INFO_64 / LC_BUILD_VERSION
Payload/REKitApp.app/Frameworks/REKit.framework/    1,002,752 bytes arm64 MH_DYLIB, ncmds=30
  链接库 10 个，同样带 LC_DYLD_CHAINED_FIXUPS
bundle: com.chuck.rekitapp  minOS 15.0  framework: com.chuck.rekit (FMWK)
ipa 大小 701,835 bytes
```

也就是说：链式重绑定那条代码路径不是摆设——被测二进制自己就带 `LC_DYLD_CHAINED_FIXUPS`。

### CI 环境踩到的坑（已修，写下来省时间）

- `runs-on: macos-14` 在这个账号下会被秒取消（`runner_id: 0`、`steps: []`），换 `macos-latest` 才拿到真机 runner；`macos-13` 直接排队挂死。
- 框架 target 必须 `GENERATE_INFOPLIST_FILE: YES`，否则打包阶段报 `REKit.framework did not contain an Info.plist`。
- 模拟器名字不能写死：workflow 里先 `xcrun simctl list devices available` 挑第一台 iPhone，再拼 `-destination`，镜像换代不会炸。

### 还没验证（需要真机，不编）

- 注入后的 App 实际启动（取决于目标 App 的签名与 dylib 依赖是否齐全）
- `Interpose` 在真实第三方进程上的重绑定命中率（只有真机日志能证明）
- 越狱路径屏蔽对具体检测库的有效性
- Frida 脚本在真实进程里的输出
- 未签名 IPA 直接安装（需要 ldid 自签 / TrollStore / 自签工具）

以上每一项在 App 里都有运行时状态输出（`InterposeStatus.summary`、`Signer.Result.log`），跑一次就知道命中多少。

## 边界

- 32 位切片只解析头/命令/符号，ObjC 元数据静态解析跳过（界面会显示警告）
- ZIP64 不支持（>4GB 归档）
- 注入只在头填充内做，不做段搬移；空间不够就报错
- 方法蹦床只支持 0 参数方法——参数 ABI 不猜，猜错就是崩溃
- 不内置 ldid 二进制，工具缺失时会明确报「未找到」
