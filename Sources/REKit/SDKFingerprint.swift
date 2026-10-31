import Foundation

public struct SDKHit: Identifiable, Hashable {
    public let id = UUID()
    public let name: String
    public let category: String
    public let evidence: String
    public let note: String
}

public enum SDKFingerprint {
    struct Signature {
        let name: String
        let category: String
        let frameworks: [String]
        let prefixes: [String]
        let strings: [String]
        let note: String
    }

    static let signatures: [Signature] = [
        .init(name: "Alamofire", category: "网络", frameworks: ["Alamofire"],
              prefixes: ["AF"], strings: ["com.alamofire"], note: "Swift HTTP 栈"),
        .init(name: "AFNetworking", category: "网络", frameworks: ["AFNetworking"],
              prefixes: ["AFHTTPSessionManager"], strings: ["AFNetworking"], note: "ObjC HTTP 栈"),
        .init(name: "Moya", category: "网络", frameworks: ["Moya"], prefixes: ["MoyaProvider"],
              strings: ["Moya.MoyaProvider"], note: "基于 Alamofire 的抽象层"),
        .init(name: "Firebase", category: "后端/分析", frameworks: ["FirebaseCore", "FirebaseAnalytics"],
              prefixes: ["FIR"], strings: ["firebaseio.com", "google.firebase"], note: "需检查 firebase_options 泄露"),
        .init(name: "Stripe", category: "支付", frameworks: ["Stripe"], prefixes: ["STP"],
              strings: ["api.stripe.com"], note: "检查 pk_/sk_ 是否混用"),
        .init(name: "Realm", category: "数据库", frameworks: ["Realm", "RealmSwift"],
              prefixes: ["RLM"], strings: ["io.realm"], note: "本地明文数据库常见"),
        .init(name: "Sentry", category: "崩溃上报", frameworks: ["Sentry"],
              prefixes: ["Sentry"], strings: ["ingest.sentry.io"], note: "DSN 常在 Info.plist 中"),
        .init(name: "AppsFlyer", category: "归因", frameworks: ["AppsFlyerLib"],
              prefixes: ["AppsFlyer"], strings: ["appsflyer.com"], note: "设备指纹采集"),
        .init(name: "Adjust", category: "归因", frameworks: ["Adjust"], prefixes: ["ADJ"],
              strings: ["adjust.com"], note: "归因 SDK"),
        .init(name: "Facebook SDK", category: "社交", frameworks: ["FBSDKCoreKit"],
              prefixes: ["FBSDK"], strings: ["graph.facebook.com"], note: "App Events"),
        .init(name: "Google Mobile Ads", category: "广告", frameworks: ["GoogleMobileAds"],
              prefixes: ["GAD"], strings: ["googleads.g.doubleclick.net"], note: "广告变现"),
        .init(name: "OneSignal", category: "推送", frameworks: ["OneSignal"],
              prefixes: ["OneSignal"], strings: ["onesignal.com"], note: "推送 key 可能泄露"),
        .init(name: "Agora", category: "音视频", frameworks: ["AgoraRtcKit"],
              prefixes: ["AgoraRtc"], strings: ["agora.io"], note: "App ID 常在代码中"),
        .init(name: "Tencent Bugly", category: "崩溃上报", frameworks: ["Bugly"],
              prefixes: ["Bugly"], strings: ["bugly.qq.com"], note: "国内崩溃采集"),
        .init(name: "UMeng", category: "分析", frameworks: ["UMCommon"],
              prefixes: ["UMCommon", "UMDevice"], strings: ["umeng.com"], note: "国内统计"),
        .init(name: "WeChat SDK", category: "社交", frameworks: ["WechatSDK"],
              prefixes: ["WXApi"], strings: ["weixin.qq.com"], note: "AppID 泄露风险"),
        .init(name: "IOSSecuritySuite", category: "安全", frameworks: ["IOSSecuritySuite"],
              prefixes: ["IOSSecuritySuite"], strings: ["jailbreak"], note: "越狱/调试检测"),
        .init(name: "CocoaLumberjack", category: "日志", frameworks: ["CocoaLumberjack"],
              prefixes: ["DDLog"], strings: ["cocoalumberjack"], note: "日志可能落盘"),
        .init(name: "Kingfisher", category: "图片", frameworks: ["Kingfisher"],
              prefixes: ["Kingfisher"], strings: ["kingfisher"], note: "图片缓存"),
        .init(name: "SDWebImage", category: "图片", frameworks: ["SDWebImage"],
              prefixes: ["SDWebImage"], strings: ["sdwebimage"], note: "图片缓存"),
    ]

    public static func detect(file: MachOFile, classes: [ObjCClassInfo], strings: [StringHit]) -> [SDKHit] {
        let libNames = file.dylibs.map { ($0.path as NSString).lastPathComponent.lowercased() }
        let classNames = classes.map { $0.name }
        let text = strings.map { $0.value }.joined(separator: "\n").lowercased()
        var out: [SDKHit] = []

        for sig in signatures {
            var evidence: [String] = []
            for fw in sig.frameworks {
                let fwl = fw.lowercased()
                if libNames.contains(where: { $0.hasPrefix(fwl) }) || file.dylibs.contains(where: { $0.path.contains("/\(fw).framework/") }) {
                    evidence.append("framework \(fw)")
                }
            }
            for prefix in sig.prefixes {
                let count = classNames.filter { $0.hasPrefix(prefix) }.count
                if count > 0 { evidence.append("类前缀 \(prefix) ×\(count)") }
            }
            for s in sig.strings where text.contains(s.lowercased()) {
                evidence.append("字符串 \(s)")
                break
            }
            if !evidence.isEmpty {
                out.append(SDKHit(name: sig.name, category: sig.category,
                                  evidence: evidence.joined(separator: " · "), note: sig.note))
            }
        }
        return out.sorted { $0.name < $1.name }
    }
}
