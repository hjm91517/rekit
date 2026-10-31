import Foundation

public enum Severity: String, CaseIterable, Comparable, Identifiable {
    case critical = "严重"
    case high = "高"
    case medium = "中"
    case low = "低"
    case info = "信息"

    public var id: String { rawValue }
    public var rank: Int {
        switch self {
        case .critical: return 0
        case .high: return 1
        case .medium: return 2
        case .low: return 3
        case .info: return 4
        }
    }
    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
}

public struct SecretRule: Identifiable, Hashable {
    public let id = UUID()
    public let provider: String
    public let name: String
    public let pattern: String
    public let severity: Severity
    public let clientSafe: Bool
}

public struct SecretFinding: Identifiable, Hashable {
    public let id = UUID()
    public let provider: String
    public let kind: String
    public let masked: String
    public let rawLength: Int
    public let severity: Severity
    public let entropy: Double
    public let clientSafe: Bool
    public let falsePositive: Severity
    public let offset: Int
}

public enum SecretScan {
    public static let rules: [SecretRule] = [
        .init(provider: "AWS", name: "Access Key ID", pattern: #"AKIA[0-9A-Z]{16}"#, severity: .critical, clientSafe: false),
        .init(provider: "AWS", name: "Secret Access Key", pattern: #"(?i)aws_?secret_?access_?key\s*[=:]\s*[A-Za-z0-9/+=]{40}"#, severity: .critical, clientSafe: false),
        .init(provider: "Google", name: "API Key", pattern: #"AIza[0-9A-Za-z_\-]{35}"#, severity: .medium, clientSafe: true),
        .init(provider: "Firebase", name: "Realtime DB URL", pattern: #"https://[a-z0-9\-]+\.firebaseio\.com"#, severity: .low, clientSafe: true),
        .init(provider: "Stripe", name: "Secret Key", pattern: #"sk_live_[0-9a-zA-Z]{24,}"#, severity: .critical, clientSafe: false),
        .init(provider: "Stripe", name: "Publishable Key", pattern: #"pk_live_[0-9a-zA-Z]{24,}"#, severity: .info, clientSafe: true),
        .init(provider: "GitHub", name: "Token", pattern: #"gh[pousr]_[A-Za-z0-9]{36,}"#, severity: .critical, clientSafe: false),
        .init(provider: "Slack", name: "Token", pattern: #"xox[baprs]-[0-9A-Za-z\-]{10,}"#, severity: .high, clientSafe: false),
        .init(provider: "JWT", name: "JSON Web Token", pattern: #"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"#, severity: .high, clientSafe: false),
        .init(provider: "PEM", name: "Private Key Block", pattern: #"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"#, severity: .critical, clientSafe: false),
        .init(provider: "Telegram", name: "Bot Token", pattern: #"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}"#, severity: .high, clientSafe: false),
        .init(provider: "Twilio", name: "API Key", pattern: #"SK[0-9a-fA-F]{32}"#, severity: .high, clientSafe: false),
        .init(provider: "SendGrid", name: "API Key", pattern: #"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"#, severity: .high, clientSafe: false),
        .init(provider: "Mapbox", name: "Public Token", pattern: #"pk\.[A-Za-z0-9]{60,}\.[A-Za-z0-9]{20,}"#, severity: .info, clientSafe: true),
        .init(provider: "Azure", name: "Storage Connection String", pattern: #"DefaultEndpointsProtocol=https;AccountName=[^;\s]{3,}"#, severity: .critical, clientSafe: false),
        .init(provider: "Generic", name: "Basic Auth in URL", pattern: #"://[^/\s:@]{2,}:[^/\s:@]{3,}@"#, severity: .high, clientSafe: false),
        .init(provider: "Generic", name: "Bearer Token Literal", pattern: #"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"#, severity: .medium, clientSafe: false),
        .init(provider: "Alibaba", name: "AccessKey ID", pattern: #"LTAI[0-9A-Za-z]{12,}"#, severity: .high, clientSafe: false),
    ]

    static let placeholderMarkers = ["example", "your_", "yourkey", "xxx", "placeholder", "test_", "dummy",
                                     "fake", "sample", "<", ">", "....", "changeme", "todo", "abcdefghijk"]

    public static func looksLikeSecret(_ s: String) -> Bool {
        let lower = s.lowercased()
        if lower.contains("akia") || lower.contains("sk_live") || lower.contains("ghp_")
            || lower.contains("aiza") || lower.contains("begin private") || lower.contains("xox") {
            return true
        }
        return false
    }

    public static func scan(_ data: Data, strings: [StringHit]? = nil) -> [SecretFinding] {
        let hits = strings ?? StringsScan.extract(data, minLength: 8, limit: 80_000)
        var findings: [SecretFinding] = []
        var seen = Set<String>()
        for hit in hits {
            for rule in rules {
                guard let re = try? NSRegularExpression(pattern: rule.pattern) else { continue }
                let ns = hit.value as NSString
                let range = NSRange(location: 0, length: ns.length)
                for m in re.matches(in: hit.value, range: range) {
                    let value = ns.substring(with: m.range)
                    if value.isEmpty || seen.contains(value) { continue }
                    seen.insert(value)
                    let ent = Entropy.shannon([UInt8](value.utf8)[...])
                    let fp = falsePositiveLikelihood(value, entropy: ent, rule: rule)
                    let masked = mask(value)
                    findings.append(SecretFinding(provider: rule.provider, kind: rule.name, masked: masked,
                                                  rawLength: value.count,
                                                  severity: fp == .high ? .info : rule.severity,
                                                  entropy: ent, clientSafe: rule.clientSafe,
                                                  falsePositive: fp, offset: hit.offset))
                }
            }
        }
        return findings.sorted { ($0.severity, -$0.entropy) < ($1.severity, -$1.entropy) }
    }

    static func falsePositiveLikelihood(_ value: String, entropy: Double, rule: SecretRule) -> Severity {
        let lower = value.lowercased()
        if placeholderMarkers.contains(where: { lower.contains($0) }) { return .high }
        if entropy < 3.0 { return .medium }
        if value.count < 12 { return .medium }
        return .low
    }

    public static func mask(_ value: String) -> String {
        guard value.count > 10 else { return String(repeating: "•", count: max(value.count, 4)) }
        let head = value.prefix(4)
        let tail = value.suffix(4)
        return "\(head)••••••\(tail)  (\(value.count))"
    }
}
