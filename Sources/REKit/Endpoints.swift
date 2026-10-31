import Foundation

public struct EndpointHit: Identifiable, Hashable {
    public let id = UUID()
    public let url: String
    public let host: String
    public let scheme: String
    public let path: String
    public let offset: Int

    public var display: String {
        guard let comps = URLComponents(string: url) else { return url }
        let p = comps.path.isEmpty ? "/" : comps.path
        var line = "\(comps.scheme ?? scheme)://\(comps.host ?? host)\(p)"
        if let q = comps.query { line += "?\(q)" }
        return line
    }
}

public enum Endpoints {
    public static func extract(from strings: [StringHit]) -> [EndpointHit] {
        var seen = Set<String>()
        var out: [EndpointHit] = []
        for hit in strings where hit.category == StringsScan.Category.url.rawValue {
            var value = hit.value.trimmingCharacters(in: .whitespacesAndNewlines)
            value = value.trimmingCharacters(in: CharacterSet(charactersIn: "\"'`,;)"))
            if value.isEmpty || seen.contains(value) { continue }
            seen.insert(value)
            let comps = URLComponents(string: value)
            out.append(EndpointHit(url: value, host: comps?.host ?? "", scheme: comps?.scheme ?? "",
                                   path: comps?.path ?? "", offset: hit.offset))
        }
        return out.sorted { $0.host == $1.host ? $0.path < $1.path : $0.host < $1.host }
    }

    public static func grouped(_ hits: [EndpointHit]) -> [(host: String, items: [EndpointHit])] {
        let groups = Dictionary(grouping: hits, by: { $0.host.isEmpty ? "(no host)" : $0.host })
        return groups.map { (host: $0.key, items: $0.value.sorted { $0.path < $1.path }) }
            .sorted { $0.host < $1.host }
    }
}
