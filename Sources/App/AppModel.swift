import Foundation
import UIKit
import SwiftUI
import REKit

final class AppModel: ObservableObject {
    @Published var report: AnalysisReport?
    @Published var status: String = "等待输入"
    @Published var busy: Bool = false
    @Published var errorMessage: String?
    @Published var recent: [URL] = Workspace.knownBinaries()
    @Published var liveClasses: [LiveClass] = []
    @Published var interposeLog: [String] = []

    func refreshRecent() {
        recent = Workspace.knownBinaries()
    }

    func analyze(_ url: URL) {
        busy = true
        errorMessage = nil
        status = "准备分析 \(url.lastPathComponent)"
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let local = try Workspace.copyIntoImports(url)
                let report = try Analyzer.analyze(url: local) { step in
                    DispatchQueue.main.async { self.status = step }
                }
                DispatchQueue.main.async {
                    self.report = report
                    self.busy = false
                    self.status = "完成 · 风险 \(report.riskLevel)（\(report.auditScore)/100）"
                    self.refreshRecent()
                }
            } catch {
                DispatchQueue.main.async {
                    self.busy = false
                    self.status = "失败"
                    self.errorMessage = "\(error)"
                }
            }
        }
    }

    func loadLiveClasses(filter: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let all = Runtime.classes()
            let result: [LiveClass]
            if filter.isEmpty {
                result = Array(all.prefix(4000))
            } else {
                let lower = filter.lowercased()
                result = all.filter { $0.name.lowercased().contains(lower) }
            }
            DispatchQueue.main.async { self.liveClasses = result }
        }
    }

    func append(_ line: String) {
        DispatchQueue.main.async { self.interposeLog.insert(line, at: 0) }
    }

    func saveReport(ext: String) -> URL? {
        guard let report = report else { return nil }
        let body = ext == "json" ? report.json : report.markdown
        return Workspace.saveReport(body, name: report.sourceName, ext: ext)
    }
}
