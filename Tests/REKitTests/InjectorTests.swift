import XCTest
import Foundation
@testable import REKit

final class InjectorTests: XCTestCase {
    func testInjectsLoadDylibIntoHeaderPadding() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rekit-inject-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let input = tmp.appendingPathComponent("Input")
        let output = tmp.appendingPathComponent("Output")
        let original = Fixtures.syntheticMachO()
        try original.write(to: input)

        let result = try DylibInjector.inject(dylibPath: "@executable_path/Frameworks/Hook.dylib",
                                             binary: input, output: output)
        XCTAssertTrue(result.success, result.message)
        XCTAssertEqual(result.sliceArch, "arm64")

        let patched = try Data(contentsOf: output)
        XCTAssertEqual(patched.count, original.count, "注入不应改变文件大小")

        let file = try MachOParser.parse(data: patched)
        XCTAssertEqual(file.header.ncmds, 2)
        let injected = try XCTUnwrap(file.commands.first { $0.cmd == 0xC })
        XCTAssertTrue(injected.detail.contains("Hook.dylib"), injected.detail)

        // 头填充边界：新命令必须落在第一条 section 之前
        let firstSection = try XCTUnwrap(file.allSections.first)
        XCTAssertLessThan(injected.offset + UInt64(injected.size), UInt64(firstSection.offset))
    }

    func testRejectsMissingPadding() throws {
        var data = Fixtures.syntheticMachO()
        // 第一条 section 的 offset 挪到 0xC0，紧贴加载命令之后（32+152=184），制造填充不足
        let sectionOffsetField = 32 + 72 + 48
        data[sectionOffsetField] = 0xC0
        for i in 1..<4 { data[sectionOffsetField + i] = 0 }
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rekit-nopad-\(UUID().uuidString)")
        try data.write(to: tmp)
        let result = try DylibInjector.inject(dylibPath: "@executable_path/Frameworks/Hook.dylib",
                                             binary: tmp, output: tmp.appendingPathExtension("out"))
        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("填充"), result.message)
    }

    func testPlistFlattenAndDisplay() {
        let dict: [String: Any] = ["b": 1, "a": ["x": true]]
        let flat = PlistTools.flatten(dict)
        XCTAssertEqual(flat.count, 2)
        XCTAssertEqual(flat.first { $0.0 == "b" }?.1, "1")
        XCTAssertEqual(flat.first { $0.0 == "a.x" }?.1, "true")
        XCTAssertTrue(PlistTools.display(dict).contains("a:"))
    }

    func testAnalysisPipelineOnSyntheticBinary() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("rekit-analyze-\(UUID().uuidString)")
        try Fixtures.syntheticMachO().write(to: tmp)
        let report = try Analyzer.analyze(url: tmp)
        XCTAssertEqual(report.macho.header.arch, "arm64")
        XCTAssertFalse(report.markdown.isEmpty)
        XCTAssertTrue(report.markdown.contains("逆向报告"))
        XCTAssertFalse(report.json.isEmpty)
        XCTAssertTrue(report.audit.contains { $0.title.contains("libSystem") })
    }
}
