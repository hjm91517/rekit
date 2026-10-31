import XCTest
import Foundation
@testable import REKit

/// Minimal little-endian writer used to synthesise fixtures.
struct TestWriter {
    var data = Data()

    mutating func u8(_ v: UInt8) { data.append(v) }
    mutating func u16(_ v: UInt16) {
        data.append(UInt8(v & 0xFF)); data.append(UInt8((v >> 8) & 0xFF))
    }
    mutating func u32(_ v: UInt32) {
        for i in 0..<4 { data.append(UInt8((v >> (8 * UInt32(i))) & 0xFF)) }
    }
    mutating func u64(_ v: UInt64) {
        for i in 0..<8 { data.append(UInt8((v >> (8 * UInt64(i))) & 0xFF)) }
    }
    mutating func fixed(_ s: String, _ length: Int) {
        var bytes = Array(s.utf8)
        if bytes.count > length { bytes = Array(bytes.prefix(length)) }
        data.append(contentsOf: bytes)
        data.append(contentsOf: [UInt8](repeating: 0, count: length - bytes.count))
    }
    mutating func zeros(_ n: Int) { data.append(contentsOf: [UInt8](repeating: 0, count: n)) }
}

enum Fixtures {
    /// 64-bit arm64 MH_EXECUTE with one __TEXT,__text section placed at 0x4000,
    /// leaving a large legal header padding area for LC injection.
    static func syntheticMachO() -> Data {
        var w = TestWriter()
        w.u32(0xfeed_facf)      // magic
        w.u32(0x0100_000C)      // CPU_TYPE_ARM64
        w.u32(0)                // subtype
        w.u32(2)                // MH_EXECUTE
        w.u32(1)                // ncmds
        w.u32(72 + 80)          // sizeofcmds
        w.u32(0x0020_0000)      // MH_PIE
        w.u32(0)                // reserved

        w.u32(0x19)             // LC_SEGMENT_64
        w.u32(72 + 80)
        w.fixed("__TEXT", 16)
        w.u64(0x1_0000_0000)    // vmaddr
        w.u64(0x4000)           // vmsize
        w.u64(0)                // fileoff
        w.u64(0x4000)           // filesize
        w.u32(5)                // maxprot r-x
        w.u32(5)                // initprot
        w.u32(1)                // nsects
        w.u32(0)                // flags

        w.fixed("__text", 16)
        w.fixed("__TEXT", 16)
        w.u64(0x1_0000_4000)    // addr
        w.u64(0x100)            // size
        w.u32(0x4000)           // offset
        w.u32(2)                // align
        w.u32(0)                // reloff
        w.u32(0)                // nreloc
        w.u32(0x8000_0400)      // flags: pure instructions
        w.u32(0)
        w.u32(0)
        w.u32(0)

        w.zeros(0x4000 - w.data.count)
        w.zeros(0x100)
        return w.data
    }

    static func storedZip(name: String, content: String) -> Data {
        let payload = Array(content.utf8)
        let nameBytes = Array(name.utf8)
        var w = TestWriter()
        // local header
        w.u32(0x0403_4b50)
        w.u16(20); w.u16(0); w.u16(0); w.u16(0); w.u16(0)
        w.u32(0)
        w.u32(UInt32(payload.count))
        w.u32(UInt32(payload.count))
        w.u16(UInt16(nameBytes.count))
        w.u16(0)
        w.data.append(contentsOf: nameBytes)
        w.data.append(contentsOf: payload)
        let cdOffset = w.data.count
        // central directory
        w.u32(0x0201_4b50)
        w.u16(20); w.u16(20); w.u16(0); w.u16(0); w.u16(0); w.u16(0)
        w.u32(0)
        w.u32(UInt32(payload.count))
        w.u32(UInt32(payload.count))
        w.u16(UInt16(nameBytes.count))
        w.u16(0); w.u16(0); w.u16(0); w.u16(0)
        w.u32(0)
        w.u32(0)
        w.data.append(contentsOf: nameBytes)
        let cdSize = w.data.count - cdOffset
        // EOCD
        w.u32(0x0605_4b50)
        w.u16(0); w.u16(0); w.u16(1); w.u16(1)
        w.u32(UInt32(cdSize))
        w.u32(UInt32(cdOffset))
        w.u16(0)
        return w.data
    }
}

final class MachOParserTests: XCTestCase {
    func testParsesSyntheticArm64Image() throws {
        let file = try MachOParser.parse(data: Fixtures.syntheticMachO())
        XCTAssertEqual(file.header.arch, "arm64")
        XCTAssertEqual(file.header.typeName, "MH_EXECUTE")
        XCTAssertTrue(file.header.isPIE)
        XCTAssertEqual(file.segments.count, 1)
        XCTAssertEqual(file.segments.first?.name, "__TEXT")
        XCTAssertEqual(file.allSections.first?.name, "__text")
        XCTAssertEqual(file.allSections.first?.offset, 0x4000)
        XCTAssertEqual(file.commands.count, 1)
    }

    func testParsesOwnTestBundleExecutable() throws {
        let bundle = Bundle(for: MachOParserTests.self)
        guard let exe = bundle.executableURL else {
            throw XCTSkip("测试宿主没有可执行文件")
        }
        let file = try MachOParser.parse(url: exe)
        XCTAssertGreaterThan(file.header.ncmds, 0)
        XCTAssertFalse(file.header.uuid.isEmpty)
        XCTAssertTrue(file.segments.contains { $0.name == "__TEXT" })
        XCTAssertGreaterThan(file.commands.count, 0)
        XCTAssertGreaterThan(file.dylibs.count, 0)
    }

    func testEntropyBounds() {
        let zeros = [UInt8](repeating: 0, count: 1024)
        XCTAssertEqual(Entropy.shannon(zeros[...]), 0, accuracy: 0.0001)
        let distinct = (0..<256).map { UInt8($0) }
        XCTAssertEqual(Entropy.shannon(distinct[...]), 8, accuracy: 0.001)
    }

    func testSecretRulesAndPlaceholderDowngrade() {
        let live = Array(("AKIA" + "ABCDEFGHIJKLMNOP").utf8)
        let placeholder = Array(("AKIA" + "IOSFODNN7" + "EXAMPLE").utf8)
        let s1 = String(decoding: live, as: UTF8.self)
        let s2 = String(decoding: placeholder, as: UTF8.self)
        let hits = [
            StringHit(value: s1, offset: 0, category: "未知", utf16: false),
            StringHit(value: s2, offset: 40, category: "未知", utf16: false)
        ]
        let findings = SecretScan.scan(Data(), strings: hits)
        XCTAssertEqual(findings.count, 2)
        let liveFinding = findings.first { $0.rawLength == s1.count }
        let fakeFinding = findings.first { $0.rawLength == s2.count }
        XCTAssertEqual(liveFinding?.clientSafe, false)
        XCTAssertEqual(fakeFinding?.falsePositive, .high)
    }

    func testZipStoredEntryRoundTrip() throws {
        let data = Fixtures.storedZip(name: "Payload/App.app/Info.plist", content: "<plist/>")
        let zip = try ZipArchive(data: data)
        XCTAssertEqual(zip.entries.count, 1)
        let entry = try XCTUnwrap(zip.entries.first)
        XCTAssertEqual(entry.method, 0)
        XCTAssertEqual(try zip.read(entry), Data("<plist/>".utf8))
        XCTAssertEqual(zip.appBundlePath(), "Payload/App.app/")
    }
}
