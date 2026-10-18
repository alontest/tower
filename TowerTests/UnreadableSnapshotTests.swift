import XCTest
@testable import Tower

/// A snapshot this build cannot read must never be replaced by an empty start,
/// and values added by a newer build must not make a whole snapshot unreadable.
@MainActor
final class UnreadableSnapshotTests: XCTestCase {
    private var folder: URL!

    override func setUp() async throws {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: folder)
    }

    private var stateURL: URL { folder.appendingPathComponent("local.json") }
    private var backupFolder: URL { folder.appendingPathComponent("local.json-backups") }

    private func savedSnapshotData(name: String) throws -> Data {
        let model = AppModel(persistence: PersistenceStore(fileURL: stateURL), arguments: [])
        model.setConfigurationName(name)
        model.flushPendingWrite()
        return try Data(contentsOf: stateURL)
    }

    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testProtocolAndClientFromNewerBuildDecodeAndKeepTheirSpelling() throws {
        let node = ProxyNode(kind: .vless, name: "Future", server: "example.com", port: 443, rawURI: "vless://x")
        var snapshotObject = try object(try savedSnapshotData(name: "Newer"))
        var nodeObject = try object(try JSONEncoder().encode(node))
        nodeObject["kind"] = "warp-next"
        snapshotObject["nodes"] = [nodeObject]
        snapshotObject["selectedTarget"] = "future-client"
        let data = try JSONSerialization.data(withJSONObject: snapshotObject)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(AppSnapshot.self, from: data)
        XCTAssertEqual(snapshot.configurationName, "Newer")
        XCTAssertEqual(snapshot.selectedTarget, .surge)
        let decoded = try XCTUnwrap(snapshot.nodes.first)
        XCTAssertEqual(decoded.kind, .unknown)

        // Written back unchanged, so syncing from an older device does not
        // turn the newer device's node into an unknown one.
        XCTAssertEqual(try object(try JSONEncoder().encode(decoded))["kind"] as? String, "warp-next")
        var edited = decoded
        edited.kind = .trojan
        XCTAssertEqual(try object(try JSONEncoder().encode(edited))["kind"] as? String, "trojan")
        XCTAssertEqual(try JSONDecoder().decode(ProxyKind.self, from: Data("\"warp-next\"".utf8)), .unknown)
    }

    func testUndecodableStateIsKeptBeforeTheEmptyStartSaves() async throws {
        _ = try savedSnapshotData(name: "Before downgrade")
        try PersistenceStore(fileURL: stateURL).saveCloudBaseline(XCTUnwrap(PersistenceStore(fileURL: stateURL).load()))
        let damaged = Data(#"{"subscriptions":"written by a newer build"}"#.utf8)
        try damaged.write(to: stateURL)

        let model = AppModel(persistence: PersistenceStore(fileURL: stateURL), arguments: [])
        XCTAssertTrue(model.subscriptions.isEmpty)
        XCTAssertNil(try PersistenceStore(fileURL: stateURL).cloudBaseline(),
                     "An empty start must merge like a new device, not delete what the baseline holds")
        model.setConfigurationName("After")
        model.flushPendingWrite()
        XCTAssertEqual(try PersistenceStore(fileURL: stateURL).load()?.configurationName, "After")

        let kept = try FileManager.default.contentsOfDirectory(at: backupFolder, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("unreadable-") }
        XCTAssertEqual(kept.count, 1)
        XCTAssertEqual(try Data(contentsOf: XCTUnwrap(kept.first)), damaged)

        // The copy that cannot be read does not hide the readable ones.
        try PersistenceStore(fileURL: stateURL).backup(XCTUnwrap(PersistenceStore(fileURL: stateURL).load()))
        XCTAssertEqual(try PersistenceStore(fileURL: stateURL).recoveryCopies().map(\.snapshot.configurationName), ["After"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: kept[0].path))

        // Relaunching on the same file adds no second copy.
        try damaged.write(to: stateURL)
        _ = AppModel(persistence: PersistenceStore(fileURL: stateURL), arguments: [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: backupFolder.path)
            .filter { $0.hasPrefix("unreadable-") }.count, 1)
    }

    func testStateThatCannotBeReadYetIsNeitherReplacedNorSynced() async throws {
        let saved = try savedSnapshotData(name: "Locked")
        // A directory stands in for a file protected data keeps closed:
        // it exists, but neither reading nor keeping a copy works.
        try FileManager.default.removeItem(at: stateURL)
        try FileManager.default.createDirectory(at: stateURL, withIntermediateDirectories: false)

        let model = AppModel(persistence: PersistenceStore(fileURL: stateURL), arguments: [])
        model.setConfigurationName("Typed while locked")
        model.flushPendingWrite()
        XCTAssertNil(model.toast, "No write is attempted over the unread file")
        XCTAssertFalse(FileManager.default.fileExists(atPath: backupFolder.path))

        try FileManager.default.removeItem(at: stateURL)
        try saved.write(to: stateURL)
        model.loadLaunchSnapshotIfUnread()
        XCTAssertEqual(model.configurationName, "Locked")
        model.setConfigurationName("Unlocked")
        model.flushPendingWrite()
        XCTAssertEqual(try PersistenceStore(fileURL: stateURL).load()?.configurationName, "Unlocked")
    }
}
