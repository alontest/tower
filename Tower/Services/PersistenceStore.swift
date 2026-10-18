import CryptoKit
import Foundation

struct PersistenceStore {
    private let fileURL: URL

    init(fileURL: URL? = nil) {
        if let fileURL {
            self.fileURL = fileURL
            return
        }

        if TowerTestIsolation.isEnabled {
            self.fileURL = TowerTestIsolation.directory.appendingPathComponent("state.json")
            return
        }
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.fileURL = baseURL
            .appendingPathComponent("Tower", isDirectory: true)
            .appendingPathComponent("state.json", isDirectory: false)
    }

    /// Distinguishes stores for device-local preferences kept beside them.
    var identifier: String { fileURL.path }

    func load() throws -> AppSnapshot? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(AppSnapshot.self, from: data)
    }

    func save(_ snapshot: AppSnapshot) throws {
        try write(Self.encoded(snapshot))
    }

    /// Encoding is the expensive half of `save`. Split out so callers can do
    /// it off the main actor and keep only the ordered write there.
    static func encoded(_ snapshot: AppSnapshot) throws -> Data {
        let encoder = JSONEncoder()
        // Compact: indentation made a ~900 KB state file noticeably larger and
        // slower to write, and nobody reads it by hand on a device.
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(snapshot)
    }

    func write(_ data: Data) throws {
        let folderURL = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: folderURL, withIntermediateDirectories: true)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    private var cloudBaselineURL: URL { fileURL.appendingPathExtension("cloud-base") }
    private var backupDirectory: URL { fileURL.deletingLastPathComponent().appendingPathComponent(fileURL.lastPathComponent + "-backups") }

    func cloudBaseline() throws -> AppSnapshot? { try PersistenceStore(fileURL: cloudBaselineURL).load() }
    func saveCloudBaseline(_ snapshot: AppSnapshot) throws { try PersistenceStore(fileURL: cloudBaselineURL).save(snapshot) }
    func writeCloudBaseline(_ data: Data) throws { try PersistenceStore(fileURL: cloudBaselineURL).write(data) }
    func clearCloudBaseline() throws {
        if FileManager.default.fileExists(atPath: cloudBaselineURL.path) { try FileManager.default.removeItem(at: cloudBaselineURL) }
    }
    func clearRecoveryData() throws {
        try clearCloudBaseline()
        if FileManager.default.fileExists(atPath: backupDirectory.path) { try FileManager.default.removeItem(at: backupDirectory) }
    }
    /// Recovery copies kept on this device (and versions kept in iCloud).
    static let backupRetention = CloudSnapshotJournal.retentionLimit

    func backup(_ snapshot: AppSnapshot) throws {
        // A copy differing only in refresh status or caches is not a new version.
        guard try !recoveryCopies().contains(where: { CloudSnapshotMerge.sameContent($0.snapshot, snapshot) }) else { return }
        // Backups are only read when restoring, so they are stored compressed:
        // each was a full ~900 KB snapshot, eight of them over 7 MB on device.
        let data = try (Self.encoded(snapshot) as NSData).compressed(using: .lzfse) as Data
        let url = backupDirectory.appendingPathComponent(UUID().uuidString + ".json.lzfse")
        try PersistenceStore(fileURL: url).write(data)
        _ = try recoveryCopies()
    }

    /// Keeps a `state.json` this build cannot decode (written by a newer
    /// build, or damaged) before the app starts empty and its next save
    /// replaces the file. It sits with the recovery copies, named by content
    /// so relaunching adds nothing, and is listed for restore once a build
    /// that reads it is installed. Throws when the file cannot be read.
    func preserveUnreadableSnapshot() throws {
        let data = try Data(contentsOf: fileURL)
        let digest = SHA256.hash(data: data).prefix(8).map { String(format: "%02x", $0) }.joined()
        let url = backupDirectory.appendingPathComponent("unreadable-\(digest).json")
        guard !FileManager.default.fileExists(atPath: url.path) else { return }
        try PersistenceStore(fileURL: url).write(data)
    }

    /// Reads a plain (older) or compressed backup.
    private static func loadBackup(at url: URL) throws -> AppSnapshot? {
        var data = try Data(contentsOf: url)
        if url.pathExtension == "lzfse" { data = try (data as NSData).decompressed(using: .lzfse) as Data }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(AppSnapshot.self, from: data)
    }
    func recoveryCopies() throws -> [CloudRecoveryCopy] {
        guard FileManager.default.fileExists(atPath: backupDirectory.path) else { return [] }
        let copies = try FileManager.default.contentsOfDirectory(at: backupDirectory, includingPropertiesForKeys: nil)
            .filter { ["json", "lzfse"].contains($0.pathExtension) }
            // A copy this build cannot decode stays on disk, out of the list
            // and out of pruning, instead of hiding every other copy.
            .compactMap { url in
                (try? Self.loadBackup(at: url)).map { CloudRecoveryCopy(id: "local-" + url.lastPathComponent, snapshot: $0) }
            }
            .sorted {
                let left = $0.snapshot.updatedAt ?? .distantPast, right = $1.snapshot.updatedAt ?? .distantPast
                return left == right ? $0.id < $1.id : left > right
            }
        let retained = Array(CloudRecoveryCopy.unique(copies).prefix(CloudSnapshotJournal.retentionLimit))
        let retainedIDs = Set(retained.map(\.id))
        for copy in copies where !retainedIDs.contains(copy.id) {
            try FileManager.default.removeItem(at: backupDirectory.appendingPathComponent(String(copy.id.dropFirst("local-".count))))
        }
        return retained
    }
}
