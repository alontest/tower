import XCTest
@testable import Tower

/// Runs the recogniser over corpus names gathered by
/// Scripts/policy_group_corpus.py. Skipped unless TEST_RUNNER_TOWER_CORPUS
/// points at the script's `eval_names.txt`; writes `<file>.out` for its report.
final class PolicyGroupEmojiCorpusEvaluation: XCTestCase {
    func testEvaluateCorpus() throws {
        guard let path = ProcessInfo.processInfo.environment["TOWER_CORPUS"] else { throw XCTSkip("no corpus") }
        let names = try String(contentsOfFile: path, encoding: .utf8).split(separator: "\n").map(String.init)
        let lines = names.map { name in "\(name)\t\(PolicyGroupEmoji.recognized(for: name) ?? "-")" }
        try lines.joined(separator: "\n").write(toFile: path + ".out", atomically: true, encoding: .utf8)
    }
}
