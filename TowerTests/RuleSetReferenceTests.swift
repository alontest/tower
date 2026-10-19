import XCTest
@testable import Tower

/// What "prefer rule sets" writes for each client beyond the bundled lists:
/// downloads through a proxy, MRS for Stash, SRS for Hiddify, and inline rule
/// sets for the user's own rules that have no URL to fetch.
final class RuleSetReferenceTests: XCTestCase {
    private let repository = RuleSchemeRepository()
    private let node = ProxyNode(kind: .shadowsocks, name: "HK 01", server: "hk.example.com", port: 443,
                                 cipher: "aes-128-gcm", password: "p", rawURI: "ss://x")

    private func fullScheme() throws -> RuleScheme {
        try XCTUnwrap(repository.bundledSchemes().first { $0.id == "acl4ssr-full" })
    }

    private func generate(_ scheme: RuleScheme, _ target: ClientTarget, preferRuleSets: Bool = true) -> String {
        ConfigurationGenerator().generate(nodes: [node], scheme: scheme, target: target,
                                          schemes: repository, preferRuleSets: preferRuleSets).content
    }

    private func library(_ lines: [String], group: String, name: String = "我的规则") -> [RuleSchemeRuleset] {
        lines.map {
            RuleSchemeRuleset(groupName: group, resource: .inline($0), origin: .added(name))
        }
    }

    /// The scheme with the user's rules inserted at the top, as the library
    /// expansion places them before the first conflicting rule.
    private func scheme(adding rulesets: [RuleSchemeRuleset]) throws -> RuleScheme {
        var scheme = try fullScheme()
        scheme.rulesets.insert(contentsOf: rulesets, at: 0)
        return scheme
    }

    private func providerBlocks(_ content: String) -> [String] {
        guard let start = content.range(of: "\nrule-providers:\n"),
              let end = content.range(of: "\nrules:\n", range: start.upperBound..<content.endIndex) else { return [] }
        return content[start.upperBound..<end.lowerBound]
            .components(separatedBy: "\n  tower-").dropFirst().map { "tower-" + $0 }
    }

    /// mihomo already routes provider downloads through the profile's rules
    /// and the user's selection; a pinned `proxy:` would bypass both.
    func testRuleProvidersFollowTheProfileRulesForDownloads() throws {
        let scheme = try fullScheme()
        for target in [ClientTarget.clashVerge, .clashMi, .clash, .clashApple, .karing, .shadowrocket] {
            let remote = providerBlocks(generate(scheme, target)).filter { $0.contains("type: http") }
            XCTAssertFalse(remote.isEmpty, target.rawValue)
            XCTAssertFalse(remote.contains { $0.contains("\n    proxy: ") }, target.rawValue)
        }
    }

    func testStashReadsImportedMRSAndKaringStillCannot() throws {
        var scheme = try fullScheme()
        let url = try XCTUnwrap(URL(string: "https://example.com/rules/ai.mrs"))
        scheme.rulesets.insert(RuleSchemeRuleset(groupName: "🚀 节点选择", resource: .remote(url),
                                                 provider: RuleProviderMetadata(behavior: "domain", format: "mrs", interval: nil)), at: 0)
        let planner = RuleSetEmissionPlanner(repository: repository)
        for prefer in [false, true] {
            let stash = planner.plan(for: scheme, target: .clash, preferRuleSets: prefer)
            XCTAssertEqual(stash.remoteResources.first { $0.url == url }?.format, .clashDomainMRS)
            XCTAssertTrue(stash.unreadableResources.isEmpty)
            let karing = planner.plan(for: scheme, target: .karing, preferRuleSets: prefer)
            XCTAssertEqual(karing.unreadableResources.map(\.url), [url])
        }
    }

    func testHiddifyReferencesTheBundledSRSAndDownloadsThroughTheProxy() throws {
        let scheme = try fullScheme()
        let hiddify = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(generate(scheme, .hiddify).utf8)) as? [String: Any])
        let route = try XCTUnwrap(hiddify["route"] as? [String: Any])
        let ruleSets = try XCTUnwrap(route["rule_set"] as? [[String: Any]])
        XCTAssertEqual(ruleSets.count, 31)
        XCTAssertTrue(ruleSets.allSatisfy { $0["format"] as? String == "binary" && $0["download_detour"] is String })
        XCTAssertNil(hiddify["http_clients"], "Hiddify's sing-box 1.13 has no http_client")

        let singBox = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(generate(scheme, .singBox).utf8)) as? [String: Any])
        let singBoxSets = try XCTUnwrap((singBox["route"] as? [String: Any])?["rule_set"] as? [[String: Any]])
        XCTAssertTrue(singBoxSets.allSatisfy { $0["download_detour"] == nil }, "sing-box MT uses http_client instead")

        let inline = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(generate(scheme, .hiddify, preferRuleSets: false).utf8)) as? [String: Any])
        XCTAssertNil((inline["route"] as? [String: Any])?["rule_set"])
    }

    func testLibraryRulesWithoutURLBecomeOneInlineSetPerRun() throws {
        let scheme = try scheme(adding:
            library(["DOMAIN-SUFFIX,example.com", "DOMAIN,api.example.org"], group: "🚀 节点选择", name: "域名")
            + library(["IP-CIDR,203.0.113.0/24,no-resolve", "IP-CIDR6,2001:db8::/32,no-resolve"], group: "🎯 全球直连", name: "地址")
            + library(["DOMAIN-KEYWORD,tracker", "DOMAIN-SUFFIX,ads.example"], group: "🛑 广告拦截", name: "混合"))

        let mihomo = generate(scheme, .clashMi)
        let blocks = providerBlocks(mihomo).filter { $0.contains("type: inline") }
        XCTAssertEqual(blocks.count, 3)
        XCTAssertTrue(blocks[0].contains("behavior: domain") && blocks[0].contains("\"+.example.com\"") && blocks[0].contains("\"api.example.org\""), blocks[0])
        XCTAssertTrue(blocks[1].contains("behavior: ipcidr") && blocks[1].contains("\"203.0.113.0/24\"") && blocks[1].contains("\"2001:db8::/32\""), blocks[1])
        XCTAssertTrue(blocks[2].contains("behavior: classical") && blocks[2].contains("\"DOMAIN-KEYWORD,tracker\""), blocks[2])
        let rules = mihomo.components(separatedBy: "\nrules:\n")[1].components(separatedBy: "\n")
        XCTAssertEqual(Array(rules.prefix(3)), [
            "  - RULE-SET,tower-local-1,🚀 节点选择",
            "  - RULE-SET,tower-local-2,🎯 全球直连,no-resolve",
            "  - RULE-SET,tower-local-3,🛑 广告拦截"
        ])
        XCTAssertFalse(mihomo.contains("DOMAIN-SUFFIX,example.com,"), "the rules are not also written one by one")
        XCTAssertTrue(generate(scheme, .clash).contains("  tower-local-1:\n    type: inline\n    behavior: domain"), "Stash")

        let surge = generate(scheme, .surge)
        // Surge draws each group's icon, so names carry no emoji there.
        XCTAssertTrue(surge.contains("\n[Rule]\nRULE-SET,tower-local-1,节点选择\nRULE-SET,tower-local-2,全球直连,no-resolve\nRULE-SET,tower-local-3,广告拦截\n"), surge)
        XCTAssertTrue(surge.contains("[Ruleset tower-local-1]\nDOMAIN-SUFFIX,example.com\nDOMAIN,api.example.org\n"))
        XCTAssertTrue(surge.contains("[Ruleset tower-local-2]\nIP-CIDR,203.0.113.0/24\nIP-CIDR6,2001:db8::/32\n"))
        XCTAssertTrue(generate(scheme, .surgeMac).contains("[Ruleset tower-local-3]\nDOMAIN-KEYWORD,tracker\n"))
    }

    func testIPSetsCarryNoResolveTheWaySingleRulesWould() throws {
        let scheme = try scheme(adding: library(["IP-CIDR,198.51.100.0/24", "IP-CIDR,192.0.2.0/24"], group: "🎯 全球直连"))
        // mihomo keeps an IP rule resolving unless the source said otherwise.
        XCTAssertTrue(generate(scheme, .clashMi).contains("  - RULE-SET,tower-local-1,🎯 全球直连\n"))
        // Surge writes no-resolve on every IP rule.
        XCTAssertTrue(generate(scheme, .surge).contains("RULE-SET,tower-local-1,全球直连,no-resolve\n"))

        let mixed = try self.scheme(adding: library(["IP-CIDR,198.51.100.0/24", "IP-CIDR,192.0.2.0/24,no-resolve"], group: "🎯 全球直连"))
        XCTAssertFalse(generate(mixed, .clashMi).contains("tower-local-"), "one rule each side is no set")
        XCTAssertTrue(generate(mixed, .surge).contains("[Ruleset tower-local-1]\nIP-CIDR,198.51.100.0/24\nIP-CIDR,192.0.2.0/24\n"))
    }

    func testRulesThatAnInlineSetCannotCarryStayAsTheyWere() throws {
        let scheme = try scheme(adding:
            library(["DOMAIN-SUFFIX,only.example"], group: "🚀 节点选择", name: "单条")
            + library(["DOMAIN-SUFFIX,a.example", "URL-REGEX,^https?://b\\.example/ad", "DOMAIN-SUFFIX,c.example"], group: "🛑 广告拦截", name: "正则")
            + library(["DOMAIN-SUFFIX,中文.example", "DOMAIN-SUFFIX,d.example"], group: "🚀 节点选择", name: "非 ASCII")
            + [RuleSchemeRuleset(groupName: "🚀 节点选择", resource: .inline("DOMAIN-SUFFIX,first.example"), origin: .supplement),
               RuleSchemeRuleset(groupName: "🚀 节点选择", resource: .inline("DOMAIN-SUFFIX,second.example"), origin: .supplement)])

        let mihomo = generate(scheme, .flClash)
        XCTAssertFalse(mihomo.contains("type: inline"), "a single rule, runs split by an unsupported line, non-ASCII values and supplements stay single rules")
        XCTAssertTrue(mihomo.contains("  - DOMAIN-SUFFIX,only.example,🚀 节点选择\n"))
        XCTAssertTrue(mihomo.contains("  - DOMAIN-SUFFIX,first.example,🚀 节点选择\n  - DOMAIN-SUFFIX,second.example,🚀 节点选择\n"))
        XCTAssertFalse(generate(scheme, .surge).contains("[Ruleset "))

        let grouped = try self.scheme(adding: library(["DOMAIN-SUFFIX,x.example", "DOMAIN-SUFFIX,y.example"], group: "🚀 节点选择"))
        for target in [ClientTarget.shadowrocket, .karing, .clashApple, .loon, .quanx, .egern, .singBox, .hiddify] {
            XCTAssertFalse(generate(grouped, target).contains("tower-local-"), target.rawValue)
        }
        XCTAssertFalse(generate(grouped, .clashMi, preferRuleSets: false).contains("tower-local-"))
        XCTAssertTrue(generate(grouped, .clashMi).contains("tower-local-1"))
    }

    /// Every bundled list's Loon, Quantumult X, Egern and DNS copies pass the
    /// app's own coverage check against the bundled text.
    func testBundledListsHaveVerifiedCopiesForEveryFormat() throws {
        let scheme = try fullScheme()
        var verified: [RuleSchemeRepository.RuleListDialect: Int] = [:]
        var dnsDomains = 0
        for ruleset in scheme.rulesets {
            guard case .remote = ruleset.resource else { continue }
            let lines = repository.lines(for: ruleset.resource)
            for dialect in RuleSchemeRepository.RuleListDialect.allCases
            where repository.dialectResource(dialect, for: ruleset.resource, matching: lines) != nil {
                verified[dialect, default: 0] += 1
            }
            if repository.singBoxSRSResource(for: ruleset.resource, matching: lines)?.dnsDomainURL != nil { dnsDomains += 1 }
            // A changed line is a different list: no copy is used for it.
            XCTAssertNil(repository.dialectResource(.loon, for: ruleset.resource, matching: lines + ["DOMAIN,changed.example"]))
        }
        XCTAssertEqual(verified[.loon], 31)
        XCTAssertEqual(verified[.quanx], 31)
        XCTAssertEqual(verified[.egern], 31)
        XCTAssertEqual(dnsDomains, 30)
        XCTAssertNotNil(repository.publishedLocalRule("GEOIP,CN", dialect: .loon))
        XCTAssertNotNil(repository.publishedLocalRule("geoip,cn", dialect: .quanx))
        XCTAssertNil(repository.publishedLocalRule("GEOIP,US", dialect: .loon))
        XCTAssertNotNil(repository.quanXCatchAllURL)
    }

    /// Writes the exports for the local cores to check. Skipped unless
    /// TEST_RUNNER_TOWER_RULESET_OUT names an existing directory.
    func testWritesProfilesForLocalCores() throws {
        guard let directory = ProcessInfo.processInfo.environment["TOWER_RULESET_OUT"] else { throw XCTSkip("no output directory") }
        let scheme = try scheme(adding:
            library(["DOMAIN-SUFFIX,example.com", "DOMAIN,api.example.org"], group: "🚀 节点选择", name: "域名")
            + library(["IP-CIDR,203.0.113.0/24,no-resolve", "IP-CIDR6,2001:db8::/32,no-resolve"], group: "🎯 全球直连", name: "地址")
            + library(["DOMAIN-KEYWORD,tracker", "DOMAIN-SUFFIX,ads.example"], group: "🛑 广告拦截", name: "混合"))
        for (target, file) in [(ClientTarget.clashMi, "mihomo.yaml"), (.clash, "stash.yaml"), (.hiddify, "hiddify.json"),
                               (.singBox, "sing-box.json"), (.surge, "surge.conf")] {
            try generate(scheme, target).write(toFile: directory + "/" + file, atomically: true, encoding: .utf8)
        }
    }
}
