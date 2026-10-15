import XCTest
@testable import Tower

/// Issue #45: rules added from a group's page are visible, survive template
/// refreshes, and match before every template rule.
final class GroupSupplementRuleTests: XCTestCase {
    private let nodes = [
        ProxyNode(
            kind: .shadowsocks,
            name: "香港 01",
            server: "hk.example.com",
            port: 443,
            cipher: "aes-128-gcm",
            password: "demo",
            rawURI: "ss://demo"
        )
    ]

    func testParsingAcceptsWhatPeoplePaste() throws {
        XCTAssertEqual(try SupplementRule.parse("https://Chat.Example.com/path?q=1", kind: .domainSuffix).line,
                       "DOMAIN-SUFFIX,chat.example.com")
        XCTAssertEqual(try SupplementRule.parse("*.example.com", kind: .domain).line, "DOMAIN-SUFFIX,example.com")
        XCTAssertEqual(try SupplementRule.parse(".example.com", kind: .domain).line, "DOMAIN-SUFFIX,example.com")
        XCTAssertEqual(try SupplementRule.parse("example.com:8443", kind: .domain).line, "DOMAIN,example.com")
        XCTAssertEqual(try SupplementRule.parse("Example", kind: .keyword).line, "DOMAIN-KEYWORD,example")
        XCTAssertEqual(try SupplementRule.parse("203.0.113.0/24", kind: .domainSuffix).line, "IP-CIDR,203.0.113.0/24")
        XCTAssertEqual(try SupplementRule.parse("203.0.113.9", kind: .ipRange).line, "IP-CIDR,203.0.113.9/32")
        XCTAssertEqual(try SupplementRule.parse("2001:db8::/32", kind: .ipRange).line, "IP-CIDR6,2001:db8::/32")
        XCTAssertThrowsError(try SupplementRule.parse("", kind: .domain))
        XCTAssertThrowsError(try SupplementRule.parse("exa mple.com", kind: .domain))
        XCTAssertThrowsError(try SupplementRule.parse("a,b.com", kind: .domainSuffix))
        XCTAssertThrowsError(try SupplementRule.parse("example.com", kind: .ipRange))
        XCTAssertThrowsError(try SupplementRule.parse("10.0.0.0/33", kind: .ipRange))
        XCTAssertThrowsError(try SupplementRule.parse("key word", kind: .keyword))
    }

    @MainActor
    func testSupplementMatchesBeforeEveryTemplateRuleInEveryClient() throws {
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let model = AppModel(persistence: PersistenceStore(fileURL: fileURL), arguments: [])
        let scheme = try XCTUnwrap(RuleSchemeRepository().bundledSchemes().first { $0.id == "acl4ssr-full" })
        let before = model.exportedRuleOrder(for: scheme)

        // Template sends openai.com to 💬 Ai平台; the user wants 🌍 国外媒体.
        XCTAssertEqual(model.probeRule(host: "chat.openai.com", in: scheme).result.hit?.groupName, "💬 Ai平台")
        model.addSupplementRule(try SupplementRule.parse("openai.com", kind: .domainSuffix),
                                toGroup: "🌍 国外媒体", in: scheme)
        model.addSupplementRule(try SupplementRule.parse("new-ai.example", kind: .domainSuffix),
                                toGroup: "💬 Ai平台", in: scheme)

        let after = model.exportedRuleOrder(for: scheme)
        XCTAssertEqual(Array(after.dropFirst(2)), before, "模板规则顺序保持不变")
        XCTAssertEqual(after.prefix(2).map(\.origin), [.supplement, .supplement])
        XCTAssertEqual(model.probeRule(host: "chat.openai.com", in: scheme).result.hit?.groupName, "🌍 国外媒体")
        XCTAssertEqual(model.probeRule(host: "api.new-ai.example", in: scheme).result.hit?.groupName, "💬 Ai平台")
        XCTAssertEqual(model.supplementRules(forGroup: "💬 Ai平台", in: scheme).map(\.line),
                       ["DOMAIN-SUFFIX,new-ai.example"])
        XCTAssertFalse(model.ruleSources(forGroup: "💬 Ai平台", in: scheme).contains { $0.origin == .supplement })

        let exported = model.effectiveScheme(scheme)
        for target in ClientTarget.allCases where target.supportsFullConfigurationExport {
            let output = ConfigurationGenerator().generate(nodes: nodes, scheme: exported, target: target, preferRuleSets: false).content
            let supplement = try XCTUnwrap(output.range(of: "new-ai.example"), "\(target)")
            let lan = try XCTUnwrap(output.range(of: "192.168.0.0/16") ?? output.range(of: "openai"), "\(target)")
            XCTAssertLessThan(supplement.lowerBound, lan.lowerBound, "\(target) 补充规则必须最先匹配")
        }
    }

    @MainActor
    func testSameConditionMovesBetweenGroupsAndSurvivesRenameAndReload() throws {
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let store = PersistenceStore(fileURL: fileURL)
        let model = AppModel(persistence: store, arguments: [])
        let scheme = try XCTUnwrap(RuleSchemeRepository().bundledSchemes().first { $0.id == "acl4ssr-full" })
        let rule = try SupplementRule.parse("example.org", kind: .domainSuffix)

        XCTAssertNil(model.addSupplementRule(rule, toGroup: "💬 Ai平台", in: scheme))
        XCTAssertEqual(model.addSupplementRule(rule, toGroup: "🌍 国外媒体", in: scheme), "💬 Ai平台")
        XCTAssertTrue(model.supplementRules(forGroup: "💬 Ai平台", in: scheme).isEmpty)
        XCTAssertEqual(model.customRuleFlows(for: scheme).filter { $0.isGroupSupplement == true }.count, 1)

        try model.renameRuleGroup(named: "🌍 国外媒体", to: "🌍 海外", for: scheme)
        XCTAssertEqual(model.supplementRules(forGroup: "🌍 海外", in: scheme), [rule])
        XCTAssertEqual(model.probeRule(host: "www.example.org", in: scheme).result.hit?.groupName, "🌍 海外")

        let reloaded = AppModel(persistence: store, arguments: [])
        XCTAssertEqual(reloaded.supplementRules(forGroup: "🌍 海外", in: scheme), [rule])

        reloaded.removeSupplementRule(rule, fromGroup: "🌍 海外", in: scheme)
        XCTAssertTrue(reloaded.customRuleFlows(for: scheme).filter { $0.isGroupSupplement == true }.isEmpty)
    }

    @MainActor
    func testDeletingGroupAndResettingRemoveItsSupplements() throws {
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let model = AppModel(persistence: PersistenceStore(fileURL: fileURL), arguments: [])
        let scheme = try XCTUnwrap(RuleSchemeRepository().bundledSchemes().first { $0.id == "acl4ssr-full" })
        model.addSupplementRule(try SupplementRule.parse("a.example", kind: .domain), toGroup: "💬 Ai平台", in: scheme)
        model.addSupplementRule(try SupplementRule.parse("b.example", kind: .domain), toGroup: "🎥 奈飞视频", in: scheme)

        model.deleteRuleGroup(named: "💬 Ai平台", for: scheme)
        XCTAssertFalse(model.exportedRuleOrder(for: scheme).contains { $0.resource == .inline("DOMAIN,a.example") })
        XCTAssertTrue(model.exportedRuleOrder(for: scheme).contains { $0.resource == .inline("DOMAIN,b.example") })

        model.resetRuleCustomization(for: scheme)
        XCTAssertFalse(model.exportedRuleOrder(for: scheme).contains { $0.origin == .supplement })
    }

    func testSupplementsAreOrderedMostSpecificFirst() {
        let customization: RuleSchemeCustomization? = nil
        let flows = [
            CustomRuleFlow.groupSupplement(schemeID: "s", groupName: "A", rules: [
                SupplementRule(kind: .keyword, value: "google"),
                SupplementRule(kind: .domainSuffix, value: "google.com"),
            ]),
            CustomRuleFlow.groupSupplement(schemeID: "s", groupName: "B", rules: [
                SupplementRule(kind: .ipRange, value: "10.0.0.0/8"),
                SupplementRule(kind: .domainSuffix, value: "mail.google.com"),
                SupplementRule(kind: .domain, value: "x.mail.google.com"),
            ]),
        ]
        let rulesets = RuleScheme.supplementRulesets(from: flows, customization: customization, validPolicies: ["A", "B"])
        XCTAssertEqual(rulesets.map { "\($0.groupName):\($0.resource)" }, [
            "B:inline(\"DOMAIN,x.mail.google.com\")",
            "B:inline(\"DOMAIN-SUFFIX,mail.google.com\")",
            "A:inline(\"DOMAIN-SUFFIX,google.com\")",
            "A:inline(\"DOMAIN-KEYWORD,google\")",
            "B:inline(\"IP-CIDR,10.0.0.0/8\")",
        ])
        XCTAssertTrue(RuleScheme.supplementRulesets(from: flows, customization: nil, validPolicies: ["A"])
            .allSatisfy { $0.groupName == "A" }, "已删除的组不输出补充规则")
    }

    func testProbeReportsIPRulesItCannotEvaluateForADomain() {
        let rulesets = [
            RuleSchemeRuleset(groupName: "AI", resource: .inline("DOMAIN-SUFFIX,openai.com")),
            RuleSchemeRuleset(groupName: "Direct", resource: .inline("GEOIP,CN")),
            RuleSchemeRuleset(groupName: "LAN", resource: .inline("IP-CIDR,10.0.0.0/8,no-resolve")),
            RuleSchemeRuleset(groupName: "Final", resource: .inline("FINAL")),
        ]
        let lines: (RuleSchemeRuleset) -> [String] = {
            if case .inline(let line) = $0.resource { return [line] }
            return []
        }
        let domain = RuleMatchProbe.probe(host: "example.com", rulesets: rulesets, lines: lines)
        XCTAssertEqual(domain.hit?.groupName, "Final")
        XCTAssertEqual(domain.unresolvedIPRule?.groupName, "Direct")
        XCTAssertEqual(RuleMatchProbe.probe(host: "api.openai.com", rulesets: rulesets, lines: lines).hit?.groupName, "AI")
        XCTAssertEqual(RuleMatchProbe.probe(host: "10.1.2.3", rulesets: rulesets, lines: lines, country: { _ in nil }).hit?.groupName, "LAN")
        XCTAssertEqual(RuleMatchProbe.probe(host: "1.2.3.4", rulesets: rulesets, lines: lines, country: { _ in "CN" }).hit?.groupName, "Direct")
        XCTAssertEqual(RuleMatchProbe.normalizedHost("https://Chat.OpenAI.com/c/1"), "chat.openai.com")
        XCTAssertNil(RuleMatchProbe.normalizedHost("YouTube"), "普通搜索词不当作域名")
    }

    func testOlderSnapshotsDecodeAndOriginNeverPersists() throws {
        let legacy = Data(#"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","schemeID":"s","name":"n","policyName":"p","rulesText":"","isEnabled":true}"#.utf8)
        XCTAssertNil(try JSONDecoder().decode(CustomRuleFlow.self, from: legacy).isGroupSupplement)

        let ruleset = RuleSchemeRuleset(groupName: "A", resource: .inline("DOMAIN,a.example"), origin: .supplement)
        let encoded = try XCTUnwrap(String(data: JSONEncoder().encode(ruleset), encoding: .utf8))
        XCTAssertFalse(encoded.contains("origin"))
        XCTAssertEqual(ruleset, RuleSchemeRuleset(groupName: "A", resource: .inline("DOMAIN,a.example")))
    }

    // MARK: Dragging a group moves its priority next to where it was dropped

    /// The user's case: in 全分组, drag 📹 油管视频 below 🌍 国外媒体. The list
    /// (and the client's panel) take the new order, YouTube's rules now match
    /// after 国外媒体's, the app names the sites that change hands, and every
    /// other group's rules stay exactly where they were.
    @MainActor
    func testDraggingYouTubeBelowForeignMediaMovesItsPriorityAndWarns() throws {
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let store = PersistenceStore(fileURL: fileURL)
        let model = AppModel(persistence: store, arguments: [])
        let scheme = try XCTUnwrap(RuleSchemeRepository().bundledSchemes().first { $0.id == "acl4ssr-full" })
        XCTAssertEqual(model.probeRule(host: "www.youtube.com", in: scheme).result.hit?.groupName, "📹 油管视频")
        let rulesBefore = model.exportedRuleOrder(for: scheme)

        let original = model.customizableRuleGroups(for: scheme).map(\.name)
        var display = original
        XCTAssertEqual(display.first, "🚀 节点选择")
        let youtube = "📹 油管视频", media = "🌍 国外媒体"
        display.removeAll { $0 == youtube }
        display.insert(youtube, at: try XCTUnwrap(display.firstIndex(of: media)) + 1)
        let previous = model.matchingRuleGroupNames(for: scheme)
        let next = model.matchingOrderAfterDragging(youtube, from: original, to: display, in: scheme)
        XCTAssertEqual(next.firstIndex(of: youtube), try XCTUnwrap(next.firstIndex(of: media)) + 1, "排在国外媒体之后匹配")
        XCTAssertEqual(next.filter { $0 != youtube }, previous.filter { $0 != youtube }, "只动被拖的组")

        let conflicts = model.matchingOrderConflicts(from: previous, to: next, in: scheme)
        let conflict = try XCTUnwrap(conflicts.first { $0.from == youtube && $0.to == media })
        XCTAssertTrue(conflict.domains.contains { $0.contains("youtube") }, "\(conflict.domains)")

        model.setRuleGroupOrder(display, for: scheme)
        model.setMatchingOrder(next, for: scheme)
        XCTAssertEqual(model.customizableRuleGroups(for: scheme).map(\.name), display, "列表和客户端面板顺序跟着变")
        XCTAssertEqual(model.effectiveScheme(scheme).groups.map(\.name), display)
        XCTAssertEqual(model.probeRule(host: "www.youtube.com", in: scheme).result.hit?.groupName, media)
        let rulesAfter = model.exportedRuleOrder(for: scheme)
        XCTAssertEqual(rulesAfter.filter { $0.groupName != youtube }, rulesBefore.filter { $0.groupName != youtube })
        XCTAssertEqual(Set(rulesAfter), Set(rulesBefore))

        // Undo restores both orders; a reload keeps whatever was kept.
        model.setRuleGroupOrder(model.customizableScheme(for: scheme).groups.map(\.name), for: scheme)
        model.setMatchingOrder(previous, for: scheme)
        XCTAssertEqual(model.exportedRuleOrder(for: scheme), rulesBefore)
        model.setMatchingOrder(next, for: scheme)
        XCTAssertEqual(AppModel(persistence: store, arguments: []).probeRule(host: "www.youtube.com", in: scheme).result.hit?.groupName, media)
    }

    /// Dragging up above a group matches right before it; dragging a node
    /// group, or within the same relative place, changes no matching.
    @MainActor
    func testDraggingUpMatchesBeforeAndNodeGroupsNeverChangeMatching() throws {
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let model = AppModel(persistence: PersistenceStore(fileURL: fileURL), arguments: [])
        let scheme = try XCTUnwrap(RuleSchemeRepository().bundledSchemes().first { $0.id == "acl4ssr-full" })
        let current = model.matchingRuleGroupNames(for: scheme)
        let original = model.customizableRuleGroups(for: scheme).map(\.name)
        var display = original

        // 🎯 全球直连 dragged up above 💬 Ai平台 already matches first: no change.
        var up = display.filter { $0 != "🎯 全球直连" }
        up.insert("🎯 全球直连", at: try XCTUnwrap(up.firstIndex(of: "💬 Ai平台")))
        XCTAssertEqual(model.matchingOrderAfterDragging("🎯 全球直连", from: original, to: up, in: scheme), current)

        // 🌍 国外媒体 dragged up above 💬 Ai平台 now matches right before it.
        var media = display.filter { $0 != "🌍 国外媒体" }
        media.insert("🌍 国外媒体", at: try XCTUnwrap(media.firstIndex(of: "💬 Ai平台")))
        let next = model.matchingOrderAfterDragging("🌍 国外媒体", from: original, to: media, in: scheme)
        // It passed Ai平台, 油管视频 and others that matched before it; it now
        // matches right before the earliest of them.
        let passedPositions = ["💬 Ai平台", "📹 油管视频", "🎥 奈飞视频", "📺 巴哈姆特", "📺 哔哩哔哩"].compactMap { current.firstIndex(of: $0) }
        XCTAssertEqual(next.firstIndex(of: "🌍 国外媒体"), passedPositions.min())

        // A node group has no rules: dragging it never touches matching.
        display.removeAll { $0 == "🇭🇰 香港节点" }
        display.insert("🇭🇰 香港节点", at: 0)
        XCTAssertEqual(model.matchingOrderAfterDragging("🇭🇰 香港节点", from: original, to: display, in: scheme), current)

        // Dragged far down past several groups, as a drag that overshoots does,
        // 油管视频 still matches after 国外媒体, the last group it used to beat.
        var far = original.filter { $0 != "📹 油管视频" }
        far.insert("📹 油管视频", at: try XCTUnwrap(far.firstIndex(of: "Ⓜ️ 微软服务")) + 1)
        let farNext = model.matchingOrderAfterDragging("📹 油管视频", from: original, to: far, in: scheme)
        XCTAssertGreaterThan(try XCTUnwrap(farNext.firstIndex(of: "📹 油管视频")), try XCTUnwrap(farNext.firstIndex(of: "🌍 国外媒体")))
    }

    func testMovingAScatteredGroupKeepsItsGeoIPFallbackLast() throws {
        let rulesets = [
            RuleSchemeRuleset(groupName: "Direct", resource: .inline("DOMAIN-SUFFIX,lan")),
            RuleSchemeRuleset(groupName: "AI", resource: .inline("DOMAIN-SUFFIX,openai.com")),
            RuleSchemeRuleset(groupName: "Proxy", resource: .inline("DOMAIN-SUFFIX,google.com")),
            RuleSchemeRuleset(groupName: "Direct", resource: .inline("DOMAIN-SUFFIX,cn")),
            RuleSchemeRuleset(groupName: "Direct", resource: .inline("GEOIP,CN")),
        ]
        func lines(_ rulesets: [RuleSchemeRuleset]) -> [String] {
            rulesets.map { ruleset -> String in
                guard case .inline(let rule) = ruleset.resource else { return "" }
                return "\(ruleset.groupName):\(rule)"
            }
        }
        XCTAssertEqual(RuleScheme.matchingGroupNames(of: rulesets), ["Direct", "AI", "Proxy"])
        XCTAssertEqual(lines(RuleScheme.reordering(rulesets, by: ["Direct", "AI", "Proxy"])), lines(rulesets))
        XCTAssertEqual(lines(RuleScheme.reordering(rulesets, by: ["Proxy", "Direct", "AI"])), [
            "Proxy:DOMAIN-SUFFIX,google.com", "Direct:DOMAIN-SUFFIX,lan", "AI:DOMAIN-SUFFIX,openai.com",
            "Direct:DOMAIN-SUFFIX,cn", "Direct:GEOIP,CN",
        ])
        XCTAssertEqual(lines(RuleScheme.reordering(rulesets, by: ["AI", "Proxy", "Direct"])), [
            "AI:DOMAIN-SUFFIX,openai.com", "Proxy:DOMAIN-SUFFIX,google.com",
            "Direct:DOMAIN-SUFFIX,lan", "Direct:DOMAIN-SUFFIX,cn", "Direct:GEOIP,CN",
        ])
        XCTAssertEqual(lines(RuleScheme.reordering(rulesets, by: ["Gone", "Direct", "AI", "Proxy"])), lines(rulesets))
    }

    func testDomainMatcherFindsSitesBothGroupsClaim() {
        let telegram = RuleGroupDomainMatcher(lines: ["DOMAIN-SUFFIX,t.me", "DOMAIN,telegram.org", "IP-CIDR,91.108.4.0/22"])
        let proxy = RuleGroupDomainMatcher(lines: ["DOMAIN-SUFFIX,me", "DOMAIN-KEYWORD,telegram", "DOMAIN-SUFFIX,google.com"])
        let unrelated = RuleGroupDomainMatcher(lines: ["DOMAIN-SUFFIX,apple.com"])
        XCTAssertEqual(RuleGroupDomainMatcher.sharedHosts(telegram, proxy), ["t.me", "telegram.org"])
        XCTAssertTrue(RuleGroupDomainMatcher.sharedHosts(telegram, unrelated).isEmpty)
        XCTAssertTrue(proxy.matches("api.t.me"))
        XCTAssertFalse(unrelated.matches("notapple.com"))
    }

    /// The customization list, the home card preview and every export share
    /// one group order. Setting it alone never changes the rule order; a
    /// drag changes matching separately, for the dragged group only.
    @MainActor
    func testGroupOrderIsOneOrderEverywhereAndLeavesMatchingAlone() throws {
        let fileURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let store = PersistenceStore(fileURL: fileURL)
        let model = AppModel(persistence: store, arguments: [])
        let scheme = try XCTUnwrap(RuleSchemeRepository().bundledSchemes().first { $0.id == "acl4ssr-default" })
        var names = model.customizableRuleGroups(for: scheme).map(\.name)
        XCTAssertEqual(names.first, "🚀 节点选择", "和客户端面板一样，节点选择排第一")
        XCTAssertEqual(model.effectiveScheme(scheme).groups.map(\.name), names)
        let rules = model.exportedRuleOrder(for: scheme)

        names.removeAll { $0 == "🎯 全球直连" }
        names.insert("🎯 全球直连", at: 0)
        model.setRuleGroupOrder(names, for: scheme)
        XCTAssertEqual(model.customizableRuleGroups(for: scheme).map(\.name), names)
        XCTAssertEqual(model.effectiveScheme(scheme).groups.map(\.name), names, "导出的策略组顺序跟着拖动变")
        XCTAssertEqual(model.exportedRuleOrder(for: scheme), rules, "规则匹配顺序不变")

        // Stash is the `.clash` target; its panel lists proxy-groups in order.
        let stash = ConfigurationGenerator().generate(nodes: nodes, scheme: model.effectiveScheme(scheme), target: .clash, preferRuleSets: false).content
        let groups = try XCTUnwrap(stash.components(separatedBy: "proxy-groups:").dropFirst().first)
        let direct = try XCTUnwrap(groups.range(of: "全球直连"))
        let proxy = try XCTUnwrap(groups.range(of: "节点选择"))
        XCTAssertLessThan(direct.lowerBound, proxy.lowerBound, "Stash 里的策略组顺序和列表一致")
        XCTAssertEqual(AppModel(persistence: store, arguments: []).customizableRuleGroups(for: scheme).map(\.name), names)
    }
}
