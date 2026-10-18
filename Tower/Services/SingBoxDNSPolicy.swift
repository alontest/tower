import Foundation

/// Mode and DNS policy for the official sing-box dialect. Hiddify keeps its
/// independently versioned output. All inputs are already sanitized JSON tags.
enum SingBoxDNSPolicy {
    // These are exported mode identifiers, intentionally stable across app languages.
    static let ruleMode = "规则判定"
    static let globalMode = "全局代理"
    static let directMode = "直接连接"

    private static func availableTag(_ base: String, used: Set<String>) -> String {
        var tag = base
        var suffix = 2
        while used.contains(tag) { tag = "\(base) \(suffix)"; suffix += 1 }
        return tag
    }

    static func apply(to configuration: inout [String: Any], nodeTags: [String],
                      preferredProxy: String?, domainRules: [[String: Any]],
                      protection: RuleSchemeDNSProtectionMode, ipv6Enabled: Bool? = nil,
                      chinaResolverHint: Bool = false, chinaResolver: [String: Any]? = nil) {
        guard var outbounds = configuration["outbounds"] as? [[String: Any]],
              var route = configuration["route"] as? [String: Any],
              var routeRules = route["rules"] as? [[String: Any]],
              var dns = configuration["dns"] as? [String: Any],
              var servers = dns["servers"] as? [[String: Any]] else { return }
        let members = outbounds.reduce(into: [String: [String]]()) { result, outbound in
            if let tag = outbound["tag"] as? String, let children = outbound["outbounds"] as? [String] {
                result[tag] = children
            }
        }
        func onlyLeaves(_ tag: String, allowed: Set<String>, visiting: Set<String> = []) -> Bool {
            if allowed.contains(tag) { return true }
            guard !visiting.contains(tag), let children = members[tag], !children.isEmpty else { return false }
            return children.allSatisfy { onlyLeaves($0, allowed: allowed, visiting: visiting.union([tag])) }
        }
        // DNS rules cannot inspect a selector's runtime selection. In standard
        // mode project the exported default (including nested selectors), not
        // all possible choices. Keep onlyLeaves above for proxy bootstrap safety.
        let definitions = Dictionary(outbounds.compactMap { outbound -> (String, [String: Any])? in
            guard let tag = outbound["tag"] as? String else { return nil }
            return (tag, outbound)
        }, uniquingKeysWith: { first, _ in first })
        func defaultsToDirect(_ tag: String, visiting: Set<String> = []) -> Bool {
            guard !visiting.contains(tag), let definition = definitions[tag] else { return false }
            if definition["type"] as? String == "direct" { return true }
            guard definition["type"] as? String == "selector",
                  let children = members[tag], !children.isEmpty else {
                return onlyLeaves(tag, allowed: ["DIRECT"])
            }
            let selected = definition["default"] as? String ?? children[0]
            guard children.contains(selected) else { return false }
            return defaultsToDirect(selected, visiting: visiting.union([tag]))
        }
        let concreteNodes = Set(nodeTags)
        var proxy: String?
        if !nodeTags.isEmpty {
            let candidates = [preferredProxy].compactMap { $0 } + outbounds.compactMap { $0["tag"] as? String }
            proxy = candidates.first { members[$0] != nil && onlyLeaves($0, allowed: concreteNodes) }
            if proxy == nil {
                let used = Set(outbounds.compactMap { $0["tag"] as? String }).union(concreteNodes)
                let tag = availableTag("代理自动选择", used: used)
                outbounds.append(["tag": tag, "type": "urltest", "outbounds": nodeTags,
                                  "url": "https://www.gstatic.com/generate_204", "interval": "300s", "tolerance": 50])
                proxy = tag
            }
        }
        for index in servers.indices where (servers[index]["tag"] as? String)?.hasPrefix("remote") == true {
            servers[index]["detour"] = proxy
        }
        // Global needs its own manual selector. Never reuse a regional group
        // (or a business selector whose current choice may be DIRECT).
        var globalProxy: String?
        var globalDNSTag: String?
        if !nodeTags.isEmpty {
            var used = Set(outbounds.compactMap { $0["tag"] as? String }).union(concreteNodes)
            var automatic = outbounds.first {
                $0["type"] as? String == "urltest"
                    && Set($0["outbounds"] as? [String] ?? []) == concreteNodes
            }?["tag"] as? String
            if automatic == nil {
                let tag = availableTag("全局自动选择", used: used)
                used.insert(tag)
                outbounds.append(["tag": tag, "type": "urltest", "outbounds": nodeTags,
                                  "url": "https://www.gstatic.com/generate_204", "interval": "300s", "tolerance": 50])
                automatic = tag
            }
            if let automatic {
                let tag = availableTag(globalMode, used: used)
                outbounds.insert(["tag": tag, "type": "selector", "outbounds": [automatic] + nodeTags,
                                  "default": automatic, "interrupt_exist_connections": true], at: 0)
                globalProxy = tag
                // Copy the configured resolver transport; only its proxy path
                // changes, so custom DoH/TLS settings remain intact.
                if var remote = servers.first(where: { $0["tag"] as? String == "remote" }) {
                    let dnsTag = availableTag("remote-global", used: Set(servers.compactMap { $0["tag"] as? String }))
                    remote["tag"] = dnsTag
                    remote["detour"] = tag
                    servers.append(remote)
                    globalDNSTag = dnsTag
                }
            }
        }
        let fallback = proxy == nil ? "local" : "remote"
        let finalGroup = route["final"] as? String ?? "DIRECT"
        let directFinal = defaultsToDirect(finalGroup)
        dns["final"] = protection != .strict && directFinal ? "local" : fallback
        // A domain no list mentions went to the remote resolver through the
        // proxy, whose answer points at a CDN near the exit: Chinese sites got
        // US/JP/SG edges and then missed the China IP rule. sing-box's own
        // "without DNS leaks" recipe asks the remote resolver again with a
        // Chinese client subnet and keeps the answer only if it is a Chinese
        // address; otherwise the query falls through to `final` unchanged.
        // Nothing reaches the local resolver, so the lookup is not leaked.
        // Cloudflare ignores ECS, so the default resolver here is Google's.
        // Measured 2026-09-29: unlisted sites moved from US/JP/SG to CN
        // answers, foreign answers were unchanged, cold lookups ~70 ms slower.
        var chinaTag: String?
        if chinaResolverHint, protection != .followScheme, let proxy, dns["final"] as? String == "remote",
           !IPCountryDatabase.cidrs(forCountry: "CN").isEmpty {
            let tag = availableTag("remote-cn", used: Set(servers.compactMap { $0["tag"] as? String }))
            var server = chinaResolver ?? [
                "type": "https", "server": "8.8.8.8", "server_port": 443, "path": "/dns-query",
                "tls": ["enabled": true, "server_name": "dns.google"]
            ]
            server["tag"] = tag
            server["detour"] = proxy
            servers.append(server)
            chinaTag = tag
        }
        dns["servers"] = servers
        var dnsRules: [[String: Any]] = [
            ["clash_mode": directMode, "action": "route", "server": "local"],
            globalDNSTag.map { ["clash_mode": globalMode, "action": "route", "server": $0] }
                ?? ["clash_mode": globalMode, "action": "reject"]
        ]
        // Project only domain predicates, in source order: cached rules, or a
        // list's domain-only SRS, which tests the queried name and nothing
        // else. Do not use IP/SRS response filters: they may query the direct
        // resolver before discovering that a domain belongs on the proxy.
        for rule in domainRules {
            var projected = rule.filter { ["domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set"].contains($0.key) }
            guard !projected.isEmpty else { continue }
            if rule["action"] as? String == "reject" || rule["outbound"] as? String == "REJECT" {
                projected["action"] = "reject"
            } else {
                let direct = (rule["outbound"] as? String).map { defaultsToDirect($0) } ?? false
                projected["action"] = "route"
                projected["server"] = protection != .strict && direct ? "local" : fallback
                // Strict mode keeps direct names off the domestic resolver
                // but still wants the Chinese CDN edge for them.
                if protection == .strict, direct, let chinaTag {
                    projected["server"] = chinaTag
                    projected["client_subnet"] = chinaClientSubnet
                }
            }
            dnsRules.append(projected)
        }
        if let chinaTag {
            // sing-box 1.14 response matching: ask, then answer with the
            // result only if it is Chinese; anything else falls through to
            // `final`. The older form (a `rule_set` address filter on a route
            // rule) behaves the same but is deprecated for removal in 1.16,
            // and the official apps pop up "your profile is outdated" for it.
            // Only address queries: other types never match a CIDR set and
            // would just be asked twice.
            dnsRules.append([
                "query_type": ["A", "AAAA"],
                "action": "evaluate", "server": chinaTag, "client_subnet": chinaClientSubnet
            ])
            dnsRules.append([
                "match_response": true,
                "rule_set": [RoutingRuleCapabilities.localGeoIPPrefix + "cn"],
                "action": "respond"
            ])
        }
        dns["rules"] = dnsRules
        if protection == .followScheme,
           let index = routeRules.firstIndex(where: { $0["action"] as? String == "hijack-dns" }) {
            // The tunnel's own DNS still needs handling, but don't force all
            // port-53 traffic through the module in follow-scheme mode.
            routeRules[index] = ["protocol": "dns", "action": "hijack-dns"]
        }
        let index = (routeRules.firstIndex { $0["action"] as? String == "hijack-dns" } ?? -1) + 1
        routeRules.insert(contentsOf: [
            // Resolve user destinations through DNS rules, not the separate
            // default_domain_resolver used to bootstrap outbound server names.
            ["action": "resolve"],
            globalProxy.map { ["clash_mode": globalMode, "action": "route", "outbound": $0] }
                ?? ["clash_mode": globalMode, "action": "reject"],
            ["clash_mode": directMode, "action": "route", "outbound": "DIRECT"]
        ], at: index)
        routeRules.append(["clash_mode": ruleMode, "action": "route", "outbound": finalGroup])
        route["rules"] = routeRules
        var inbounds = configuration["inbounds"] as? [[String: Any]] ?? []
        for index in inbounds.indices where inbounds[index]["type"] as? String == "tun" {
            inbounds[index]["strict_route"] = protection != .followScheme
        }
        var experimental = configuration["experimental"] as? [String: Any] ?? [:]
        experimental["clash_api"] = ["default_mode": ruleMode]
        configuration["experimental"] = experimental
        configuration["outbounds"] = outbounds
        configuration["route"] = route
        if let ipv6Enabled {
            dns["strategy"] = ipv6Enabled ? "prefer_ipv4" : "ipv4_only"
            for index in inbounds.indices where inbounds[index]["type"] as? String == "tun" {
                inbounds[index]["address"] = ipv6Enabled
                    ? ["172.19.0.1/30", "fdfe:dcba:9876::1/126"] : ["172.19.0.1/30"]
            }
        }
        configuration["dns"] = dns
        configuration["inbounds"] = inbounds
    }

    /// Any Chinese address works; the resolver only needs to believe the
    /// client is in China. The sing-box manual uses the same 114 DNS range.
    static let chinaClientSubnet = "114.114.114.0/24"

    /// One rule, or a domain-only rule set standing for a whole list.
    enum DomainSource {
        case rule(RuleSetEmissionPlanner.InlineRule)
        case ruleSet(tag: String, policyName: String)
    }

    static func domainRules(from entries: [RuleSetEmissionPlanner.InlineRule]) -> [[String: Any]] {
        domainRules(from: entries.map(DomainSource.rule))
    }

    static func domainRules(from sources: [DomainSource]) -> [[String: Any]] {
        let fields = ["DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword"]
        var result: [[String: Any]] = []
        var pendingPolicy: String?
        var pendingFields: [String: [String]] = [:]
        func flush() {
            guard let policy = pendingPolicy, !pendingFields.isEmpty else { return }
            var rule: [String: Any] = pendingFields
            rule["outbound"] = policy
            result.append(rule)
            pendingFields = [:]
        }
        for source in sources {
            let entry: RuleSetEmissionPlanner.InlineRule
            switch source {
            case .ruleSet(let tag, let policyName):
                flush()
                pendingPolicy = nil
                result.append(["rule_set": [tag], "outbound": policyName])
                continue
            case .rule(let rule):
                entry = rule
            }
            let parts = entry.line.split(separator: ",", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            guard parts.count >= 2, let field = fields[parts[0].uppercased()], !parts[1].isEmpty else { continue }
            if pendingPolicy != entry.policyName {
                flush()
                pendingPolicy = entry.policyName
            }
            pendingFields[field, default: []].append(parts[1])
        }
        flush()
        return result
    }
}
