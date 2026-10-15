import Darwin
import Foundation

/// A single domain or IP condition the user attached to an existing policy
/// group ("send this site through 💬 Ai平台"). Supplements always match before
/// every template rule, so what the user adds is exactly what happens; the
/// template's own order is never rearranged (issue #40, #45).
struct SupplementRule: Hashable, Identifiable {
    enum Kind: String, CaseIterable, Identifiable {
        case domainSuffix
        case domain
        case keyword
        case ipRange

        var id: String { rawValue }

        var title: String {
            switch self {
            case .domainSuffix: String(localized: "域名及子域名")
            case .domain: String(localized: "仅此域名")
            case .keyword: String(localized: "包含关键词")
            case .ipRange: String(localized: "IP 段")
            }
        }

        var placeholder: String {
            switch self {
            case .domainSuffix, .domain: "example.com"
            case .keyword: "example"
            case .ipRange: "203.0.113.0/24"
            }
        }
    }

    enum InputError: LocalizedError, Equatable {
        case empty
        case invalidDomain
        case invalidKeyword
        case invalidIPRange

        var errorDescription: String? {
            switch self {
            case .empty: String(localized: "请输入要匹配的域名或 IP。")
            case .invalidDomain: String(localized: "域名格式不正确，例如 example.com。")
            case .invalidKeyword: String(localized: "关键词不能包含空格或逗号。")
            case .invalidIPRange: String(localized: "IP 段格式不正确，例如 203.0.113.0/24。")
            }
        }
    }

    let kind: Kind
    let value: String

    var id: String { line }

    var ruleType: String {
        switch kind {
        case .domainSuffix: "DOMAIN-SUFFIX"
        case .domain: "DOMAIN"
        case .keyword: "DOMAIN-KEYWORD"
        case .ipRange: value.contains(":") ? "IP-CIDR6" : "IP-CIDR"
        }
    }

    /// Policy-free condition, as stored in a `CustomRuleFlow`. The generator
    /// adds the group name and, for IP ranges, `no-resolve`.
    var line: String { "\(ruleType),\(value)" }

    init(kind: Kind, value: String) {
        self.kind = kind
        self.value = value
    }

    init?(line: String) {
        guard let fields = RoutingRuleSyntax.fields(line), fields.count >= 2 else { return nil }
        let value = fields[1].trimmingCharacters(in: .whitespaces)
        switch fields[0].uppercased() {
        case "DOMAIN-SUFFIX": self.init(kind: .domainSuffix, value: value)
        case "DOMAIN": self.init(kind: .domain, value: value)
        case "DOMAIN-KEYWORD": self.init(kind: .keyword, value: value)
        case "IP-CIDR", "IP-CIDR6": self.init(kind: .ipRange, value: value)
        default: return nil
        }
    }

    /// Accepts what people actually paste: a bare host, a full URL, `*.host`
    /// or `.host`. An address or CIDR is always an IP range, whatever kind was
    /// picked, because a domain rule could never match it.
    static func parse(_ input: String, kind: Kind) throws -> SupplementRule {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw InputError.empty }
        if let range = IPRange(text) {
            return SupplementRule(kind: .ipRange, value: range.description)
        }
        if kind == .ipRange { throw InputError.invalidIPRange }
        if kind == .keyword {
            guard !text.contains(where: { $0.isWhitespace || $0 == "," }) else {
                throw InputError.invalidKeyword
            }
            return SupplementRule(kind: .keyword, value: text.lowercased())
        }

        if let url = URL(string: text), let host = url.host, url.scheme != nil {
            text = host
        } else if let slash = text.firstIndex(of: "/") {
            text = String(text[..<slash])
        }
        if let colon = text.lastIndex(of: ":"), text[text.index(after: colon)...].allSatisfy(\.isNumber) {
            text = String(text[..<colon])
        }
        var resolvedKind = kind
        if text.hasPrefix("*.") {
            text.removeFirst(2)
            resolvedKind = .domainSuffix
        } else if text.hasPrefix("+.") || text.hasPrefix(".") {
            text.removeFirst(text.hasPrefix(".") ? 1 : 2)
            resolvedKind = .domainSuffix
        }
        text = text.lowercased()
        guard isValidDomain(text) else { throw InputError.invalidDomain }
        return SupplementRule(kind: resolvedKind, value: text)
    }

    private static func isValidDomain(_ text: String) -> Bool {
        guard !text.isEmpty, text.count <= 253,
              !text.hasPrefix("."), !text.hasSuffix("."), !text.contains("..") else { return false }
        return text.split(separator: ".").allSatisfy { label in
            !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
        }
    }

    /// Supplements are emitted most specific first, so a narrow rule the user
    /// added for one group is not shadowed by a broader one added for another.
    static func matchingOrder(_ lhs: SupplementRule, _ rhs: SupplementRule) -> Bool {
        func rank(_ rule: SupplementRule) -> (Int, Int) {
            switch rule.kind {
            case .domain: (0, 0)
            case .domainSuffix: (1, -rule.value.split(separator: ".").count)
            case .keyword: (2, -rule.value.count)
            case .ipRange: (3, -(IPRange(rule.value)?.prefixLength ?? 0))
            }
        }
        return rank(lhs) < rank(rhs)
    }
}

/// An IPv4 or IPv6 network parsed from `address` or `address/prefix`.
struct IPRange: CustomStringConvertible {
    let bytes: [UInt8]
    let prefixLength: Int
    private let text: String

    init?(_ raw: String) {
        let parts = raw.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let address = String(parts[0])
        guard let bytes = Self.bytes(of: address) else { return nil }
        let maximum = bytes.count * 8
        let prefix: Int
        if parts.count == 2 {
            guard let value = Int(parts[1]), (0...maximum).contains(value) else { return nil }
            prefix = value
        } else {
            prefix = maximum
        }
        self.bytes = bytes
        self.prefixLength = prefix
        self.text = "\(address)/\(prefix)"
    }

    var description: String { text }

    static func bytes(of address: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            return withUnsafeBytes(of: v4.s_addr) { Array($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            return withUnsafeBytes(of: v6) { Array($0) }
        }
        return nil
    }

    func contains(_ address: [UInt8]) -> Bool {
        guard address.count == bytes.count else { return false }
        var remaining = prefixLength
        for index in bytes.indices where remaining > 0 {
            let bits = min(8, remaining)
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
            guard address[index] & mask == bytes[index] & mask else { return false }
            remaining -= bits
        }
        return true
    }
}

/// Answers "where would this site go?" against the exported rule order, using
/// only what is on the device. Domain rules are evaluated exactly; rules that
/// need the resolved address (GEOIP, IP-CIDR for a domain, IP-ASN) cannot be,
/// so the first such rule is reported as a possible earlier match instead of
/// being guessed.
enum RuleMatchProbe {
    struct Hit: Equatable {
        /// Index into the rulesets that were probed.
        let rulesetIndex: Int
        let groupName: String
        let rule: String
    }

    struct Result: Equatable {
        let host: String
        let hit: Hit?
        let unresolvedIPRule: Hit?
    }

    static func normalizedHost(_ input: String) -> String? {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !text.contains(" ") else { return nil }
        if let url = URL(string: text), let host = url.host, url.scheme != nil {
            text = host
        } else if let slash = text.firstIndex(of: "/"), IPRange(text) == nil {
            text = String(text[..<slash])
        }
        text = text.lowercased()
        if IPRange.bytes(of: text) != nil { return text }
        guard text.contains("."), !text.hasPrefix("."), !text.hasSuffix("."),
              text.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." || $0 == "_" }) else {
            return nil
        }
        return text
    }

    static func probe(
        host: String,
        rulesets: [RuleSchemeRuleset],
        lines: (RuleSchemeRuleset) -> [String],
        country: ((String) -> String?)? = nil
    ) -> Result {
        let address = IPRange.bytes(of: host)
        var unresolved: Hit?
        for (index, ruleset) in rulesets.enumerated() {
            for line in lines(ruleset) {
                guard let fields = RoutingRuleSyntax.fields(line), let type = fields.first?.uppercased() else { continue }
                let value = fields.count > 1 ? fields[1].trimmingCharacters(in: .whitespaces) : ""
                let hit = Hit(rulesetIndex: index, groupName: ruleset.groupName, rule: line)
                switch type {
                case "FINAL", "MATCH":
                    return Result(host: host, hit: hit, unresolvedIPRule: unresolved)
                case "DOMAIN":
                    if address == nil, host == value.lowercased() { return Result(host: host, hit: hit, unresolvedIPRule: unresolved) }
                case "DOMAIN-SUFFIX":
                    let suffix = value.lowercased()
                    if address == nil, host == suffix || host.hasSuffix("." + suffix) {
                        return Result(host: host, hit: hit, unresolvedIPRule: unresolved)
                    }
                case "DOMAIN-KEYWORD":
                    if address == nil, !value.isEmpty, host.contains(value.lowercased()) {
                        return Result(host: host, hit: hit, unresolvedIPRule: unresolved)
                    }
                case "DOMAIN-WILDCARD":
                    if address == nil, wildcard(value.lowercased(), matches: host) {
                        return Result(host: host, hit: hit, unresolvedIPRule: unresolved)
                    }
                case "IP-CIDR", "IP-CIDR6":
                    if let address {
                        if IPRange(value)?.contains(address) == true {
                            return Result(host: host, hit: hit, unresolvedIPRule: unresolved)
                        }
                    } else if unresolved == nil, !fields.dropFirst(2).contains(where: { $0.lowercased() == "no-resolve" }) {
                        unresolved = hit
                    }
                case "GEOIP":
                    if address != nil, let country, let code = country(host) {
                        if code.caseInsensitiveCompare(value) == .orderedSame {
                            return Result(host: host, hit: hit, unresolvedIPRule: unresolved)
                        }
                    } else if address == nil, unresolved == nil,
                              !fields.dropFirst(2).contains(where: { $0.lowercased() == "no-resolve" }) {
                        unresolved = hit
                    }
                default:
                    continue
                }
            }
        }
        return Result(host: host, hit: nil, unresolvedIPRule: unresolved)
    }

    private static func wildcard(_ pattern: String, matches host: String) -> Bool {
        let p = Array(pattern), h = Array(host)
        var pi = 0, hi = 0, star = -1, mark = 0
        while hi < h.count {
            if pi < p.count, p[pi] == "?" || p[pi] == h[hi] {
                pi += 1; hi += 1
            } else if pi < p.count, p[pi] == "*" {
                star = pi; mark = hi; pi += 1
            } else if star >= 0 {
                pi = star + 1; mark += 1; hi = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
}

/// The domain rules of one group, for telling which sites two groups both
/// claim. Clients stop at the first match, so when a drag swaps two such
/// groups those sites change hands; the rules screen says so before export.
struct RuleGroupDomainMatcher {
    private var domains = Set<String>()
    private var suffixes = Set<String>()
    private var keywords: [String] = []
    /// One representative host per DOMAIN / DOMAIN-SUFFIX rule.
    private(set) var hosts: [String] = []

    init(lines: [String]) {
        for line in lines {
            guard let fields = RoutingRuleSyntax.fields(line), fields.count >= 2 else { continue }
            let value = fields[1].trimmingCharacters(in: .whitespaces).lowercased()
            guard !value.isEmpty else { continue }
            switch fields[0].uppercased() {
            case "DOMAIN": domains.insert(value); hosts.append(value)
            case "DOMAIN-SUFFIX": suffixes.insert(value); hosts.append(value)
            case "DOMAIN-KEYWORD": keywords.append(value)
            default: continue
            }
        }
    }

    func matches(_ host: String) -> Bool {
        if domains.contains(host) { return true }
        var remainder = Substring(host)
        while true {
            if suffixes.contains(String(remainder)) { return true }
            guard let dot = remainder.firstIndex(of: ".") else { break }
            remainder = remainder[remainder.index(after: dot)...]
        }
        return keywords.contains { host.contains($0) }
    }

    /// Hosts listed by either group that both groups match.
    static func sharedHosts(_ first: RuleGroupDomainMatcher, _ second: RuleGroupDomainMatcher) -> [String] {
        var seen = Set<String>()
        return (first.hosts + second.hosts).filter {
            seen.insert($0).inserted && first.matches($0) && second.matches($0)
        }
    }
}

/// Sites that used to match `from` and, after a reorder, match `to` first.
struct RuleOrderConflict: Equatable {
    let from: String
    let to: String
    let domains: [String]
}
