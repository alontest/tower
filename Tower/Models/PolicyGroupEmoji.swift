import Foundation

/// The one place that decides a policy group's emoji. Names in the app,
/// names filled in for imported schemes, catalog groups and exported icons all
/// come from here, so they never disagree.
///
/// A group is read in layers, most reliable first:
/// 1. the emoji its name starts with;
/// 2. its name: services and categories, then a region, then what the group
///    does (automatic, failover, manual, direct…);
/// 3. the rule lists it carries (`Netflix.list` says more than `影视节点`);
/// 4. its members: only DIRECT, only REJECT, or node filters of one region;
/// 5. its kind.
///
/// The vocabulary comes from the group names of 8,362 public configs on
/// GitHub (2026-10-19): every spelling there, mapped onto one emoji per
/// meaning rather than each author's own pick. English keywords match whole
/// words (CamelCase is split, so `AkamaiCloud` is never iCloud), Chinese
/// keywords match whole phrases, and URLs are never consulted.
enum PolicyGroupEmoji {
    /// The emoji a name starts with, if it starts with one.
    static func leading(in name: String) -> String? {
        guard let first = name.trimmingCharacters(in: .whitespacesAndNewlines).first,
              isEmoji(first) else { return nil }
        return String(first)
    }

    /// An emoji recognised from the words of a name: a service or category,
    /// then a region, then the group's role. Catalog list names pass
    /// `regions: false`: `ChinaCompanyIp` is a category of rules, not a place
    /// to fly a flag for.
    static func recognized(for name: String, regions: Bool = true) -> String? {
        let words = tokens(name)
        let lowered = name.lowercased()
        if let entry = table.first(where: { $0.matches(words: words, lowered: lowered) }) { return entry.emoji }
        if regions, let flag = region(in: name, words: words, lowered: lowered) { return flag }
        return roles.first(where: { $0.matches(words: words, lowered: lowered) })?.emoji
    }

    /// The emoji for a group in its scheme, without the kind's fallback: the
    /// name, then the rule lists it carries, then its members.
    static func recognized(for group: RuleSchemeGroup, in scheme: RuleScheme) -> String? {
        recognized(for: group.name) ?? fromRules(of: group.name, in: scheme) ?? fromMembers(group.members)
    }

    /// Always an emoji, for icons: the name's own, a recognised one, or the kind's.
    static func resolved(for name: String, kind: RuleSchemeGroup.Kind) -> String {
        leading(in: name) ?? recognized(for: name) ?? fallback(for: kind)
    }

    static func resolved(for group: RuleSchemeGroup, in scheme: RuleScheme) -> String {
        leading(in: group.name) ?? recognized(for: group, in: scheme) ?? fallback(for: group.kind)
    }

    static func fallback(for kind: RuleSchemeGroup.Kind) -> String {
        switch kind {
        case .urlTest: "⚡️"
        case .fallback: "🔁"
        case .loadBalance: "⚖️"
        default: "🌐"
        }
    }

    // MARK: - Rules and members

    /// The service the group's rule lists agree on. Several streaming
    /// services together are a streaming group; otherwise the most common.
    static func fromRules(of groupName: String, in scheme: RuleScheme) -> String? {
        var counts: [String: Int] = [:]
        var order: [String] = []
        for ruleset in scheme.rulesets where ruleset.groupName == groupName {
            let emoji: String?
            switch ruleset.resource {
            case .remote(let url): emoji = ruleListEmoji(url.deletingPathExtension().lastPathComponent)
            case .inline(let line): emoji = inlineRuleEmoji(line)
            }
            guard let emoji else { continue }
            if counts[emoji] == nil { order.append(emoji) }
            counts[emoji, default: 0] += 1
        }
        guard !order.isEmpty else { return nil }
        if order.count > 1, order.allSatisfy(streaming.contains) { return "🎬" }
        return order.max { counts[$0]! < counts[$1]! || (counts[$0]! == counts[$1]! && order.firstIndex(of: $0)! > order.firstIndex(of: $1)!) }
    }

    /// `Netflix`, `ProxyGFWlist`, `ChinaDomain`: list names are services or
    /// broad categories, never places.
    static func ruleListEmoji(_ stem: String) -> String? {
        let words = tokens(stem)
        let lowered = stem.lowercased()
        if let entry = ruleLists.first(where: { $0.matches(words: words, lowered: lowered) }) { return entry.emoji }
        return recognized(for: stem, regions: false)
    }

    private static func inlineRuleEmoji(_ line: String) -> String? {
        let fields = line.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).uppercased() }
        switch fields.first {
        case "FINAL", "MATCH": return "🐟"
        case "GEOIP" where fields.count > 1 && fields[1] == "CN": return "🎯"
        case "GEOIP" where fields.count > 1 && ["LAN", "PRIVATE"].contains(fields[1]): return "🏠"
        default: return nil
        }
    }

    /// Only DIRECT is a direct group, only REJECT a blocking one, and node
    /// filters that all name one region are that region's group.
    static func fromMembers(_ members: [RuleSchemeGroupMember]) -> String? {
        guard !members.isEmpty else { return nil }
        var references: Set<String> = []
        var patterns: [String] = []
        for member in members {
            switch member {
            case .reference(let name): references.insert(name.uppercased())
            case .nodePattern(let pattern): patterns.append(pattern)
            }
        }
        if patterns.isEmpty {
            if references == ["DIRECT"] { return "🎯" }
            if !references.isEmpty, references.allSatisfy({ $0.hasPrefix("REJECT") }) { return "🛑" }
            return nil
        }
        guard references.isEmpty else { return nil }
        let codes = Set(patterns.compactMap { NodeRegionResolver.nameRegion(for: $0)?.code })
        guard codes.count == 1, let code = codes.first, patterns.allSatisfy({ $0 != ".*" }) else { return nil }
        return NodeRegionResolver.flagEmoji(for: code)
    }

    private static let streaming: Set<String> = ["🎥", "📹", "🧸", "🎬", "📺", "🍿", "🎵"]

    // MARK: - Regions

    /// Group names shorten places in ways node names do not (`加坡节点`), and
    /// name regions that are not countries.
    private static let regionAliases: [(phrase: String, code: String)] = [
        ("加坡", "SG"), ("欧洲", "EU"), ("欧盟", "EU"),
    ]

    private static func region(in name: String, words: [String], lowered: String) -> String? {
        if let code = regionAliases.first(where: { lowered.contains($0.phrase) })?.code
            ?? (words.contains { ["europe", "eu"].contains($0) } ? "EU" : nil) {
            return NodeRegionResolver.flagEmoji(for: code)
        }
        return NodeRegionResolver.nameRegion(for: name).map { NodeRegionResolver.flagEmoji(for: $0.code) }
    }

    static func isEmoji(_ character: Character) -> Bool {
        // ASCII digits, # and * are emoji-capable scalars, but ordinary text.
        guard !character.isASCII else { return false }
        return character.unicodeScalars.contains { $0.properties.isEmoji }
    }

    // MARK: - Recognition

    struct Entry {
        let emoji: String
        /// Whole-word English keywords; a space separates words that must follow each other.
        let words: [String]
        /// Chinese phrases, matched as written.
        let phrases: [String]
        /// Words too short or common to find inside a name (`X`, `Max`):
        /// they match only a name that is nothing else.
        var exact: [String] = []

        func matches(words nameWords: [String], lowered: String) -> Bool {
            if phrases.contains(where: lowered.contains) { return true }
            if !exact.isEmpty, exact.contains(nameWords.joined(separator: " ")),
               lowered.unicodeScalars.allSatisfy({ $0.isASCII || !$0.properties.isAlphabetic }) { return true }
            // CamelCase splits brands into pieces (YouTube → you, tube), so
            // a keyword also matches two or three neighbouring words joined.
            var spellings = Set(nameWords)
            for length in 2...3 where nameWords.count >= length {
                for start in 0...(nameWords.count - length) {
                    spellings.insert(nameWords[start..<start + length].joined())
                }
            }
            return words.contains { keyword in
                let parts = keyword.split(separator: " ").map(String.init)
                // `PrimeVideo` and `primevideo` are the same words written together.
                if spellings.contains(parts.joined()) { return true }
                guard parts.count > 1, parts.count <= nameWords.count else { return false }
                return (0...(nameWords.count - parts.count)).contains { start in
                    Array(nameWords[start..<start + parts.count]) == parts
                }
            }
        }
    }

    /// Lowercased words: split on anything that is not a letter or digit, and
    /// at CamelCase boundaries (`IPTVMainland` → iptv, mainland).
    static func tokens(_ name: String) -> [String] {
        var words: [String] = []
        var current = ""
        let characters = Array(name)
        for (index, character) in characters.enumerated() {
            guard character.isLetter || character.isNumber, character.isASCII else {
                if !current.isEmpty { words.append(current); current = "" }
                continue
            }
            if !current.isEmpty, let previous = current.last {
                let next = index + 1 < characters.count ? characters[index + 1] : nil
                let lowerToUpper = previous.isLowercase && character.isUppercase
                let acronymEnd = previous.isUppercase && character.isUppercase && (next?.isLowercase ?? false)
                let letterToDigit = previous.isLetter && character.isNumber
                if lowerToUpper || acronymEnd || letterToDigit {
                    words.append(current)
                    current = ""
                }
            }
            current.append(character)
        }
        if !current.isEmpty { words.append(current) }
        return words.map { $0.lowercased() }
    }

    /// Services and categories, specific before broad; read before regions.
    /// The emoji follow ACL4SSR's own where it has one.
    static let table: [Entry] = [
        Entry(emoji: "🍃", words: [], phrases: ["应用净化"]),
        Entry(emoji: "🛑", words: ["reject", "adblock", "ad block", "ads", "advertising", "advertisement", "blocklist"],
              phrases: ["广告拦截", "全球拦截", "拦截", "广告", "去广告"], exact: ["block"]),
        Entry(emoji: "🐟", words: ["final", "match", "fallback rule"], phrases: ["漏网之鱼", "兜底", "其他流量", "其它流量", "剩余流量"], exact: ["others"]),
        Entry(emoji: "🛡️", words: ["privacy", "tracking", "tracker", "antitracking"], phrases: ["隐私", "追踪", "跟踪", "泄漏", "泄露"]),
        Entry(emoji: "🌏", words: ["china media", "asia media"], phrases: ["国内媒体", "国内视频", "国内影视", "港台媒体", "日韩媒体", "港澳台媒体", "亚洲媒体"]),
        Entry(emoji: "🌍", words: ["global media", "streaming", "foreign media", "international media"],
              phrases: ["国外媒体", "国际媒体", "海外媒体", "流媒体"]),
        Entry(emoji: "🏠", words: ["lan", "local area network", "private network", "intranet"], phrases: ["局域网", "内网", "私有网络"]),
        Entry(emoji: "🌐", words: ["dns", "httpdns", "doh"], phrases: ["域名解析"]),
        Entry(emoji: "📶", words: ["speedtest", "speed test", "network test"], phrases: ["测速工具", "测速网站", "网络测试"]),
        Entry(emoji: "🔀", words: ["non standard port"], phrases: ["非标端口", "非标准端口"]),
        // Services, most specific first
        Entry(emoji: "📢", words: ["fcm", "google fcm"], phrases: ["谷歌fcm", "谷歌 fcm", "谷歌推送"]),
        Entry(emoji: "📹", words: ["youtube", "youtube music"], phrases: ["油管"]),
        Entry(emoji: "🎥", words: ["netflix"], phrases: ["奈飞", "网飞"]),
        Entry(emoji: "🧸", words: ["disney", "disney plus", "disneyplus"], phrases: ["迪士尼"]),
        Entry(emoji: "🎬", words: ["hbo", "hbo max", "prime video", "amazon prime", "hulu", "apple tv", "appletv", "paramount", "peacock"],
              phrases: ["亚马逊视频"], exact: ["max"]),
        Entry(emoji: "🍿", words: ["emby", "jellyfin", "plex"], phrases: []),
        Entry(emoji: "⚽", words: ["dazn", "espn"], phrases: []),
        Entry(emoji: "📺", words: ["bilibili", "bahamut", "abema", "abematv", "iqiyi", "youku", "tvb", "anime", "twitch", "niconico", "viu", "mytvsuper"],
              phrases: ["哔哩", "巴哈姆特", "爱奇艺", "优酷", "动漫", "番剧", "动画", "直播"]),
        Entry(emoji: "🎵", words: ["tiktok", "douyin", "bytedance"], phrases: ["抖音", "字节跳动", "抖快"]),
        Entry(emoji: "🎧", words: ["spotify", "apple music", "deezer", "tidal", "soundcloud", "qobuz"], phrases: []),
        Entry(emoji: "🎶", words: ["netease music", "music", "kkbox", "joox"], phrases: ["网易音乐", "网易云音乐", "音乐"]),
        Entry(emoji: "📲", words: ["telegram"], phrases: ["电报"]),
        Entry(emoji: "🤖", words: ["ai", "aigc", "openai", "chatgpt", "claude", "anthropic", "copilot", "perplexity", "grok", "deepseek", "midjourney"],
              phrases: ["ai平台", "ai 平台", "ai服务", "人工智能"]),
        Entry(emoji: "🔷", words: ["gemini", "bard"], phrases: []),
        Entry(emoji: "🐦", words: ["twitter"], phrases: ["推特"], exact: ["x", "twitter x"]),
        Entry(emoji: "♾️", words: ["facebook", "instagram", "meta", "whatsapp", "threads"], phrases: ["脸书"]),
        Entry(emoji: "📣", words: ["weibo"], phrases: ["微博"]),
        Entry(emoji: "🎙️", words: ["discord"], phrases: []),
        Entry(emoji: "👽", words: ["reddit"], phrases: []),
        Entry(emoji: "📕", words: ["xiaohongshu", "rednote"], phrases: ["小红书"]),
        Entry(emoji: "💬", words: ["wechat", "line", "signal", "kakaotalk", "messenger", "im"], phrases: ["微信", "即时通讯", "通讯", "聊天"]),
        Entry(emoji: "📞", words: ["talkatone", "skype", "zoom", "voip"], phrases: ["通话", "电话"]),
        Entry(emoji: "🐙", words: ["github", "gitlab"], phrases: []),
        Entry(emoji: "🐳", words: ["docker"], phrases: []),
        Entry(emoji: "📝", words: ["notion", "evernote", "obsidian"], phrases: []),
        Entry(emoji: "📱", words: ["xiaomi", "samsung"], phrases: ["小米", "三星"]),
        Entry(emoji: "🔞", words: ["pornhub", "ehentai", "nsfw"], phrases: []),
        Entry(emoji: "🎨", words: ["pixiv", "adobe", "figma", "canva"], phrases: []),
        Entry(emoji: "💳", words: ["paypal", "stripe", "visa", "wise"], phrases: ["支付"]),
        Entry(emoji: "🪙", words: ["binance", "okx", "crypto", "coinbase", "bybit"], phrases: ["加密货币", "货币", "币安"]),
        Entry(emoji: "🛒", words: ["amazon", "ebay", "shopee", "shopping", "shop"], phrases: ["购物", "电商", "亚马逊", "淘宝", "京东", "阿里巴巴"]),
        Entry(emoji: "☁️", words: ["google cloud", "azure"], phrases: []),
        Entry(emoji: "Ⓜ️", words: ["microsoft", "bing", "onedrive", "office", "outlook", "office365", "windows", "teams"], phrases: ["微软"]),
        Entry(emoji: "🍎", words: ["apple", "icloud", "app store", "appstore", "testflight", "itunes"], phrases: ["苹果"]),
        Entry(emoji: "🔍", words: ["google", "gmail"], phrases: ["谷歌"]),
        // After the companies whose own drives say more (`微软云盘`).
        Entry(emoji: "☁️", words: ["cloudflare", "aws", "azure", "google cloud", "oracle cloud", "pikpak", "dropbox", "mega"], phrases: ["网盘", "云盘"]),
        Entry(emoji: "🎮", words: ["game", "games", "gaming", "steam", "epic", "playstation", "xbox", "nintendo", "blizzard", "videogame"], phrases: ["游戏"]),
        // Categories, after every service that names one
        Entry(emoji: "🎓", words: ["scholar", "academic", "education"], phrases: ["学术", "教育", "论文"]),
        Entry(emoji: "📰", words: ["news"], phrases: ["新闻", "资讯"]),
        Entry(emoji: "📧", words: ["mail", "email"], phrases: ["邮件", "邮箱"]),
        Entry(emoji: "🏦", words: ["bank", "banking", "finance"], phrases: ["银行", "金融"]),
        Entry(emoji: "⚽", words: ["sport", "sports"], phrases: ["体育"]),
        Entry(emoji: "👥", words: ["social"], phrases: ["社交"]),
        Entry(emoji: "📥", words: ["download", "downloads", "p2p", "bt", "torrent"], phrases: ["下载", "pt站"]),
        Entry(emoji: "🎬", words: ["video", "videos", "movie", "movies", "film", "films"], phrases: ["影视", "视频", "电影", "剧集", "追剧"]),
        // Before regions: `国内` and `Mainland` are not a Chinese node group.
        Entry(emoji: "🎯", words: ["direct", "global direct", "domestic"],
              phrases: ["全球直连", "直连", "直接连接", "国内", "大陆"], exact: ["mainland"]),
    ]

    /// What the group does, read after regions so `香港故转` and `香港-自动`
    /// stay Hong Kong. Node qualities come before the generic proxy words.
    static let roles: [Entry] = [
        Entry(emoji: "🔁", words: ["fallback", "failover", "backup"], phrases: ["故障转移", "故障切换", "故转", "备用", "容灾"]),
        Entry(emoji: "⚖️", words: ["load balance", "loadbalance", "balance", "round robin"], phrases: ["负载均衡", "均衡", "轮询"]),
        Entry(emoji: "♻️", words: ["auto", "auto select", "url test", "automatic", "best", "lowest latency"],
              phrases: ["自动", "优选", "延迟最低", "最低延迟", "低延迟"]),
        Entry(emoji: "📶", words: [], phrases: ["测速"]),
        Entry(emoji: "🎛️", words: ["manual", "manual select", "manual switch"],
              phrases: ["手动", "手选", "自选", "策略选择", "选择地区"], exact: ["select", "selector"]),
        Entry(emoji: "🏡", words: ["residential", "home broadband"], phrases: ["家宽", "家庭宽带", "原生"]),
        Entry(emoji: "💰", words: ["cheap", "budget"], phrases: ["便宜", "低价", "低倍率", "省流"]),
        Entry(emoji: "⭐", words: ["premium", "vip", "iplc", "iepl"], phrases: ["高级", "优质", "精品", "高速", "专线"]),
        Entry(emoji: "🛠️", words: ["self hosted", "selfhosted"], phrases: ["自建"]),
        Entry(emoji: "🌍", words: ["foreign", "overseas", "international", "outside"], phrases: ["国外", "国际", "海外", "境外"]),
        Entry(emoji: "🗺️", words: ["other", "others", "other regions"], phrases: ["其他", "其它"]),
        Entry(emoji: "🌐", words: ["all", "proxies"], phrases: ["全部", "所有"]),
        Entry(emoji: "🚀", words: ["proxy", "proxy select", "node select", "node selection", "nodes", "node", "default"],
              phrases: ["节点选择", "代理", "节点", "加速", "默认"]),
        Entry(emoji: "🌐", words: ["global"], phrases: ["全球"]),
    ]

    /// Rule list names Tower meets that are neither services nor roles above.
    static let ruleLists: [Entry] = [
        Entry(emoji: "🎯", words: ["china domain", "china ip", "china company", "china media", "local area network"],
              phrases: [], exact: ["china", "cn", "chinadomain", "chinaip", "chinamax", "direct", "gfw direct"]),
        Entry(emoji: "🚀", words: ["gfw", "gfwlist", "proxy gfwlist", "proxy lite", "proxy media", "global"], phrases: [],
              exact: ["proxy", "proxylite"]),
        Entry(emoji: "🛑", words: ["ban ad", "ban program ad", "ban easylist", "reject"], phrases: []),
    ]
}
