import Foundation

/// The one place that decides a policy group's emoji: the one its name starts
/// with, else one recognised from the name, else one for its kind. Names in
/// the app, names filled in for imported schemes, catalog groups and exported
/// icons all come from here, so they never disagree.
///
/// Recognition is deliberately narrow. English keywords match whole words
/// (CamelCase is split, so `AkamaiCloud` is "akamai cloud" and never iCloud),
/// Chinese keywords match whole phrases, and URLs are never consulted. Specific
/// entries come before broad ones. A name nothing recognises gets no emoji in
/// its name; only icons fall back to the group's kind.
enum PolicyGroupEmoji {
    /// The emoji a name starts with, if it starts with one.
    static func leading(in name: String) -> String? {
        guard let first = name.trimmingCharacters(in: .whitespacesAndNewlines).first,
              isEmoji(first) else { return nil }
        return String(first)
    }

    /// An emoji recognised from the words of a name: a service, then a region.
    /// Catalog list names pass `regions: false`: `ChinaCompanyIp` is a
    /// category of rules, not a place to fly a flag for.
    static func recognized(for name: String, regions: Bool = true) -> String? {
        let words = tokens(name)
        let lowered = name.lowercased()
        for entry in table where entry.matches(words: words, lowered: lowered) {
            return entry.emoji
        }
        if regions, let region = NodeRegionResolver.nameRegion(for: name) {
            return NodeRegionResolver.flagEmoji(for: region.code)
        }
        return nil
    }

    /// Always an emoji, for icons: the name's own, a recognised one, or the kind's.
    static func resolved(for name: String, kind: RuleSchemeGroup.Kind) -> String {
        leading(in: name) ?? recognized(for: name) ?? fallback(for: kind)
    }

    static func fallback(for kind: RuleSchemeGroup.Kind) -> String {
        switch kind {
        case .urlTest: "⚡️"
        case .fallback: "🔁"
        case .loadBalance: "⚖️"
        default: "🧩"
        }
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

        func matches(words nameWords: [String], lowered: String) -> Bool {
            if phrases.contains(where: lowered.contains) { return true }
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
                if lowerToUpper || acronymEnd {
                    words.append(current)
                    current = ""
                }
            }
            current.append(character)
        }
        if !current.isEmpty { words.append(current) }
        return words.map { $0.lowercased() }
    }

    /// Specific before broad. The emoji follow ACL4SSR's own where it has one.
    static let table: [Entry] = [
        // Routing roles
        Entry(emoji: "🎛️", words: ["manual", "manual select", "manual switch"], phrases: ["手动切换", "手动选择"]),
        Entry(emoji: "♻️", words: ["auto", "auto select", "url test", "automatic"], phrases: ["自动选择", "自动测速"]),
        Entry(emoji: "🍃", words: [], phrases: ["应用净化"]),
        Entry(emoji: "🛑", words: ["reject", "adblock", "ad block", "ads", "advertising", "advertisement"], phrases: ["广告拦截", "全球拦截", "拦截", "广告"]),
        Entry(emoji: "🐟", words: ["final", "match", "others", "fallback rule"], phrases: ["漏网之鱼", "兜底"]),
        Entry(emoji: "🌏", words: ["china media"], phrases: ["国内媒体"]),
        Entry(emoji: "🌍", words: ["global media", "streaming", "foreign media"], phrases: ["国外媒体", "流媒体"]),
        Entry(emoji: "🏠", words: ["lan", "local area network", "private network"], phrases: ["局域网", "内网"]),
        Entry(emoji: "🌐", words: ["dns"], phrases: ["域名解析"]),
        // Services, most specific first
        Entry(emoji: "📢", words: ["fcm", "google fcm"], phrases: ["谷歌fcm", "谷歌 fcm"]),
        Entry(emoji: "📹", words: ["youtube", "youtube music"], phrases: ["油管"]),
        Entry(emoji: "🎥", words: ["netflix"], phrases: ["奈飞", "网飞"]),
        Entry(emoji: "🧸", words: ["disney", "disney plus"], phrases: ["迪士尼"]),
        Entry(emoji: "🎬", words: ["hbo", "hbo max", "prime video", "amazon prime", "hulu"], phrases: []),
        Entry(emoji: "📺", words: ["bilibili", "bahamut", "abema", "abematv", "iqiyi", "youku", "tvb"], phrases: ["哔哩哔哩", "巴哈姆特", "爱奇艺", "优酷"]),
        Entry(emoji: "🎵", words: ["tiktok", "douyin"], phrases: ["抖音"]),
        Entry(emoji: "🎧", words: ["spotify", "apple music", "deezer", "tidal"], phrases: []),
        Entry(emoji: "🎶", words: ["netease music", "music", "kkbox"], phrases: ["网易音乐", "网易云音乐", "音乐"]),
        Entry(emoji: "📲", words: ["telegram"], phrases: ["电报"]),
        Entry(emoji: "💬", words: ["ai", "openai", "chatgpt", "claude", "anthropic", "copilot", "perplexity"], phrases: ["ai平台", "人工智能"]),
        Entry(emoji: "🔷", words: ["gemini", "bard"], phrases: []),
        Entry(emoji: "🐦", words: ["twitter"], phrases: ["推特"]),
        Entry(emoji: "♾️", words: ["facebook", "instagram", "meta", "whatsapp", "threads"], phrases: []),
        Entry(emoji: "🎙️", words: ["discord"], phrases: []),
        Entry(emoji: "🐙", words: ["github", "gitlab"], phrases: []),
        Entry(emoji: "☁️", words: ["cloudflare", "aws", "azure", "google cloud", "oracle cloud"], phrases: []),
        Entry(emoji: "💳", words: ["paypal", "stripe", "visa"], phrases: ["支付"]),
        Entry(emoji: "🪙", words: ["binance", "okx", "crypto", "coinbase"], phrases: ["加密货币"]),
        Entry(emoji: "📦", words: ["amazon", "ebay", "shopee"], phrases: ["购物"]),
        Entry(emoji: "Ⓜ️", words: ["microsoft", "bing", "onedrive", "office", "outlook", "office365", "windows"], phrases: ["微软"]),
        Entry(emoji: "🍎", words: ["apple", "icloud", "app store", "appstore", "testflight", "itunes"], phrases: ["苹果"]),
        Entry(emoji: "🔍", words: ["google", "gmail"], phrases: ["谷歌"]),
        Entry(emoji: "🎮", words: ["game", "games", "gaming", "steam", "epic", "playstation", "xbox", "nintendo", "blizzard"], phrases: ["游戏"]),
        Entry(emoji: "🎯", words: ["direct", "global direct", "domestic"], phrases: ["全球直连", "直连", "国内"]),
        Entry(emoji: "🚀", words: ["proxy", "proxy select", "node select", "node selection"], phrases: ["节点选择", "代理"]),
    ]
}
