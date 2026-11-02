import Foundation

enum ProxyClient: String, CaseIterable, Codable, Identifiable, Sendable {
    case automatic
    case clashVerge
    case flClash
    case shadowrocket
    case singBox
    case clashX
    case surge
    case other

    var id: String { rawValue }

    var title: String {
        switch self {
        case .automatic: "自动识别"
        case .clashVerge: "Clash Verge / Mihomo"
        case .flClash: "FlClash"
        case .shadowrocket: "Shadowrocket"
        case .singBox: "sing-box"
        case .clashX: "ClashX"
        case .surge: "Surge"
        case .other: "其他 / 手动"
        }
    }

    var englishTitle: String {
        switch self {
        case .automatic: "Automatic"
        case .clashVerge: "Clash Verge / Mihomo"
        case .flClash: "FlClash"
        case .shadowrocket: "Shadowrocket"
        case .singBox: "sing-box"
        case .clashX: "ClashX"
        case .surge: "Surge"
        case .other: "Other / manual"
        }
    }
}

struct MonitorSettings: Codable, Equatable, Sendable {
    var proxyClient: ProxyClient = .automatic
    var expectedCountryCode = ""
    var expectedTimeZoneID = ""
    var expectedLocaleIdentifier = ""
    var dnsTestDomain = ""
    var fakeIPCIDR = "198.18.0.0/16"
    var routeDomains: [String] = []
    var reachabilityURLs: [String] = ["https://www.cloudflare.com"]
    var intervalSeconds = 60
}
