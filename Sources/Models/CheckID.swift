import Foundation

enum CheckID: String, CaseIterable, Codable, Identifiable, Sendable {
    case proxyKernel
    case tunInterface
    case egressIP
    case ipConsistency
    case timeZone
    case locale
    case deviceRegion
    case locationProximity
    case ipv6
    case dnsTunnel
    case webRTC
    case routeRules
    case asn
    case ipReputation
    case reachability
    case mainlandEgress
    case dualStack
    case dnsLeak
    case routeProfile
    case webkitProfile

    var id: String { rawValue }

    var title: String {
        switch self {
        case .proxyKernel: "代理进程"
        case .tunInterface: "TUN 网卡"
        case .egressIP: "出口 IP"
        case .ipConsistency: "IP 一致性"
        case .timeZone: "时区"
        case .locale: "系统地区与语言"
        case .deviceRegion: "Mac 销售地区型号"
        case .locationProximity: "设备位置与 IP 位置"
        case .ipv6: "IPv6"
        case .dnsTunnel: "DNS 隧道"
        case .webRTC: "WebRTC"
        case .routeRules: "路由规则"
        case .asn: "IP 网络类型与运营商"
        case .ipReputation: "IP 信誉风险"
        case .reachability: "站点可达性"
        case .mainlandEgress: "大陆出口归属"
        case .dualStack: "双栈出口"
        case .dnsLeak: "DNS 解析器路径"
        case .routeProfile: "路由画像"
        case .webkitProfile: "WebKit 环境"
        }
    }

    var subtitle: String {
        switch self {
        case .proxyKernel: "检测到代理进程时计为风险信号，并结合出口与路由判断"
        case .tunInterface: "检测到活动隧道接口时计为风险信号"
        case .egressIP: "获取公网出口地址和地区"
        case .ipConsistency: "与本机最近 48 小时的出口记录比较"
        case .timeZone: "比较系统时区与出口 IP 归属地时区"
        case .locale: "比较系统语言地区标记与出口 IP 地区"
        case .deviceRegion: "读取 Mac 型号地区代码；只表示销售地区倾向，不代表当前位置"
        case .locationProximity: "手动授权后比较设备近似位置与出口 IP 估算位置"
        case .ipv6: "检查公网 IPv6 出口及其归属"
        case .dnsTunnel: "检查指定域名是否使用预期解析"
        case .webRTC: "通过 STUN 检查 UDP 映射地址"
        case .routeRules: "检查指定域名的代理路由表现"
        case .asn: "识别出口网络类型、运营商和 ASN"
        case .ipReputation: "显示第三方 IP 风险分与代理、托管和滥用标记"
        case .reachability: "请求设置中的 HTTPS 测试站点"
        case .mainlandEgress: "比较多个 GeoIP 来源对公网出口国家 / 地区的标记"
        case .dualStack: "分别探测 IPv4 与 IPv6 出口，并比较地区归属"
        case .dnsLeak: "用随机域名观察实际到达权威服务器的 DNS 解析器"
        case .routeProfile: "读取 macOS DNS、公共目标路由接口和系统代理配置"
        case .webkitProfile: "比较本应用 WebKit 的语言、时区和 ICE 地址"
        }
    }
}
