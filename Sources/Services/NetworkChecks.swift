import Darwin
import Foundation
import Network

struct NetworkSnapshot: Sendable {
    var publicIP: String?
    var countryCode: String?
    var geoInfo: IPInfo?
    var ipv4Address: String?
    var ipv6Address: String?
    var geoObservationsByIP: [String: [GeoProviderObservation]]
    var ipRiskByIP: [String: IPRiskObservation]
    var error: String?
    var errorEnglish: String? = nil
}

struct GeoProviderObservation: Sendable, Equatable {
    var source: String
    var countryCode: String?
    var timeZone: String?
    var asn: String?
    var organization: String?
    var available: Bool
}

struct IPInfo: Decodable, Sendable {
    var ip: String?
    var country: String?
    var timezone: String?
    var org: String?
    var loc: String?
}

struct GeoCoordinate: Sendable, Equatable {
    let latitude: Double
    let longitude: Double

    static func validated(latitude: Double?, longitude: Double?) -> GeoCoordinate? {
        guard let latitude, let longitude,
              latitude.isFinite, longitude.isFinite,
              (-90...90).contains(latitude), (-180...180).contains(longitude) else { return nil }
        return GeoCoordinate(latitude: latitude, longitude: longitude)
    }

    func distance(to other: GeoCoordinate) -> Double {
        let radians = Double.pi / 180
        let latitude1 = latitude * radians
        let latitude2 = other.latitude * radians
        let latitudeDelta = (other.latitude - latitude) * radians
        let longitudeDelta = (other.longitude - longitude) * radians
        let a = sin(latitudeDelta / 2) * sin(latitudeDelta / 2)
            + cos(latitude1) * cos(latitude2) * sin(longitudeDelta / 2) * sin(longitudeDelta / 2)
        return 6_371 * 2 * atan2(sqrt(a), sqrt(max(1 - a, 0)))
    }
}

private struct IPAPIGeoInfo: Decodable, Sendable {
    var ip: String?
    var countryCode: String?
    var timezone: String?
    var asn: String?
    var org: String?
    var latitude: Double?
    var longitude: Double?

    enum CodingKeys: String, CodingKey {
        case ip
        case countryCode = "country_code"
        case timezone
        case asn
        case org
        case latitude
        case longitude
    }
}

struct IPRiskReport: Decodable, Sendable {
    var ip: String?
    var risk: Int?
    var network: Network?
    var geolocation: Geo?
    var time: Time?
    var flags: Flags?
    var extra: Extra?
    var lastCheck: Int?

    enum CodingKeys: String, CodingKey {
        case ip, risk, time, flags, extra
        case network = "net"
        case geolocation = "geo"
        case lastCheck = "last_check"
    }

    struct Network: Decodable, Sendable {
        var isp: String?
        var organization: String?
        var asn: String?
        var type: String?

        enum CodingKeys: String, CodingKey {
            case isp, asn, type
            case organization = "org"
        }
    }

    struct Geo: Decodable, Sendable {
        var countryCode: String?

        enum CodingKeys: String, CodingKey {
            case countryCode = "country_code"
        }
    }

    struct Time: Decodable, Sendable {
        var timezone: String?
    }

    struct Flags: Decodable, Sendable {
        var proxy: Bool?
        var vpn: Bool?
        var tor: Bool?
        var hosting: Bool?
        var fraud: Bool?
        var scam: Bool?
        var abuse: Bool?
        var mobile: Bool?
    }

    struct Extra: Decodable, Sendable {
        var blocklist: Bool?
    }
}

struct IPRiskObservation: Sendable {
    var report: IPRiskReport
    var fetchedAt: Date
}

private struct IPRiskResponse: Decodable, Sendable {
    var ok: Bool
    var data: IPRiskReport?
    var error: String?
}

actor NetworkChecks {
    private struct CacheEntry: Sendable {
        var info: IPInfo?
        var ipapi: IPAPIGeoInfo?
        var expiresAt: Date
    }

    private struct IPRiskCacheEntry: Sendable {
        var observation: IPRiskObservation?
        var expiresAt: Date
    }

    private struct CountryEvidence {
        var countryCode: String?
        var detail: String
        var englishDetail: String
        var reason: String
        var englishReason: String
    }

    private struct HTTPResult {
        var data: Data
        var statusCode: Int
    }

    private let session: URLSession
    private var geoCache: [String: CacheEntry] = [:]
    private var ipRiskCache: [String: IPRiskCacheEntry] = [:]
    private var latestNativeWebRTCResult: CheckResult?

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 10
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration, delegate: NoRedirectDelegate.shared, delegateQueue: nil)
    }

    func collectSnapshot() async -> NetworkSnapshot {
        let trace = await fetchCloudflareTrace()
        let traceIP = trace?.ip.flatMap { Self.isIPAddress($0) ? Self.canonicalIP($0) : nil }
        var fallbackInfo: IPInfo?
        if traceIP == nil, let fallbackURL = URL(string: "https://ipinfo.io/json") {
            fallbackInfo = await fetchIPInfo(at: fallbackURL)
        }
        let fallbackIP = fallbackInfo?.ip.flatMap { Self.isIPAddress($0) ? Self.canonicalIP($0) : nil }

        async let ipv4Result = fetchIPv4Address()
        async let ipv6Result = fetchIPv6Address()
        let (ipv4, ipv6) = await (ipv4Result, ipv6Result)
        let publicIP = traceIP ?? fallbackIP ?? ipv4 ?? ipv6
        let addresses = Set([publicIP, ipv4, ipv6].compactMap { $0 }).sorted()

        var lookupEntries: [(String, CacheEntry)] = []
        await withTaskGroup(of: (String, CacheEntry).self) { group in
            for address in addresses {
                let override = address == fallbackIP ? fallbackInfo : nil
                group.addTask {
                    (address, await self.geoInfo(for: address, fallbackInfo: override))
                }
            }
            for await entry in group {
                lookupEntries.append(entry)
            }
        }

        let lookups = Dictionary(uniqueKeysWithValues: lookupEntries)
        var riskLookupEntries: [(String, IPRiskObservation)] = []
        await withTaskGroup(of: (String, IPRiskObservation?).self) { group in
            for address in addresses {
                group.addTask {
                    (address, await self.ipRiskReport(for: address))
                }
            }
            for await entry in group {
                if let report = entry.1 {
                    riskLookupEntries.append((entry.0, report))
                }
            }
        }
        let riskReports = Dictionary(uniqueKeysWithValues: riskLookupEntries)

        var observations: [String: [GeoProviderObservation]] = [:]
        for address in addresses {
            let entry = lookups[address]
            let risk = riskReports[address]?.report
            let infoCountry = entry?.info?.country?.uppercased()
            let ipapiCountry = entry?.ipapi?.countryCode?.uppercased()
            var providers: [GeoProviderObservation] = []
            if address == traceIP, let trace {
                let country = trace.countryCode?.uppercased()
                providers.append(GeoProviderObservation(
                    source: "Cloudflare Trace",
                    countryCode: country.flatMap { Self.isCountryCode($0) ? $0 : nil },
                    timeZone: nil,
                    asn: nil,
                    organization: nil,
                    available: true
                ))
            }
            providers.append(GeoProviderObservation(
                source: "ipinfo.io",
                countryCode: infoCountry.flatMap { Self.isCountryCode($0) ? $0 : nil },
                timeZone: entry?.info?.timezone,
                asn: nil,
                organization: entry?.info?.org,
                available: entry?.info != nil
            ))
            providers.append(GeoProviderObservation(
                source: "ipapi.co",
                countryCode: ipapiCountry.flatMap { Self.isCountryCode($0) ? $0 : nil },
                timeZone: entry?.ipapi?.timezone,
                asn: entry?.ipapi?.asn,
                organization: entry?.ipapi?.org,
                available: entry?.ipapi != nil
            ))
            if let risk {
                let riskCountry = risk.geolocation?.countryCode?.uppercased()
                providers.append(GeoProviderObservation(
                    source: "IPFastcheck",
                    countryCode: riskCountry.flatMap { Self.isCountryCode($0) ? $0 : nil },
                    timeZone: risk.time?.timezone,
                    asn: risk.network?.asn,
                    organization: risk.network?.isp ?? risk.network?.organization,
                    available: true
                ))
            }
            observations[address] = providers
        }

        let primaryLookup = publicIP.flatMap { lookups[$0] }
        let primaryInfo = primaryLookup?.info ?? fallbackInfo
        let traceCountry = publicIP == traceIP ? trace?.countryCode?.uppercased() : nil
        let riskCountry = publicIP.flatMap { riskReports[$0]?.report.geolocation?.countryCode?.uppercased() }
            .flatMap { Self.isCountryCode($0) ? $0 : nil }
        let country = traceCountry.flatMap(Self.isCountryCode) == true
            ? traceCountry
            : (primaryInfo?.country?.uppercased() ?? riskCountry)

        guard let publicIP else {
            return NetworkSnapshot(
                publicIP: nil,
                countryCode: nil,
                geoInfo: nil,
                ipv4Address: ipv4,
                ipv6Address: ipv6,
                geoObservationsByIP: observations,
                ipRiskByIP: riskReports,
                error: "出口信息服务无响应",
                errorEnglish: "The egress information service did not respond."
            )
        }

        return NetworkSnapshot(
            publicIP: publicIP,
            countryCode: country,
            geoInfo: primaryInfo,
            ipv4Address: ipv4,
            ipv6Address: ipv6,
            geoObservationsByIP: observations,
            ipRiskByIP: riskReports,
            error: nil
        )
    }

    func compareDeviceLocation(_ device: DeviceLocationSample) async -> CheckResult {
        let age = abs(Date.now.timeIntervalSince(device.timestamp))
        guard age <= 120, device.horizontalAccuracy >= 0, device.horizontalAccuracy <= 100_000 else {
            return result(.locationProximity, .unknown,
                          "macOS 返回的位置过旧或精度不足，无法可靠比较。",
                          english: "The macOS location is stale or too imprecise for a useful comparison.")
        }

        let trace = await fetchCloudflareTrace()
        let traceIP = trace?.ip.flatMap { Self.isIPAddress($0) ? Self.canonicalIP($0) : nil }
        var fallbackInfo: IPInfo?
        if traceIP == nil, let fallbackURL = URL(string: "https://ipinfo.io/json") {
            fallbackInfo = await fetchIPInfo(at: fallbackURL)
        }
        let fallbackIP = fallbackInfo?.ip.flatMap { Self.isIPAddress($0) ? Self.canonicalIP($0) : nil }
        var ip = traceIP ?? fallbackIP
        if ip == nil {
            async let ipv4 = fetchIPv4Address()
            async let ipv6 = fetchIPv6Address()
            let (address4, address6) = await (ipv4, ipv6)
            ip = address4 ?? address6
        }
        guard let ip else {
            return result(.locationProximity, .unknown,
                          "未能取得公网出口 IP，无法与 IP 位置比较。",
                          english: "Could not obtain a public egress IP to compare with its mapped location.")
        }

        let lookup = await geoInfo(for: ip, fallbackInfo: ip == fallbackIP ? fallbackInfo : nil)
        var geoPoints: [(source: String, point: GeoCoordinate)] = []
        if let point = Self.ipInfoCoordinate(lookup.info) {
            geoPoints.append(("ipinfo.io", point))
        }
        if let point = Self.ipAPICoordinate(lookup.ipapi) {
            geoPoints.append(("ipapi.co", point))
        }
        guard let first = geoPoints.first else {
            return result(.locationProximity, .unknown,
                          "GeoIP 来源没有返回可用坐标；这不代表检测通过或发现泄漏。",
                          english: "No usable coordinates were returned by the GeoIP providers; this is neither a pass nor evidence of a leak.")
        }

        let estimate: GeoCoordinate
        if geoPoints.count > 1 {
            let disagreement = first.point.distance(to: geoPoints[1].point)
            if disagreement > 300 {
                let rounded = Int((disagreement / 50).rounded()) * 50
                return result(.locationProximity, .unknown,
                              "ipinfo.io 与 ipapi.co 的 IP 定位点相差约 \(rounded) km，来源不一致，无法可靠比较。",
                              english: "The ipinfo.io and ipapi.co IP-location points differ by about \(rounded) km, so the sources do not agree well enough to compare reliably.")
            }
            estimate = GeoCoordinate(
                latitude: (first.point.latitude + geoPoints[1].point.latitude) / 2,
                longitude: (first.point.longitude + geoPoints[1].point.longitude) / 2
            )
        } else {
            estimate = first.point
        }

        let distance = device.coordinate.distance(to: estimate)
        let roundedDistance = Int((distance / 50).rounded()) * 50
        let sourceDetail = geoPoints.count > 1
            ? "两个 GeoIP 来源的估算位置接近"
            : "仅有 \(first.source) 一个 GeoIP 坐标来源，参考性较低"
        let englishSourceDetail = geoPoints.count > 1
            ? "the two GeoIP estimates are close"
            : "only one GeoIP coordinate source (\(first.source)) is available, so confidence is lower"
        let caveat = "设备位置和 IP 位置均为估算；距离较远不等于已确认泄漏。"
        let englishCaveat = "Both device and IP locations are estimates; a large distance does not confirm a leak."
        let chineseDetail = "与 \(ip) 的 IP 估算位置相差约 \(roundedDistance) km；\(sourceDetail)。\(caveat)"
        let englishDetail = "About \(roundedDistance) km from the IP-mapped location for \(ip); \(englishSourceDetail). \(englishCaveat)"

        if distance <= 300 {
            return result(.locationProximity, .pass, "位置大致接近；" + chineseDetail, english: "The locations are roughly near each other; " + englishDetail)
        }
        if distance > 1_000 {
            return result(.locationProximity, .warning, "位置差距较大，建议复核出口或代理路径；" + chineseDetail, english: "The locations differ substantially; review the egress or proxy path. " + englishDetail)
        }
        return result(.locationProximity, .unknown, "距离处于无法定性的范围；" + chineseDetail, english: "The distance is inconclusive. " + englishDetail)
    }

    func run(_ id: CheckID, settings: MonitorSettings, history: HistoryStore, snapshot: NetworkSnapshot) async -> CheckResult {
        switch id {
        case .egressIP:
            guard let ip = snapshot.publicIP else {
                return result(id, .unknown, snapshot.error ?? "未获取到公网出口 IP", english: snapshot.errorEnglish ?? "Could not obtain a public egress IP.")
            }
            let evidence = countryEvidence(for: ip, snapshot: snapshot)
            let country = evidence.countryCode ?? snapshot.countryCode ?? "地区未知"
            return result(id, .pass, "\(ip) · \(country) · \(evidence.detail)", english: "\(ip) · \(country) · \(evidence.englishDetail)")
        case .ipConsistency:
            return await ipConsistency(snapshot: snapshot, history: history)
        case .timeZone:
            return timeZone(snapshot: snapshot, expected: settings.expectedTimeZoneID)
        case .locale:
            return locale(snapshot: snapshot, settings: settings)
        case .ipv6:
            return ipv6(snapshot: snapshot, settings: settings)
        case .dnsTunnel:
            return await dnsTunnel(settings: settings)
        case .webRTC:
            let check = await webRTC(snapshot: snapshot)
            latestNativeWebRTCResult = check
            return check
        case .routeRules:
            return await routeRules(settings: settings)
        case .mainlandEgress:
            return mainlandEgress(snapshot: snapshot)
        case .dualStack:
            return dualStack(snapshot: snapshot, expectedCountry: settings.expectedCountryCode)
        case .asn:
            return ipNetworkProfile(snapshot: snapshot)
        case .ipReputation:
            return ipReputation(snapshot: snapshot)
        case .reachability:
            return await reachability(urlStrings: settings.reachabilityURLs)
        case .dnsLeak:
            return await DNSLeakProbe.run()
        case .webkitProfile:
            return await webkitProfile(snapshot: snapshot, settings: settings)
        case .routeProfile:
            return await SystemChecks.run(id, settings: settings)
        case .deviceRegion:
            return await SystemChecks.run(id, settings: settings)
        case .locationProximity:
            return result(id, .unknown, "请使用本项目的专用按钮，在你主动授权后进行位置比较。", english: "Use this check's dedicated button to compare locations after you explicitly authorize it.")
        case .proxyKernel, .tunInterface:
            return await SystemChecks.run(id, settings: settings)
        }
    }

    private static func ipInfoCoordinate(_ info: IPInfo?) -> GeoCoordinate? {
        guard let parts = info?.loc?.split(separator: ","), parts.count == 2 else { return nil }
        return GeoCoordinate.validated(latitude: Double(parts[0]), longitude: Double(parts[1]))
    }

    private static func ipAPICoordinate(_ info: IPAPIGeoInfo?) -> GeoCoordinate? {
        GeoCoordinate.validated(latitude: info?.latitude, longitude: info?.longitude)
    }

    private func riskAddressEntries(snapshot: NetworkSnapshot) -> [(label: String, ip: String)] {
        var entries: [(label: String, ip: String)] = []
        if let ipv4 = snapshot.ipv4Address { entries.append(("IPv4", ipv4)) }
        if let ipv6 = snapshot.ipv6Address { entries.append(("IPv6", ipv6)) }
        if let publicIP = snapshot.publicIP, !entries.contains(where: { $0.ip == publicIP }) {
            entries.insert(("公网出口", publicIP), at: 0)
        }
        return entries
    }

    private func ipNetworkProfile(snapshot: NetworkSnapshot) -> CheckResult {
        let addresses = riskAddressEntries(snapshot: snapshot)
        guard !addresses.isEmpty else {
            return result(.asn, .unknown, snapshot.error ?? "没有可用的公网出口 IP", english: snapshot.errorEnglish ?? "No public egress IP is available.")
        }

        var details: [String] = []
        var englishDetails: [String] = []
        var hasDataCenter = false
        var allTypesKnown = true

        for (label, ip) in addresses {
            guard let observation = snapshot.ipRiskByIP[ip] else {
                details.append("\(label)：\(ip)；第三方网络类型资料暂不可用")
                englishDetails.append("\(label): \(ip); third-party network profile is unavailable")
                allTypesKnown = false
                continue
            }

            let report = observation.report
            let rawType = report.network?.type?.lowercased()
            let type = Self.networkTypeLabel(report.network?.type)
            var parts = ["\(label)：\(ip)", "网络类型：\(type.chinese)"]
            var englishParts = ["\(label): \(ip)", "Network type: \(type.english)"]
            if let isp = report.network?.isp?.trimmingCharacters(in: .whitespacesAndNewlines), !isp.isEmpty {
                parts.append("运营商：\(isp)")
                englishParts.append("ISP: \(isp)")
            }
            if let organization = report.network?.organization?.trimmingCharacters(in: .whitespacesAndNewlines),
               !organization.isEmpty, organization != report.network?.isp {
                parts.append("组织：\(organization)")
                englishParts.append("Organization: \(organization)")
            }
            if let asn = report.network?.asn, !asn.isEmpty {
                parts.append("ASN：\(asn)")
                englishParts.append("ASN: \(asn)")
            }
            details.append(parts.joined(separator: "；"))
            englishDetails.append(englishParts.joined(separator: "; "))

            switch rawType {
            case "residential", "mobile": break
            case "datacenter": hasDataCenter = true
            default: allTypesKnown = false
            }
        }

        details.append("网络类型是第三方归类，不能单独证明实际接入方式")
        englishDetails.append("Network type is a third-party classification, not proof of the actual access method")
        let status: CheckStatus = hasDataCenter ? .warning : (allTypesKnown ? .pass : .unknown)
        return result(.asn, status, details.joined(separator: "；"), english: englishDetails.joined(separator: "; "))
    }

    private func ipReputation(snapshot: NetworkSnapshot) -> CheckResult {
        let addresses = riskAddressEntries(snapshot: snapshot)
        guard !addresses.isEmpty else {
            return result(.ipReputation, .unknown, snapshot.error ?? "没有可用的公网出口 IP", english: snapshot.errorEnglish ?? "No public egress IP is available.")
        }

        var details: [String] = []
        var englishDetails: [String] = []
        var hasReport = false
        var hasIncompleteData = false
        var hasCaution = false
        var hasHighRisk = false

        for (label, ip) in addresses {
            guard let observation = snapshot.ipRiskByIP[ip] else {
                details.append("\(label)：\(ip)；第三方 IP 信誉资料暂不可用")
                englishDetails.append("\(label): \(ip); third-party IP reputation data is unavailable")
                hasIncompleteData = true
                continue
            }

            let report = observation.report
            guard let score = report.risk, (0...100).contains(score) else {
                details.append("\(label)：\(ip)；服务未返回有效风险分")
                englishDetails.append("\(label): \(ip); the provider returned no valid risk score")
                hasIncompleteData = true
                continue
            }

            hasReport = true
            let scoreLabel: String
            let englishScoreLabel: String
            switch score {
            case 0..<35:
                scoreLabel = "低"
                englishScoreLabel = "low"
            case 35..<70:
                scoreLabel = "需留意"
                englishScoreLabel = "caution"
            default:
                scoreLabel = "高"
                englishScoreLabel = "high"
            }

            let flags = report.flags
            let flagPairs: [(Bool?, String, String)] = [
                (flags?.proxy, "服务方标记为已知开放代理", "provider flagged a known open proxy"),
                (flags?.vpn, "服务方标记为已知 VPN 出口", "provider flagged a known VPN exit node"),
                (flags?.tor, "服务方标记为 Tor 出口节点", "provider flagged a Tor exit node"),
                (flags?.hosting, "服务方标记为数据中心 / 托管网络", "provider flagged a data center / hosting network"),
                (flags?.fraud, "服务方标记欺诈信号", "provider flagged a fraud signal"),
                (flags?.scam, "服务方标记诈骗风险", "provider flagged a scam risk"),
                (flags?.abuse, "服务方标记近期滥用活动", "provider flagged recent abuse activity"),
                (report.extra?.blocklist, "服务方标记出现在封禁清单", "provider flagged the IP on a blocklist"),
            ]
            var riskFlags = flagPairs.filter { $0.0 == true }.map { $0.1 }
            var englishRiskFlags = flagPairs.filter { $0.0 == true }.map { $0.2 }
            if riskFlags.isEmpty {
                let flagsAvailable = flagPairs.contains { $0.0 != nil }
                riskFlags = [flagsAvailable ? "本次未返回阳性风险标记" : "服务未提供风险标记"]
                englishRiskFlags = [flagsAvailable ? "No positive risk flags were returned" : "The provider did not return risk flags"]
            }

            let networkType = Self.networkTypeLabel(report.network?.type)
            let type = report.network?.type == nil ? "未知" : networkType.chinese
            let englishType = report.network?.type == nil ? "unknown" : networkType.english
            var parts = ["\(label)：\(ip)", "IP 风险分：\(score)/100（\(scoreLabel)）", "网络类型：\(type)", "标记：\(riskFlags.joined(separator: "、"))"]
            var englishParts = ["\(label): \(ip)", "IP risk score: \(score)/100 (\(englishScoreLabel))", "Network type: \(englishType)", "Flags: \(englishRiskFlags.joined(separator: ", "))"]
            if let isp = report.network?.isp, !isp.isEmpty {
                parts.append("运营商：\(isp)")
                englishParts.append("ISP: \(isp)")
            }
            if let asn = report.network?.asn, !asn.isEmpty {
                parts.append("ASN：\(asn)")
                englishParts.append("ASN: \(asn)")
            }
            if let lastCheck = report.lastCheck, lastCheck > 0 {
                let date = Self.utcDateString(lastCheck)
                parts.append("服务最近记录：\(date) UTC")
                englishParts.append("Provider last record: \(date) UTC")
            }
            let fetchedAt = Self.utcDateTimeString(observation.fetchedAt)
            parts.append("本机取得资料时间：\(fetchedAt)")
            englishParts.append("Retrieved locally: \(fetchedAt)")
            details.append(parts.joined(separator: "；"))
            englishDetails.append(englishParts.joined(separator: "; "))

            let highRiskFlag = flags?.proxy == true
                || flags?.vpn == true
                || flags?.tor == true
                || flags?.hosting == true
                || flags?.fraud == true
                || flags?.abuse == true
                || report.extra?.blocklist == true
            if score >= 70 || highRiskFlag {
                hasHighRisk = true
            } else if score >= 35 || flags?.scam == true {
                hasCaution = true
            }
        }

        details.append("来源：IPfastcheck；分段：0–34 低、35–69 需留意、70–100 高；这是服务方的 IP 信誉估计，不是通用安全评分，也不预测特定网站的处理结果")
        englishDetails.append("Source: IPfastcheck; bands: 0–34 low, 35–69 caution, 70–100 high. This is the provider's IP reputation estimate, not a universal security score or a prediction of how a specific website will treat the connection")

        let status: CheckStatus
        if hasHighRisk {
            status = .failure
        } else if hasCaution {
            status = .warning
        } else if hasReport && !hasIncompleteData {
            status = .pass
        } else {
            status = .unknown
        }
        return result(.ipReputation, status, details.joined(separator: "；"), english: englishDetails.joined(separator: "; "))
    }

    private static func networkTypeLabel(_ value: String?) -> (chinese: String, english: String) {
        switch value?.lowercased() {
        case "residential": ("住宅宽带", "residential")
        case "mobile": ("移动网络", "mobile")
        case "datacenter": ("数据中心 / 托管网络", "data center / hosting")
        default: ("未知", "unknown")
        }
    }

    private static func utcDateString(_ timestamp: Int) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(timestamp)))
    }

    private static func utcDateTimeString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss 'UTC'"
        return formatter.string(from: date)
    }

    private func mainlandEgress(snapshot: NetworkSnapshot) -> CheckResult {
        guard let ip = snapshot.publicIP else {
            return result(.mainlandEgress, .unknown, snapshot.error ?? "未获取到公网出口 IP", english: snapshot.errorEnglish ?? "Could not obtain a public egress IP.")
        }
        let evidence = countryEvidence(for: ip, snapshot: snapshot)
        guard let country = evidence.countryCode else {
            return result(.mainlandEgress, .unknown, "出口：\(ip)；\(evidence.detail)；\(evidence.reason)", english: "Egress: \(ip); \(evidence.englishDetail); \(evidence.englishReason).")
        }
        if country == "CN" {
            return result(.mainlandEgress, .warning, "出口：\(ip)；多来源一致标记为中国大陆 CN；\(evidence.detail)", english: "Egress: \(ip); multiple sources classify it as mainland China (CN); \(evidence.englishDetail).")
        }
        return result(.mainlandEgress, .pass, "出口：\(ip)；多来源一致标记为 \(country)（非 CN）；\(evidence.detail)", english: "Egress: \(ip); multiple sources classify it as \(country) (not CN); \(evidence.englishDetail).")
    }

    private func dualStack(snapshot: NetworkSnapshot, expectedCountry rawExpectedCountry: String) -> CheckResult {
        let expectedCountry = rawExpectedCountry.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if !expectedCountry.isEmpty, !Self.isCountryCode(expectedCountry) {
            return result(.dualStack, .needsConfiguration, "预期国家 / 地区代码应为两个英文字母", english: "Expected country/region code must contain two Latin letters.")
        }
        guard let ipv4 = snapshot.ipv4Address, let ipv6 = snapshot.ipv6Address else {
            let present = [snapshot.ipv4Address.map { "IPv4：\($0)" }, snapshot.ipv6Address.map { "IPv6：\($0)" }].compactMap { $0 }.joined(separator: "；")
            let missing = snapshot.ipv4Address == nil ? "IPv4" : "IPv6"
            return result(.dualStack, .unknown, "\(present.isEmpty ? "尚无可用出口地址" : present)；没有取得 \(missing) 探测响应，不能据此判定通过或泄漏", english: "\(present.isEmpty ? "No usable egress address was obtained" : present); no \(missing) probe response was received, so this cannot be marked as a pass or leak.")
        }

        let ipv4Evidence = countryEvidence(for: ipv4, snapshot: snapshot)
        let ipv6Evidence = countryEvidence(for: ipv6, snapshot: snapshot)
        guard let ipv4Country = ipv4Evidence.countryCode, let ipv6Country = ipv6Evidence.countryCode else {
            return result(.dualStack, .unknown, "IPv4：\(ipv4)（\(ipv4Evidence.detail)；\(ipv4Evidence.reason)）；IPv6：\(ipv6)（\(ipv6Evidence.detail)；\(ipv6Evidence.reason)）", english: "IPv4: \(ipv4) (\(ipv4Evidence.englishDetail); \(ipv4Evidence.englishReason)); IPv6: \(ipv6) (\(ipv6Evidence.englishDetail); \(ipv6Evidence.englishReason)).")
        }

        let summary = "IPv4：\(ipv4) → \(ipv4Country)；IPv6：\(ipv6) → \(ipv6Country)"
        let englishSummary = "IPv4: \(ipv4) → \(ipv4Country); IPv6: \(ipv6) → \(ipv6Country)"
        if !expectedCountry.isEmpty {
            guard ipv4Country == expectedCountry, ipv6Country == expectedCountry else {
                return result(.dualStack, .warning, "\(summary)；与预期地区 \(expectedCountry) 不一致", english: "\(englishSummary); one or both regions differ from the expected \(expectedCountry).")
            }
            return result(.dualStack, .pass, "\(summary)；两个地址族均与预期地区 \(expectedCountry) 相符", english: "\(englishSummary); both address families match the expected region \(expectedCountry).")
        }
        guard ipv4Country == ipv6Country else {
            return result(.dualStack, .warning, "\(summary)；两个地址族的地区判断不同，地址不同本身不代表泄漏", english: "\(englishSummary); the address families are classified in different regions. Different IP addresses alone do not prove a leak.")
        }
        guard ipv4Country != "CN" else {
            return result(.dualStack, .warning, "\(summary)；两个地址族均被标记为中国大陆 CN", english: "\(englishSummary); both address families are classified as mainland China (CN).")
        }
        return result(.dualStack, .pass, "\(summary)；两个地址族的地区判断一致，且均非 CN", english: "\(englishSummary); both address families agree and are classified outside mainland China (CN).")
    }

    private func countryEvidence(for ip: String, snapshot: NetworkSnapshot) -> CountryEvidence {
        let observations = snapshot.geoObservationsByIP[ip] ?? []
        let detail = observations.map { observation in
            "\(observation.source)：\(observation.countryCode ?? (observation.available ? "无国家代码" : "无响应"))"
        }.joined(separator: "；")
        let englishDetail = observations.map { observation in
            "\(observation.source): \(observation.countryCode ?? (observation.available ? "no country code" : "unavailable"))"
        }.joined(separator: "; ")
        let codes = observations.compactMap(\.countryCode)
        if codes.count >= 2, Set(codes).count == 1, let country = codes.first {
            return CountryEvidence(
                countryCode: country,
                detail: detail.isEmpty ? "地区来源一致" : detail,
                englishDetail: englishDetail.isEmpty ? "Sources agree on the region" : englishDetail,
                reason: "",
                englishReason: ""
            )
        }
        let reason: String
        let englishReason: String
        if codes.count < 2 {
            reason = "可用地区来源不足，至少需要两个一致来源"
            englishReason = "Fewer than two usable region sources agree"
        } else {
            reason = "GeoIP 来源判断不一致"
            englishReason = "GeoIP sources disagree"
        }
        return CountryEvidence(
            countryCode: nil,
            detail: detail.isEmpty ? "没有可用的地区来源" : detail,
            englishDetail: englishDetail.isEmpty ? "No region source is available" : englishDetail,
            reason: reason,
            englishReason: englishReason
        )
    }

    private func ipConsistency(snapshot: NetworkSnapshot, history: HistoryStore) async -> CheckResult {
        guard let currentIP = snapshot.publicIP else {
            return result(.ipConsistency, .unknown, snapshot.error ?? "出口 IP 不可用，无法比较历史", english: snapshot.errorEnglish ?? "Egress IP is unavailable, so history cannot be compared.")
        }

        let cutoff = Date.now.addingTimeInterval(-48 * 60 * 60)
        let historySummary = await history.recordAndCompare(ip: currentIP, since: cutoff)
        let changes = historySummary.changeCount

        guard let lastIP = historySummary.previousIP else {
            return result(.ipConsistency, .unknown, "已记录出口 IP 基准；下一轮起可比较变化（本地保留 48 小时）", english: "The initial egress IP has been recorded. Changes can be compared starting with the next check; history is kept locally for 48 hours.")
        }
        if lastIP != currentIP {
            return result(.ipConsistency, .warning, "出口 IP 变化：\(lastIP) → \(currentIP)；48 小时内变化 \(changes) 次", english: "Egress IP changed: \(lastIP) → \(currentIP). It changed \(changes) time(s) in the past 48 hours.")
        }
        if changes >= 3 {
            return result(.ipConsistency, .warning, "当前出口与上次一致；48 小时内变化 \(changes) 次", english: "The current egress matches the previous one. It changed \(changes) time(s) in the past 48 hours.")
        }
        return result(.ipConsistency, .pass, "出口 IP 与上次一致；48 小时内变化 \(changes) 次", english: "Egress IP matches the previous value. It changed \(changes) time(s) in the past 48 hours.")
    }

    private func timeZone(snapshot: NetworkSnapshot, expected: String) -> CheckResult {
        let current = SystemChecks.currentTimeZoneID()
        let expectedValue = expected.trimmingCharacters(in: .whitespacesAndNewlines)
        if !expectedValue.isEmpty, TimeZone(identifier: expectedValue) == nil {
            return result(.timeZone, .needsConfiguration, "预期时区无效：\(expectedValue)", english: "Invalid expected time zone: \(expectedValue)")
        }

        let timeZones = Set((snapshot.geoObservationsByIP[snapshot.publicIP ?? ""] ?? []).compactMap(\.timeZone))
        let geoTimeZone = timeZones.count == 1 ? timeZones.first : nil
        let validGeoTimeZone = geoTimeZone.flatMap { TimeZone(identifier: $0) == nil ? nil : $0 }
        let expectedMismatch = !expectedValue.isEmpty && current != expectedValue
        let egressMismatch = validGeoTimeZone.map { current != $0 } ?? false
        let detailParts = [
            "系统时区：\(current)",
            validGeoTimeZone.map { "出口 IP 时区：\($0)" },
            expectedValue.isEmpty ? nil : "预期时区：\(expectedValue)",
        ].compactMap { $0 }
        let englishParts = [
            "System time zone: \(current)",
            validGeoTimeZone.map { "egress IP time zone: \($0)" },
            expectedValue.isEmpty ? nil : "expected time zone: \(expectedValue)",
        ].compactMap { $0 }

        if expectedMismatch || egressMismatch {
            let sourceNote = validGeoTimeZone == nil ? "；出口 IP 时区来源不足或判断不一致" : ""
            let englishSourceNote = validGeoTimeZone == nil ? "; egress time-zone data is missing or inconsistent" : ""
            return result(.timeZone, .warning, detailParts.joined(separator: "；") + sourceNote, english: englishParts.joined(separator: "; ") + englishSourceNote)
        }

        guard validGeoTimeZone != nil else {
            let reason = timeZones.count > 1 ? "各地区来源的时区判断不一致" : "出口 IP 时区资料不足"
            let englishReason = timeZones.count > 1 ? "region sources disagree about the time zone" : "egress IP time-zone data is unavailable"
            return result(.timeZone, .unknown, detailParts.joined(separator: "；") + "；" + reason, english: englishParts.joined(separator: "; ") + "; " + englishReason)
        }
        return result(.timeZone, .pass, detailParts.joined(separator: "；") + "；与出口 IP 时区一致", english: englishParts.joined(separator: "; ") + "; matches the egress IP time zone")
    }

    private func locale(snapshot: NetworkSnapshot, settings: MonitorSettings) -> CheckResult {
        let current = SystemChecks.currentLocaleID()
        let configuredLocale = settings.expectedLocaleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        if !configuredLocale.isEmpty, !Self.isValidLocaleIdentifier(configuredLocale) {
            return result(.locale, .needsConfiguration, "预期系统地区格式无效：\(configuredLocale)", english: "Invalid expected locale: \(configuredLocale)")
        }
        let configuredCountry = settings.expectedCountryCode.trimmingCharacters(in: .whitespacesAndNewlines)
        if !configuredCountry.isEmpty, !Self.isCountryCode(configuredCountry) {
            return result(.locale, .needsConfiguration, "国家 / 地区代码应为两个英文字母", english: "Country/region code must contain two Latin letters.")
        }

        let egressCountry = snapshot.publicIP.flatMap { countryEvidence(for: $0, snapshot: snapshot).countryCode }
        let expectedCountry = configuredCountry.isEmpty ? nil : configuredCountry.uppercased()
        let regionCodes = Set(([current] + Locale.preferredLanguages).compactMap(Self.localeRegionCode))
        let localeMatchesExpected = configuredLocale.isEmpty || Self.locale(current, matches: configuredLocale)
        let egressMatches = egressCountry.map { country in regionCodes.isEmpty || regionCodes.allSatisfy { $0 == country } } ?? true
        let expectedMatches = expectedCountry.map { country in regionCodes.isEmpty || regionCodes.allSatisfy { $0 == country } } ?? true
        let detailParts = [
            "系统地区：\(current)",
            "系统语言地区标记：\(regionCodes.sorted().joined(separator: ", "))",
            egressCountry.map { "出口 IP 地区：\($0)" },
            expectedCountry.map { "预期地区：\($0)" },
            configuredLocale.isEmpty ? nil : "预期系统地区：\(configuredLocale)",
        ].compactMap { $0 }
        let englishParts = [
            "System locale: \(current)",
            "system language region tags: \(regionCodes.sorted().joined(separator: ", "))",
            egressCountry.map { "egress IP region: \($0)" },
            expectedCountry.map { "expected region: \($0)" },
            configuredLocale.isEmpty ? nil : "expected locale: \(configuredLocale)",
        ].compactMap { $0 }

        if !localeMatchesExpected || !egressMatches || !expectedMatches {
            return result(.locale, .warning, detailParts.joined(separator: "；") + "；系统地区标记与参考地区不一致", english: englishParts.joined(separator: "; ") + "; system region tags differ from a reference region")
        }
        if regionCodes.isEmpty {
            return result(.locale, .unknown, detailParts.joined(separator: "；") + "；系统语言没有地区代码，无法比较国家 / 地区", english: englishParts.joined(separator: "; ") + "; system language has no region tag, so country/region consistency cannot be assessed")
        }
        guard egressCountry != nil || expectedCountry != nil || !configuredLocale.isEmpty else {
            return result(.locale, .unknown, detailParts.joined(separator: "；") + "；没有一致的出口地区来源", english: englishParts.joined(separator: "; ") + "; no agreeing egress region source is available")
        }
        return result(.locale, .pass, detailParts.joined(separator: "；") + "；地区标记与出口 / 预期地区一致", english: englishParts.joined(separator: "; ") + "; region tags match the egress or expected region")
    }

    private func ipv6(snapshot: NetworkSnapshot, settings: MonitorSettings) -> CheckResult {
        guard let address = snapshot.ipv6Address else {
            return result(.ipv6, .unknown, "没有得到 IPv6 探测响应；这不能证明 IPv6 不可用", english: "No IPv6 probe response was received; this does not prove that IPv6 is unavailable.")
        }
        let expectedCountry = settings.expectedCountryCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if !expectedCountry.isEmpty, !Self.isCountryCode(expectedCountry) {
            return result(.ipv6, .needsConfiguration, "国家 / 地区代码应为两个英文字母", english: "Country/region code must contain two Latin letters.")
        }
        let evidence = countryEvidence(for: address, snapshot: snapshot)
        guard let observedCountry = evidence.countryCode else {
            return result(.ipv6, .unknown, "检测到公网 IPv6：\(address)；\(evidence.detail)；\(evidence.reason)", english: "Public IPv6 detected: \(address); \(evidence.englishDetail); \(evidence.englishReason.lowercased()).")
        }
        guard !expectedCountry.isEmpty else {
            return result(.ipv6, .unknown, "检测到公网 IPv6：\(address)（多来源地区：\(observedCountry)）；未设置预期出口地区，无法判断路由是否符合预期", english: "Public IPv6 detected: \(address) (multi-source region: \(observedCountry)). No expected egress region is set, so the route cannot be judged.")
        }
        guard observedCountry != expectedCountry else {
            return result(.ipv6, .unknown, "检测到公网 IPv6：\(address)，多来源地区与预期 \(expectedCountry) 相符；仍不能单凭地区确认代理路由", english: "Public IPv6 detected: \(address). Its multi-source region matches \(expectedCountry), but region alone cannot confirm proxy routing.")
        }
        return result(.ipv6, .warning, "检测到公网 IPv6：\(address)，多来源地区 \(observedCountry) 与预期地区 \(expectedCountry) 不同", english: "Public IPv6 detected: \(address). Its multi-source region \(observedCountry) differs from the expected region \(expectedCountry).")
    }

    private func dnsTunnel(settings: MonitorSettings) async -> CheckResult {
        let domain = settings.dnsTestDomain.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard Self.isValidDomain(domain), Self.isValidIPv4CIDR(settings.fakeIPCIDR) else {
            return result(.dnsTunnel, .needsConfiguration, "填写测试域名和有效的 IPv4 Fake-IP 网段", english: "Enter a test domain and a valid IPv4 Fake-IP range.")
        }
        guard let addresses = await resolve(domain) else {
            return result(.dnsTunnel, .unknown, "系统 DNS 查询未能完成", english: "The system DNS lookup could not be completed.")
        }
        guard !addresses.isEmpty else {
            return result(.dnsTunnel, .warning, "\(domain) 没有返回地址", english: "\(domain) returned no addresses.")
        }
        let fakeIPs = addresses.filter { Self.ipv4($0, isInside: settings.fakeIPCIDR) }
        if fakeIPs.count == addresses.count {
            return result(.dnsTunnel, .pass, "\(domain) → \(fakeIPs.joined(separator: ", "))", english: "\(domain) → \(fakeIPs.joined(separator: ", "))")
        }
        if !fakeIPs.isEmpty {
            return result(.dnsTunnel, .warning, "\(domain) 返回混合地址，只有部分落入预期 Fake-IP 网段；全部结果：\(addresses.prefix(4).joined(separator: ", "))", english: "\(domain) returned mixed addresses; only some are in the expected Fake-IP range. Results: \(addresses.prefix(4).joined(separator: ", "))")
        }
        return result(.dnsTunnel, .warning, "\(domain) 未解析到预期 Fake-IP；返回：\(addresses.prefix(3).joined(separator: ", "))", english: "\(domain) did not resolve to the expected Fake-IP range. Returned: \(addresses.prefix(3).joined(separator: ", "))")
    }

    private func webRTC(snapshot: NetworkSnapshot) async -> CheckResult {
        let servers: [(String, UInt16)] = [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]
        var mapped: [String] = []
        var errors: [String] = []
        var errorsEnglish: [String] = []

        for (host, rawPort) in servers {
            guard let port = NWEndpoint.Port(rawValue: rawPort) else { continue }
            do {
                let address = try await STUNProbe.publicAddress(
                    server: NWEndpoint.Host(host),
                    port: port,
                    timeout: 4
                )
                mapped.append(address)
            } catch {
                errors.append("\(host)：无响应")
                errorsEnglish.append("\(host): no response")
            }
        }

        guard !mapped.isEmpty else {
            return result(.webRTC, .unknown, "STUN 节点均无响应；不能据此判断没有泄漏", english: "All STUN servers were unresponsive; this does not prove there is no leak.")
        }
        let distinct = Set(mapped.map { Self.canonicalIP($0) ?? $0 })
        let egressAddresses = Set([snapshot.publicIP, snapshot.ipv4Address, snapshot.ipv6Address].compactMap { address in
            address.flatMap(Self.canonicalIP)
        })
        guard !egressAddresses.isEmpty else {
            return result(.webRTC, .unknown, "STUN 映射：\(mapped.joined(separator: ", "))；HTTP 出口地址不可用，无法比较", english: "STUN mappings: \(mapped.joined(separator: ", ")). HTTP egress addresses are unavailable, so they cannot be compared.")
        }

        if distinct.isSubset(of: egressAddresses) {
            guard errors.isEmpty else {
                return result(.webRTC, .unknown, "STUN 映射与至少一个 HTTP 地址族出口相符，但部分节点无响应：\(errors.joined(separator: "；"))", english: "STUN mappings match at least one HTTP address-family egress, but some servers were unresponsive: \(errorsEnglish.joined(separator: "; "))")
            }
            return result(.webRTC, .pass, "STUN 映射与至少一个 HTTP IPv4 / IPv6 出口相符；这只说明本轮观测一致，不保证没有泄漏：\(distinct.sorted().joined(separator: ", "))", english: "STUN mappings match at least one HTTP IPv4 / IPv6 egress. This only describes agreement in this run and does not guarantee that no leak exists: \(distinct.sorted().joined(separator: ", "))")
        }
        let detail = "STUN 映射：\(distinct.sorted().joined(separator: ", "))；HTTP IPv4 / IPv6 出口：\(egressAddresses.sorted().joined(separator: ", "))；不同结果是路径差异信号，不单独证明泄漏" + (errors.isEmpty ? "" : "；部分节点无响应")
        let englishDetail = "STUN mappings: \(distinct.sorted().joined(separator: ", ")); HTTP IPv4 / IPv6 egress: \(egressAddresses.sorted().joined(separator: ", ")); divergence is a path signal, not proof of a leak" + (errorsEnglish.isEmpty ? "" : "; some servers were unresponsive")
        return result(.webRTC, .warning, detail, english: englishDetail)
    }

    private func webkitProfile(snapshot: NetworkSnapshot, settings: MonitorSettings) async -> CheckResult {
        let profile = await WebKitProfileProbe.run()
        let languageText = profile.languages.isEmpty ? "未读取到" : profile.languages.joined(separator: ", ")
        let englishLanguageText = profile.languages.isEmpty ? "unavailable" : profile.languages.joined(separator: ", ")
        let platform = profile.platform?.isEmpty == false ? profile.platform! : "未读取到"
        let englishPlatform = profile.platform?.isEmpty == false ? profile.platform! : "unavailable"
        let webkitTimeZone = profile.timeZone?.isEmpty == false ? profile.timeZone! : nil
        let systemTimeZone = SystemChecks.currentTimeZoneID()
        let preferredLanguages = Locale.preferredLanguages
        let systemLocale = SystemChecks.currentLocaleID()

        var findings: [String] = []
        var englishFindings: [String] = []
        var hasMismatch = false
        if !profile.languages.isEmpty, !preferredLanguages.isEmpty,
           !profile.languages.contains(where: { webkit in preferredLanguages.contains(where: { Self.languageTagsMatch(webkit, $0) }) }) {
            hasMismatch = true
            findings.append("WebKit 语言与 macOS 首选语言列表不同")
            englishFindings.append("WebKit languages differ from macOS preferred languages")
        }
        if !profile.languages.isEmpty,
           !profile.languages.contains(where: { Self.localeTagsMatch($0, systemLocale) }) {
            hasMismatch = true
            findings.append("WebKit 语言与当前系统 Locale 不同")
            englishFindings.append("WebKit languages differ from the current system locale")
        }
        if let expectedLocale = Self.normalizedLocale(settings.expectedLocaleIdentifier),
           !profile.languages.contains(where: { Self.localeTagsMatch($0, expectedLocale) }) {
            hasMismatch = true
            findings.append("WebKit 语言与预期 Locale 不同")
            englishFindings.append("WebKit language differs from the expected locale")
        }
        if let webkitTimeZone {
            let expectedTimeZone = settings.expectedTimeZoneID.trimmingCharacters(in: .whitespacesAndNewlines)
            if !expectedTimeZone.isEmpty, webkitTimeZone != expectedTimeZone {
                hasMismatch = true
                findings.append("WebKit 时区与预期时区不同")
                englishFindings.append("WebKit time zone differs from the expected time zone")
            } else if expectedTimeZone.isEmpty, webkitTimeZone != systemTimeZone {
                hasMismatch = true
                findings.append("WebKit 时区与 macOS 系统时区不同")
                englishFindings.append("WebKit time zone differs from the macOS system time zone")
            }
        }

        let egressAddresses = Set([snapshot.publicIP, snapshot.ipv4Address, snapshot.ipv6Address].compactMap { address in
            address.flatMap(Self.canonicalIP)
        })
        let webkitAddresses = Set(profile.publicICEAddresses.compactMap(Self.canonicalIP))
        let unexpectedICE = webkitAddresses.subtracting(egressAddresses)
        if !unexpectedICE.isEmpty, !egressAddresses.isEmpty {
            hasMismatch = true
            findings.append("WebKit 公网 ICE 映射与 HTTP 出口不同；这是路径差异信号，不单独证明泄漏")
            englishFindings.append("Public WebKit ICE mappings differ from HTTP egress; this signals path divergence but does not by itself prove a leak")
        }

        let nativeDetail = latestNativeWebRTCResult?.detail ?? "尚未运行原生 STUN 探测"
        let nativeEnglishDetail = latestNativeWebRTCResult?.englishDetail ?? "The native STUN probe has not run."
        let iceText = profile.publicICEAddresses.isEmpty ? "没有可用的公网 ICE 候选" : profile.publicICEAddresses.joined(separator: ", ")
        let englishICEText = profile.publicICEAddresses.isEmpty ? "no public ICE candidate was available" : profile.publicICEAddresses.joined(separator: ", ")
        let profileError = profile.error.map { "；探测状态：\($0)" } ?? ""
        let englishProfileError = profile.error.map { "; probe status: \($0)" } ?? ""
        let summary = "WebKit languages：\(languageText)；platform：\(platform)；JS 时区：\(webkitTimeZone ?? "未读取到")；公网 ICE：\(iceText)；macOS preferred languages：\(preferredLanguages.joined(separator: ", "))；system Locale：\(systemLocale)；system 时区：\(systemTimeZone)；原生 STUN：\(nativeDetail)"
        let englishSummary = "WebKit languages: \(englishLanguageText); platform: \(englishPlatform); JS time zone: \(webkitTimeZone ?? "unavailable"); public ICE: \(englishICEText); macOS preferred languages: \(preferredLanguages.joined(separator: ", ")); system locale: \(systemLocale); system time zone: \(systemTimeZone); native STUN: \(nativeEnglishDetail)"

        guard profile.completed else {
            return result(.webkitProfile, .unknown, "\(summary)\(profileError)；本次结果不完整，不能判断是否泄漏", english: "\(englishSummary)\(englishProfileError); the probe was incomplete, so it cannot determine whether anything leaked.")
        }
        guard !profile.languages.isEmpty, webkitTimeZone != nil, profile.platform?.isEmpty == false else {
            return result(.webkitProfile, .unknown, "\(summary)；WebKit 语言、时区或平台信息不完整，无法确认环境一致性", english: "\(englishSummary); WebKit language, time-zone, or platform data is incomplete, so profile consistency cannot be determined.")
        }
        guard !profile.publicICEAddresses.isEmpty else {
            return result(.webkitProfile, .unknown, "\(summary)；没有公网 ICE 候选不等于没有泄漏", english: "\(englishSummary); no public ICE candidate does not prove there is no leak.")
        }
        guard !egressAddresses.isEmpty else {
            return result(.webkitProfile, .unknown, "\(summary)；HTTP 出口地址不可用，无法比较 ICE 映射", english: "\(englishSummary); HTTP egress is unavailable, so the ICE mapping cannot be compared.")
        }

        let conclusion = hasMismatch
            ? "信号：\(findings.joined(separator: "；"))；此项只描述本应用内嵌 WebKit，不代表 Safari 或 Chrome，也不能单独确认泄漏"
            : "本轮未观察到明显差异；此项只描述本应用内嵌 WebKit，不代表 Safari 或 Chrome，也不保证没有泄漏"
        let englishConclusion = hasMismatch
            ? "Signals: \(englishFindings.joined(separator: "; ")); this describes this app's embedded WebKit only, not Safari or Chrome, and does not by itself confirm a leak"
            : "No obvious mismatch was observed in this run; this describes this app's embedded WebKit only, not Safari or Chrome, and does not guarantee that no leak exists"
        return result(.webkitProfile, hasMismatch ? .warning : .pass, "\(summary)；\(conclusion)", english: "\(englishSummary); \(englishConclusion).")
    }

    private static func normalizedLocale(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return trimmed.replacingOccurrences(of: "_", with: "-").lowercased()
    }

    private static func languageTagsMatch(_ lhs: String, _ rhs: String) -> Bool {
        let left = lhs.replacingOccurrences(of: "_", with: "-").lowercased()
        let right = rhs.replacingOccurrences(of: "_", with: "-").lowercased()
        return left == right || left.hasPrefix(right + "-") || right.hasPrefix(left + "-")
    }

    private static func localeTagsMatch(_ lhs: String, _ rhs: String) -> Bool {
        let left = lhs.replacingOccurrences(of: "_", with: "-").lowercased()
        let right = rhs.replacingOccurrences(of: "_", with: "-").lowercased()
        return left == right || left.hasPrefix(right + "-") || right.hasPrefix(left + "-")
    }

    private func routeRules(settings: MonitorSettings) async -> CheckResult {
        let domains = settings.routeDomains.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        guard !domains.isEmpty, domains.allSatisfy(Self.isValidDomain), Self.isValidIPv4CIDR(settings.fakeIPCIDR) else {
            return result(.routeRules, .needsConfiguration, "添加要检查的域名并设置预期 Fake-IP 网段", english: "Add domains to check and set the expected Fake-IP range.")
        }
        guard domains.count <= 20 else {
            return result(.routeRules, .needsConfiguration, "最多添加 20 个路由测试域名；当前有 \(domains.count) 个", english: "Add no more than 20 route test domains; \(domains.count) are currently configured.")
        }

        var unmatched: [String] = []
        var unavailable: [String] = []
        for domain in domains {
            guard let addresses = await resolve(domain), !addresses.isEmpty else {
                unavailable.append(domain)
                continue
            }
            if !addresses.allSatisfy({ Self.ipv4($0, isInside: settings.fakeIPCIDR) }) {
                unmatched.append(domain)
            }
        }

        if !unavailable.isEmpty {
            return result(.routeRules, .unknown, "无法验证：\(unavailable.joined(separator: ", "))", english: "Could not verify: \(unavailable.joined(separator: ", "))")
        }
        if !unmatched.isEmpty {
            return result(.routeRules, .warning, "未解析到 Fake-IP：\(unmatched.joined(separator: ", "))；本检查只验证 DNS 路由迹象", english: "These domains did not resolve to Fake-IP: \(unmatched.joined(separator: ", ")). This check only looks for DNS routing indicators.")
        }
        return result(.routeRules, .pass, "\(domains.count) 个域名解析到 Fake-IP；不代表已验证代理策略组", english: "\(domains.count) domain(s) resolved to Fake-IP. This does not verify the proxy policy group.")
    }

    private func reachability(urlStrings: [String]) async -> CheckResult {
        let values = Array(urlStrings.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.prefix(10))
        guard !values.isEmpty else {
            return result(.reachability, .needsConfiguration, "添加一个 HTTPS 测试站点", english: "Add an HTTPS test site.")
        }

        var reachable: [String] = []
        var failures: [String] = []
        var inconclusive: [String] = []
        var invalid: [String] = []
        var reachableEnglish: [String] = []
        for rawValue in values {
            guard let components = URLComponents(string: rawValue),
                  components.scheme?.lowercased() == "https",
                  components.host != nil,
                  components.user == nil,
                  components.password == nil,
                  let url = components.url else {
                invalid.append(rawValue)
                continue
            }

            var request = URLRequest(url: url)
            request.httpMethod = "HEAD"
            request.timeoutInterval = 6
            do {
                let response = try await session.data(for: request).1
                guard let http = response as? HTTPURLResponse else {
                    failures.append(url.host ?? rawValue)
                    continue
                }
                let isRedirect = (300..<400).contains(http.statusCode)
                let redirectNote = isRedirect ? "（未跟随跳转）" : ""
                let englishRedirectNote = isRedirect ? " (redirect not followed)" : ""
                reachable.append("\(url.host ?? rawValue) HTTP \(http.statusCode)\(redirectNote)")
                reachableEnglish.append("\(url.host ?? rawValue) HTTP \(http.statusCode)\(englishRedirectNote)")
            } catch {
                let name = url.host ?? rawValue
                if let urlError = error as? URLError,
                   [.timedOut, .notConnectedToInternet, .networkConnectionLost, .dataNotAllowed].contains(urlError.code) {
                    inconclusive.append(name)
                } else {
                    failures.append(name)
                }
            }
        }

        if reachable.isEmpty, failures.isEmpty, inconclusive.isEmpty {
                return result(.reachability, .needsConfiguration, "HTTPS 地址无效：\(invalid.joined(separator: "、"))", english: "Invalid HTTPS URL(s): \(invalid.joined(separator: ", "))")
        }
        if reachable.isEmpty {
            if !inconclusive.isEmpty {
                let details = inconclusive.joined(separator: "、")
                return result(.reachability, .unknown, "没有得到网络响应，无法判断：\(details)", english: "No network response was received, so this is inconclusive: \(inconclusive.joined(separator: ", "))")
            }
            return result(.reachability, .failure, "HTTPS 连接失败：\(failures.joined(separator: ", "))", english: "HTTPS connection failed: \(failures.joined(separator: ", "))")
        }
        if failures.isEmpty, inconclusive.isEmpty, invalid.isEmpty {
            return result(.reachability, .pass, reachable.joined(separator: " · "), english: reachableEnglish.joined(separator: " · "))
        }
        var details = ["可达：\(reachable.joined(separator: " · "))"]
        var englishDetails = ["Reachable: \(reachableEnglish.joined(separator: " · "))"]
        if !failures.isEmpty {
            details.append("失败：\(failures.joined(separator: ", "))")
            englishDetails.append("Failed: \(failures.joined(separator: ", "))")
        }
        if !inconclusive.isEmpty {
            details.append("无响应：\(inconclusive.joined(separator: "、"))")
            englishDetails.append("No response: \(inconclusive.joined(separator: ", "))")
        }
        if !invalid.isEmpty {
            details.append("无效地址：\(invalid.joined(separator: "、"))")
            englishDetails.append("Invalid URL: \(invalid.joined(separator: ", "))")
        }
        return result(.reachability, .warning, details.joined(separator: "；"), english: englishDetails.joined(separator: "; "))
    }

    private func resolve(_ domain: String) async -> [String]? {
        guard let output = await CommandRunner.output(
            "/usr/bin/dig",
            arguments: ["+short", "+time=3", "+tries=1", domain],
            timeout: 5
        ) else {
            return nil
        }
        return output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { Self.isIPAddress($0) }
    }

    private func fetchCloudflareTrace() async -> (ip: String?, countryCode: String?)? {
        guard let url = URL(string: "https://www.cloudflare.com/cdn-cgi/trace"),
              let response = try? await get(url),
              (200..<300).contains(response.statusCode),
              let text = String(data: response.data, encoding: .utf8) else { return nil }
        var fields: [String: String] = [:]
        for line in text.components(separatedBy: .newlines) {
            let pair = line.split(separator: "=", maxSplits: 1).map(String.init)
            if pair.count == 2 { fields[pair[0]] = pair[1] }
        }
        return (fields["ip"], fields["loc"])
    }

    private func geoInfo(for ip: String, fallbackInfo: IPInfo? = nil) async -> CacheEntry {
        if let cached = geoCache[ip], cached.expiresAt > .now { return cached }

        async let ipapiResult = fetchIPAPI(for: ip)
        let info: IPInfo?
        if let fallbackInfo {
            info = fallbackInfo
        } else {
            info = await fetchIPInfo(for: ip)
        }
        let ipapi = await ipapiResult
        let lifetime: TimeInterval = info != nil && ipapi != nil ? 24 * 60 * 60 : 15 * 60
        let entry = CacheEntry(info: info, ipapi: ipapi, expiresAt: .now.addingTimeInterval(lifetime))
        geoCache[ip] = entry
        return entry
    }

    private func ipRiskReport(for ip: String) async -> IPRiskObservation? {
        if let cached = ipRiskCache[ip], cached.expiresAt > .now {
            return cached.observation
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = "ipfastcheck.com"
        components.path = "/short/\(ip)"

        var observation: IPRiskObservation?
        if let url = components.url,
           let response = try? await get(url),
           (200..<300).contains(response.statusCode),
           let decoded = try? JSONDecoder().decode(IPRiskResponse.self, from: response.data),
           decoded.ok,
           let data = decoded.data,
           data.ip.flatMap(Self.canonicalIP) == Self.canonicalIP(ip),
           data.risk.map({ (0...100).contains($0) }) == true {
            observation = IPRiskObservation(report: data, fetchedAt: .now)
        }

        let lifetime: TimeInterval = observation == nil ? 15 * 60 : 24 * 60 * 60
        ipRiskCache[ip] = IPRiskCacheEntry(observation: observation, expiresAt: .now.addingTimeInterval(lifetime))
        return observation
    }

    private func fetchIPv4Address() async -> String? {
        await fetchAddress(at: "https://api.ipify.org", validator: Self.isIPv4)
    }

    private func fetchIPv6Address() async -> String? {
        await fetchAddress(at: "https://api6.ipify.org", validator: Self.isIPv6)
    }

    private func fetchAddress(at rawURL: String, validator: (String) -> Bool) async -> String? {
        guard let url = URL(string: rawURL),
              let response = try? await get(url),
              (200..<300).contains(response.statusCode),
              let address = String(data: response.data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              validator(address) else { return nil }
        return Self.canonicalIP(address)
    }

    private func fetchIPInfo(for ip: String) async -> IPInfo? {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "ipinfo.io"
        components.path = "/\(ip)/json"
        guard let url = components.url else { return nil }
        return await fetchIPInfo(at: url, expectedIP: ip)
    }

    private func fetchIPAPI(for ip: String) async -> IPAPIGeoInfo? {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "ipapi.co"
        components.path = "/\(ip)/json/"
        guard let url = components.url,
              let response = try? await get(url),
              (200..<300).contains(response.statusCode),
              let decoded = try? JSONDecoder().decode(IPAPIGeoInfo.self, from: response.data) else { return nil }
        if let returnedIP = decoded.ip,
           Self.canonicalIP(returnedIP) != Self.canonicalIP(ip) {
            return nil
        }
        guard let country = decoded.countryCode?.uppercased(), Self.isCountryCode(country) else { return nil }
        var validated = decoded
        validated.countryCode = country
        return validated
    }

    private func fetchIPInfo(at url: URL, expectedIP: String? = nil) async -> IPInfo? {
        guard let response = try? await get(url),
              (200..<300).contains(response.statusCode) else { return nil }
        guard var decoded = try? JSONDecoder().decode(IPInfo.self, from: response.data),
              let country = decoded.country?.uppercased(), Self.isCountryCode(country) else { return nil }
        if let expectedIP, let returnedIP = decoded.ip,
           Self.canonicalIP(returnedIP) != Self.canonicalIP(expectedIP) {
            return nil
        }
        decoded.country = country
        return decoded
    }

    private func get(_ url: URL) async throws -> HTTPResult {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 8
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return HTTPResult(data: data, statusCode: http.statusCode)
    }

    // Accept only assigned ISO 3166-1 alpha-2 regions. Provider sentinels such as XX/ZZ
    // must not count toward GeoIP consensus or become a non-mainland pass.
    private static let supportedCountryCodes: Set<String> = Set("""
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
    CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO
    JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
    MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA
    RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO
    TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
    """.split(whereSeparator: \.isWhitespace).map(String.init))

    private static func locale(_ current: String, matches expected: String) -> Bool {
        let cleanCurrent = current.split(separator: "@").first.map(String.init) ?? current
        let actual = cleanCurrent.replacingOccurrences(of: "-", with: "_").lowercased()
        let target = expected.replacingOccurrences(of: "-", with: "_").lowercased()
        let actualParts = actual.split(separator: "_").map(String.init)
        let targetParts = target.split(separator: "_").map(String.init)
        guard actualParts.first == targetParts.first else { return false }
        let expectedRegion = targetParts.dropFirst().first { part in
            (part.count == 2 && part.allSatisfy(\.isLetter)) || (part.count == 3 && part.allSatisfy(\.isNumber))
        }
        if let expectedRegion {
            return actualParts.dropFirst().contains(expectedRegion)
        }
        return actual == target || actual.hasPrefix(target + "_")
    }

    private static func localeRegionCode(_ value: String) -> String? {
        let cleanValue = value.split(separator: "@").first.map(String.init) ?? value
        let parts = cleanValue.replacingOccurrences(of: "-", with: "_").split(separator: "_").dropFirst()
        return parts.compactMap { part -> String? in
            let candidate = String(part).uppercased()
            let isAlphaRegion = candidate.count == 2 && candidate.allSatisfy(\.isLetter)
            let isNumericRegion = candidate.count == 3 && candidate.allSatisfy(\.isNumber)
            return isAlphaRegion || isNumericRegion ? candidate : nil
        }.first
    }

    private static func isCountryCode(_ value: String) -> Bool {
        supportedCountryCodes.contains(value.uppercased())
    }

    private static func isValidLocaleIdentifier(_ value: String) -> Bool {
        value.range(of: #"^[A-Za-z]{2,3}([_-][A-Za-z0-9]{2,8})*(@[A-Za-z0-9_=+\-]+)?$"#, options: .regularExpression) != nil
    }

    private static func isValidDomain(_ input: String) -> Bool {
        let domain = input.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
        guard !domain.isEmpty, domain.count <= 253 else { return false }
        return domain.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard !label.isEmpty, label.count <= 63,
                  label.first?.isLetter == true || label.first?.isNumber == true,
                  label.last?.isLetter == true || label.last?.isNumber == true else { return false }
            return label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
        }
    }

    private static func isValidIPv4CIDR(_ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, Int(parts[1]).map({ (0...32).contains($0) }) == true else { return false }
        return isIPv4(String(parts[0]))
    }

    private static func ipv4(_ ip: String, isInside cidr: String) -> Bool {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              let address = ipv4Number(ip), let network = ipv4Number(String(parts[0])) else { return false }
        let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
        return (address & mask) == (network & mask)
    }

    private static func ipv4Number(_ value: String) -> UInt32? {
        let octets = value.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt8($0) }
        guard octets.count == 4, value.split(separator: ".", omittingEmptySubsequences: false).count == 4 else { return nil }
        return octets.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    private static func isIPv4(_ value: String) -> Bool { ipv4Number(value) != nil }
    private static func isIPAddress(_ value: String) -> Bool { isIPv4(value) || isIPv6(value) }

    private static func isIPv6(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func canonicalIP(_ value: String) -> String? {
        if let number = ipv4Number(value) {
            return [24, 16, 8, 0].map { String((number >> $0) & 0xff) }.joined(separator: ".")
        }
        var address = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &address) == 1 }) else { return nil }
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let converted = output.withUnsafeMutableBufferPointer { buffer in
            inet_ntop(AF_INET6, &address, buffer.baseAddress, socklen_t(buffer.count))
        }
        guard converted != nil else { return nil }
        let bytes = output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self).lowercased()
    }

    private func result(_ id: CheckID, _ status: CheckStatus, _ detail: String, english englishDetail: String) -> CheckResult {
        CheckResult(id: id, status: status, detail: detail, englishDetail: englishDetail, observedAt: .now)
    }
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    static let shared = NoRedirectDelegate()

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
