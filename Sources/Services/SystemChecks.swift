import Foundation
@preconcurrency import Dispatch
import Darwin
import IOKit

enum SystemChecks {
    static func run(_ id: CheckID, settings: MonitorSettings) async -> CheckResult {
        switch id {
        case .proxyKernel:
            return await proxyKernel(settings.proxyClient)
        case .tunInterface:
            return await tunInterface()
        case .routeProfile:
            return await routeProfile()
        case .deviceRegion:
            return deviceRegion()
        default:
            return CheckResult(id: id, status: .unknown, detail: "此检查由网络探测模块执行", englishDetail: "This check is handled by the network probe module.", observedAt: .now)
        }
    }

    static func currentTimeZoneID() -> String {
        TimeZone.current.identifier
    }

    static func currentLocaleID() -> String {
        Locale.current.identifier
    }

    private static func deviceRegion() -> CheckResult {
        guard let code = platformRegionCode() else {
            return result(.deviceRegion, .unknown,
                          "系统未提供可读取的型号地区代码；未读取序列号。",
                          english: "The system did not expose a readable model-region code; no serial number was read.")
        }

        switch code.uppercased() {
        case "CH/A":
            return result(.deviceRegion, .warning,
                          "型号地区代码：\(code)；常见映射为中国大陆销售渠道，按中国相关销售区列为风险信号。该代码仅是销售地区参考，不代表当前所在地或购买凭证。",
                          english: "Model-region code: \(code); commonly mapped to mainland-China sales. Counted as a China-related sales-region risk signal. This code is only a sales-region reference, not proof of current location or purchase history.")
        case "LL/A":
            return result(.deviceRegion, .pass,
                          "型号地区代码：\(code)；常见映射为美国销售渠道，属于非中国销售区，此项不计风险。该代码仅是销售地区参考，不代表当前所在地或购买凭证。",
                          english: "Model-region code: \(code); commonly mapped to U.S. sales. This is a non-China sales region and is not counted as a risk signal. The code is only a sales-region reference, not proof of current location or purchase history.")
        default:
            return result(.deviceRegion, .unknown,
                          "型号地区代码：\(code)；无法确认是否属于中国相关销售渠道，因此暂不判为风险或通过。",
                          english: "Model-region code: \(code). The sales region cannot be confirmed as China-related or non-China, so this check remains inconclusive.")
        }
    }

    private static func platformRegionCode() -> String? {
        let matching = IOServiceMatching("IOPlatformExpertDevice")
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != IO_OBJECT_NULL else { return nil }
        defer { IOObjectRelease(service) }

        guard let value = IORegistryEntryCreateCFProperty(
            service,
            "region-info" as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue(), let data = value as? Data else { return nil }
        let bytes = data.prefix(16).prefix { $0 != 0 }
        guard let code = String(bytes: bytes, encoding: .utf8),
              code.range(of: #"^[A-Z]{1,3}/A$"#, options: .regularExpression) != nil else { return nil }
        return code
    }

    private static func proxyKernel(_ selected: ProxyClient) async -> CheckResult {
        guard let processList = await CommandRunner.output("/bin/ps", arguments: ["-axo", "comm="]) else {
            return result(.proxyKernel, .unknown, "无法读取本机进程列表", english: "Could not read the local process list.")
        }

        let processText = processList.lowercased()
        let candidates = proxyCandidates(for: selected)
        for candidate in candidates {
            if candidate.markers.contains(where: processText.contains) {
                return result(.proxyKernel, .warning, "检测到代理进程：\(candidate.name)；按风险信号记录，进程存在不代表所有流量都经过该代理", english: "Proxy process detected: \(candidate.name). Counted as a risk signal; process presence does not prove all traffic uses it.")
            }
        }

        if selected == .shadowrocket,
           let connections = await CommandRunner.output("/usr/sbin/scutil", arguments: ["--nc", "list"]),
           connections.localizedCaseInsensitiveContains("Shadowrocket"),
           connections.localizedCaseInsensitiveContains("Connected") {
            return result(.proxyKernel, .warning, "检测到 Shadowrocket 隧道已连接；按风险信号记录", english: "Shadowrocket tunnel is connected. Counted as a risk signal.")
        }

        if selected == .other {
            return result(.proxyKernel, .needsConfiguration, "当前版本尚未配置此客户端的识别方式", english: "Detection for this client has not been configured in this version.")
        }
        let expected = selected == .automatic ? "已支持的代理客户端" : selected.title
        let englishExpected = selected == .automatic ? "a supported proxy client" : selected.englishTitle
        return result(.proxyKernel, .pass, "未发现运行中的\(expected)；此结果仅限本机进程检测", english: "No running \(englishExpected) was found; this result covers local process detection only.")
    }

    private static func proxyCandidates(for selected: ProxyClient) -> [(name: String, markers: [String])] {
        let all: [(name: String, markers: [String])] = [
            ("Clash Verge / Mihomo", ["verge-mihomo", "mihomo"]),
            ("FlClash", ["flclashcore", "flclash"]),
            ("Shadowrocket", ["shadowrocket"]),
            ("sing-box", ["sing-box"]),
            ("ClashX", ["clashx"]),
            ("Surge", ["surge"]),
        ]
        switch selected {
        case .automatic:
            return all
        case .clashVerge:
            return [all[0]]
        case .flClash:
            return [all[1]]
        case .shadowrocket:
            return [all[2]]
        case .singBox:
            return [all[3]]
        case .clashX:
            return [all[4]]
        case .surge:
            return [all[5]]
        case .other:
            return []
        }
    }

    private static func tunInterface() async -> CheckResult {
        guard let output = await CommandRunner.output("/sbin/ifconfig", arguments: ["-a"]) else {
            return result(.tunInterface, .unknown, "无法读取网络接口", english: "Could not read the network interfaces.")
        }

        let candidates = output.components(separatedBy: .newlines).compactMap { line -> String? in
            guard !line.hasPrefix(" "), let colon = line.firstIndex(of: ":") else { return nil }
            let name = String(line[..<colon])
            let supported = name.range(of: #"^(utun\d+|tun\d*|tap\d*|ipsec\d+|ppp\d+)$"#, options: .regularExpression) != nil
            guard supported, let open = line.firstIndex(of: "<"), let close = line[open...].firstIndex(of: ">") else { return nil }
            let flags = line[line.index(after: open)..<close].split(separator: ",").map(String.init)
            return flags.contains("UP") ? name : nil
        }

        if candidates.isEmpty {
            return result(.tunInterface, .pass, "未发现活动隧道接口", english: "No active tunnel interface was found.")
        }
        return result(.tunInterface, .warning, "发现活动隧道接口：\(candidates.joined(separator: ", "))；按风险信号记录", english: "Active tunnel interface(s) detected: \(candidates.joined(separator: ", ")). Counted as a risk signal.")
    }

    private static func routeProfile() async -> CheckResult {
        async let dnsOutput = CommandRunner.output("/usr/sbin/scutil", arguments: ["--dns"])
        async let ipv4Output = CommandRunner.output("/sbin/route", arguments: ["-n", "get", "-inet", "1.1.1.1"])
        async let ipv6Output = CommandRunner.output("/sbin/route", arguments: ["-n", "get", "-inet6", "2606:4700:4700::1111"])
        async let proxyOutput = CommandRunner.output("/usr/sbin/scutil", arguments: ["--proxy"])
        let (dns, ipv4, ipv6, proxy) = await (dnsOutput, ipv4Output, ipv6Output, proxyOutput)

        var details: [String] = []
        var englishDetails: [String] = []
        var complete = true
        var tunnelRouteFound = false
        var systemProxyEnabled = false

        if let dns {
            let summary = resolverSummary(dns)
            details.append("DNS：\(summary.chinese)")
            englishDetails.append("DNS: \(summary.english)")
        } else {
            complete = false
            details.append("DNS：读取失败")
            englishDetails.append("DNS: could not be read")
        }

        for (label, englishLabel, output) in [("IPv4 公网目标路由（1.1.1.1）", "IPv4 public-destination route (1.1.1.1)", ipv4), ("IPv6 公网目标路由（2606:4700:4700::1111）", "IPv6 public-destination route (2606:4700:4700::1111)", ipv6)] {
            if let output, let interface = routeInterface(output) {
                details.append("\(label)：\(interface)")
                englishDetails.append("\(englishLabel): \(interface)")
                if Self.isTunnelInterface(interface) { tunnelRouteFound = true }
            } else {
                details.append("\(label)：未检测到或不可用")
                englishDetails.append("\(englishLabel): unavailable or not detected")
            }
        }

        if let proxy {
            let summary = proxySummary(proxy)
            details.append("系统代理：\(summary.chinese)")
            englishDetails.append("System proxy: \(summary.english)")
            systemProxyEnabled = summary.enabled
        } else {
            complete = false
            details.append("系统代理：读取失败")
            englishDetails.append("System proxy: could not be read")
        }

        if systemProxyEnabled {
            details.append("系统代理已启用，列为风险信号；仍需结合公网路由判断")
            englishDetails.append("System proxy is enabled and is recorded as a risk signal; compare it with the public route")
        }
        if tunnelRouteFound {
            details.append("公网目标经隧道接口路由，作为风险信号")
            englishDetails.append("A public destination uses a tunnel interface and is counted as a risk signal")
        }
        details.append("仅展示配置和路由证据；不能单独证明全部流量的实际去向")
        englishDetails.append("Shows configuration and route evidence only; it cannot prove the actual path of all traffic")
        let hasRoute = ipv4.flatMap(routeInterface) != nil || ipv6.flatMap(routeInterface) != nil
        let status: CheckStatus = (systemProxyEnabled || tunnelRouteFound) ? .warning : (complete && hasRoute ? .pass : .unknown)
        return result(.routeProfile, status, details.joined(separator: "；"), english: englishDetails.joined(separator: "; "))
    }

    private static func resolverSummary(_ output: String) -> (chinese: String, english: String) {
        let blocks = output.components(separatedBy: "resolver #").dropFirst()
        var chineseEntries: [String] = []
        var englishEntries: [String] = []
        for block in blocks {
            let lines = block.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
            let servers = lines.compactMap { line -> String? in
                guard line.hasPrefix("nameserver["), let separator = line.firstIndex(of: ":") else { return nil }
                return line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            }
            let domains = lines.compactMap { line -> String? in
                guard line.range(of: #"^(domain|search domain\[[0-9]+\])\s*:"#, options: .regularExpression) != nil else { return nil }
                guard let separator = line.firstIndex(of: ":") else { return nil }
                let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
            guard !servers.isEmpty || !domains.isEmpty else { continue }
            var chineseEntry = servers.isEmpty ? "未配置 DNS 服务器" : servers.joined(separator: ", ")
            var englishEntry = servers.isEmpty ? "no DNS servers configured" : servers.joined(separator: ", ")
            if !domains.isEmpty {
                chineseEntry += " [搜索域：\(domains.joined(separator: ", "))]"
                englishEntry += " [search domains: \(domains.joined(separator: ", "))]"
            }
            if lines.contains(where: { $0.hasPrefix("if_index") || $0.hasPrefix("if_scope") }) {
                chineseEntry += " [接口限定]"
                englishEntry += " [scoped]"
            }
            if !chineseEntries.contains(chineseEntry) {
                chineseEntries.append(chineseEntry)
                englishEntries.append(englishEntry)
            }
        }
        guard !chineseEntries.isEmpty else {
            return ("未发现已配置的解析器", "no configured resolver was found")
        }
        let shownChinese = chineseEntries.prefix(6).joined(separator: "；")
        let shownEnglish = englishEntries.prefix(6).joined(separator: "; ")
        let extraCount = max(chineseEntries.count - 6, 0)
        let extra = extraCount > 0 ? "；另有 \(extraCount) 项" : ""
        let englishExtra = extraCount > 0 ? "; and \(extraCount) more" : ""
        return (shownChinese + extra, shownEnglish + englishExtra)
    }

    private static func routeInterface(_ output: String) -> String? {
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("interface:"), let separator = trimmed.firstIndex(of: ":") else { continue }
            let value = trimmed[trimmed.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
        return nil
    }

    private static func proxySummary(_ output: String) -> (chinese: String, english: String, enabled: Bool) {
        var values: [String: String] = [:]
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let separator = trimmed.firstIndex(of: ":") else { continue }
            let key = trimmed[..<separator].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            values[key] = value
        }
        let kinds: [(String, String, String)] = [
            ("HTTPEnable", "HTTP", "HTTP"),
            ("HTTPSEnable", "HTTPS", "HTTPS"),
            ("SOCKSEnable", "SOCKS", "SOCKS"),
            ("ProxyAutoConfigEnable", "PAC", "PAC"),
            ("ProxyAutoDiscoveryEnable", "自动发现", "auto-discovery"),
        ]
        let enabled = kinds.compactMap { key, _, english in isEnabled(values[key]) ? english : nil }
        let enabledChinese = kinds.compactMap { key, chinese, _ in isEnabled(values[key]) ? chinese : nil }
        if enabled.isEmpty {
            return ("未发现已启用的系统代理", "no enabled system proxy was found", false)
        }
        return ("已启用：\(enabledChinese.joined(separator: ", "))", "enabled: \(enabled.joined(separator: ", "))", true)
    }

    private static func isTunnelInterface(_ name: String) -> Bool {
        name.range(of: #"^(utun\d+|tun\d*|tap\d*|ipsec\d+|ppp\d+)$"#, options: .regularExpression) != nil
    }

    private static func isEnabled(_ rawValue: String?) -> Bool {
        guard let rawValue else { return false }
        return rawValue == "1" || rawValue.lowercased() == "true"
    }

    private static func result(_ id: CheckID, _ status: CheckStatus, _ detail: String, english englishDetail: String) -> CheckResult {
        CheckResult(id: id, status: status, detail: detail, englishDetail: englishDetail, observedAt: .now)
    }
}

enum CommandRunner {
    static func output(_ executable: String, arguments: [String], timeout: TimeInterval = 5) async -> String? {
        let execution = CommandExecution()
        return await withTaskCancellationHandler {
            await Task.detached(priority: .utility) {
                execution.run(executable, arguments: arguments, timeout: timeout)
            }.value
        } onCancel: {
            execution.cancel()
        }
    }
}

private final class CommandExecution: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var wasCancelled = false
    private var didTimeOut = false

    func run(_ executable: String, arguments: [String], timeout: TimeInterval) -> String? {
        let pipe = Pipe()
        let child = Process()
        child.executableURL = URL(fileURLWithPath: executable)
        child.arguments = arguments
        child.standardOutput = pipe
        child.standardError = FileHandle.nullDevice

        lock.lock()
        guard !wasCancelled else {
            lock.unlock()
            return nil
        }
        process = child
        do {
            try child.run()
        } catch {
            process = nil
            lock.unlock()
            return nil
        }
        lock.unlock()

        let timeoutWork = DispatchWorkItem { [weak self] in
            self?.cancel(didTimeOut: true)
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: timeoutWork)

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        timeoutWork.cancel()

        lock.lock()
        let wasInterrupted = wasCancelled || didTimeOut
        process = nil
        lock.unlock()
        guard !wasInterrupted, child.terminationStatus == 0 else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func cancel(didTimeOut: Bool = false) {
        lock.lock()
        if didTimeOut {
            self.didTimeOut = true
        } else {
            wasCancelled = true
        }
        let child = process
        lock.unlock()

        guard let child, child.isRunning else { return }
        child.terminate()
        let processID = child.processIdentifier
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1) {
            if child.isRunning {
                _ = Darwin.kill(processID, SIGKILL)
            }
        }
    }
}
