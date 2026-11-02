import Foundation

enum DNSLeakProbe {
    private struct NewTest: Decodable, Sendable {
        var testId: String
        var hostnames: [String]
    }

    private struct GroupSummary {
        var label: String?
        var status: String?
        var addresses: [String]
    }

    private struct Report {
        var status: String
        var lookups: Int
        var groups: [GroupSummary]
    }

    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 10
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.waitsForConnectivity = false
        return URLSession(configuration: configuration, delegate: NoRedirectDelegate.shared, delegateQueue: nil)
    }()

    static func run() async -> CheckResult {
        guard let test = await startTest() else {
            return result(.unknown, "DNS 测试服务未返回有效响应", english: "The DNS test service did not return a valid response.")
        }
        guard validTestID(test.testId),
              (2...24).contains(test.hostnames.count),
              test.hostnames.allSatisfy(validHostname) else {
            return result(.unknown, "DNS 测试服务返回的编号或主机名列表格式无效", english: "The DNS test service returned an invalid test ID or hostname list.")
        }

        let resolveResults = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for hostname in test.hostnames {
                group.addTask {
                    guard !Task.isCancelled else { return false }
                    return await CommandRunner.output(
                        "/usr/bin/dscacheutil",
                        arguments: ["-q", "host", "-a", "name", hostname],
                        timeout: 5
                    ) != nil
                }
            }
            var results: [Bool] = []
            for await resolved in group { results.append(resolved) }
            return results
        }

        guard !Task.isCancelled else {
            return result(.unknown, "DNS 检测已取消", english: "The DNS check was cancelled.")
        }
        let attempted = resolveResults.filter { $0 }.count
        guard attempted == test.hostnames.count else {
            return result(.unknown, "系统解析器请求未全部完成：\(attempted)/\(test.hostnames.count)", english: "System-resolver requests did not all complete: \(attempted)/\(test.hostnames.count).")
        }

        var report: Report?
        for attempt in 0..<3 {
            if attempt > 0 {
                do { try await Task.sleep(for: .milliseconds(750)) } catch { break }
            }
            guard !Task.isCancelled, let current = await fetchReport(testID: test.testId) else { continue }
            report = current
            if current.lookups >= test.hostnames.count { break }
        }

        guard let report else {
            return result(.unknown, "测试查询已发出，但无法读取权威 DNS 观察结果", english: "Test queries were sent, but the authoritative DNS observations could not be retrieved.")
        }

        let groupsChinese = describeGroups(report.groups, english: false)
        let groupsEnglish = describeGroups(report.groups, english: true)
        let completeness = "已观察到 \(report.lookups)/\(test.hostnames.count) 个查询"
        let englishCompleteness = "\(report.lookups)/\(test.hostnames.count) queries observed"
        guard report.lookups >= test.hostnames.count else {
            return result(.unknown, "\(completeness)；数据未完整，解析器观察：\(groupsChinese)", english: "\(englishCompleteness); the result is incomplete. Resolver observations: \(groupsEnglish).")
        }

        switch report.status.lowercased() {
        case "split":
            return result(.warning, "观察到解析请求分流；\(completeness)；解析器：\(groupsChinese)", english: "A split resolver result was observed; \(englishCompleteness); resolvers: \(groupsEnglish).")
        case "no_leak":
            return result(.pass, "本轮未观察到 split；这不代表所有 DNS 查询都绝无泄漏。\(completeness)；解析器：\(groupsChinese)", english: "No split was observed in this run; this does not prove that all DNS queries are leak-free. \(englishCompleteness); resolvers: \(groupsEnglish).")
        case "inconclusive":
            return result(.unknown, "服务无法根据本轮观测作出判断；\(completeness)；解析器：\(groupsChinese)", english: "The service could not determine a result from this run; \(englishCompleteness); resolvers: \(groupsEnglish).")
        default:
            return result(.unknown, "服务返回未识别状态“\(report.status)”；\(completeness)；解析器：\(groupsChinese)", english: "The service returned an unrecognized status (\(report.status)); \(englishCompleteness); resolvers: \(groupsEnglish).")
        }
    }

    private static func startTest() async -> NewTest? {
        guard let url = URL(string: "https://dnsleak.dev/api/new") else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 8
        guard let (data, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode) else { return nil }
        return try? JSONDecoder().decode(NewTest.self, from: data)
    }

    private static func fetchReport(testID: String) async -> Report? {
        guard validTestID(testID),
              var components = URLComponents(string: "https://dnsleak.dev") else { return nil }
        components.path = "/api/result/\(testID)"
        guard let url = components.url else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 8
        guard let (data, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let verdict = root["verdict"] as? [String: Any],
              let status = verdict["status"] as? String else { return nil }

        let lookups = (root["lookups"] as? NSNumber)?.intValue ?? 0
        let groups = (root["groups"] as? [[String: Any]] ?? []).map { group in
            let members = group["members"] as? [Any] ?? []
            let addresses = members.compactMap { member -> String? in
                if let address = member as? String { return address }
                if let member = member as? [String: Any] {
                    return member["ip"] as? String ?? member["address"] as? String
                }
                return nil
            }
            return GroupSummary(
                label: group["label"] as? String,
                status: group["status"] as? String,
                addresses: addresses
            )
        }
        return Report(status: status, lookups: lookups, groups: groups)
    }

    private static func describeGroups(_ groups: [GroupSummary], english: Bool) -> String {
        guard !groups.isEmpty else { return english ? "none reported" : "暂无解析器分组" }
        return groups.prefix(8).map { group in
            let label = group.label ?? (english ? "Unknown resolver" : "未知解析器")
            let addresses = group.addresses.isEmpty ? "" : " (\(group.addresses.prefix(3).joined(separator: ", ")))"
            let state = group.status.map { " · \(displayStatus($0, english: english))" } ?? ""
            return "\(label)\(addresses)\(state)"
        }.joined(separator: english ? "; " : "；")
    }

    private static func displayStatus(_ status: String, english: Bool) -> String {
        guard !english else { return status }
        return switch status.lowercased() {
        case "matched": "同网络"
        case "same-country": "同国家 / 地区"
        case "operator": "公共解析器"
        case "foreign": "不同国家 / 地区"
        case "minority": "少数分流"
        case "observer": "旁观者（非本轮解析器）"
        case "unknown": "未知"
        default: status
        }
    }

    private static func validTestID(_ value: String) -> Bool {
        value.range(of: #"^[A-Za-z0-9_-]{8,120}$"#, options: .regularExpression) != nil
    }

    private static func validHostname(_ value: String) -> Bool {
        let hostname = value.lowercased()
        guard hostname.hasSuffix(".t.dnsleak.dev"), hostname.count <= 253 else { return false }
        let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
        // Documented names are <test-id>-aNN.t.dnsleak.dev or <test-id>-qNN.t.dnsleak.dev.
        guard labels.count >= 4 else { return false }
        return labels.allSatisfy { label in
            !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-"
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }

    private static func result(_ status: CheckStatus, _ detail: String, english: String) -> CheckResult {
        CheckResult(id: .dnsLeak, status: status, detail: detail, englishDetail: english, observedAt: .now)
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
