import Foundation

struct AuditEngine: Sendable {
    private let networkChecks = NetworkChecks()

    func runAll(settings: MonitorSettings, history: HistoryStore, includeDeepChecks: Bool) async -> [CheckResult] {
        let snapshot = await networkChecks.collectSnapshot()
        var results: [CheckResult] = []

        for id in CheckID.allCases {
            if Task.isCancelled { break }
            if id == .locationProximity { continue }
            if !includeDeepChecks && (id == .dnsLeak || id == .webkitProfile) { continue }
            results.append(await networkChecks.run(id, settings: settings, history: history, snapshot: snapshot))
        }
        return results
    }

    func compareDeviceLocation(_ sample: DeviceLocationSample) async -> CheckResult {
        await networkChecks.compareDeviceLocation(sample)
    }
}
