import Combine
import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var results: [CheckID: CheckResult] = Dictionary(
        uniqueKeysWithValues: CheckID.allCases.map { ($0, .initial($0)) }
    )
    @Published private(set) var latestCycleCheckIDs = Set(CheckID.allCases)
    @Published private(set) var isChecking = false
    @Published private(set) var isLocationChecking = false
    @Published private(set) var isMonitoring = false
    @Published private(set) var isClearingHistory = false
    @Published private(set) var lastRun: Date?
    @Published var settings: MonitorSettings {
        didSet { saveSettings() }
    }
    @Published var interfaceLanguage: InterfaceLanguage {
        didSet { UserDefaults.standard.set(interfaceLanguage.rawValue, forKey: Self.languageKey) }
    }

    var interfaceLocale: Locale { interfaceLanguage.locale }

    private let history: HistoryStore
    private let engine = AuditEngine()
    private var cycleTask: Task<Void, Never>?
    private var monitorTask: Task<Void, Never>?
    private var locationTask: Task<Void, Never>?
    private var locationProbe: DeviceLocationProbe?

    init() {
        history = HistoryStore()
        interfaceLanguage = InterfaceLanguage(rawValue: UserDefaults.standard.string(forKey: Self.languageKey) ?? "") ?? .system
        if let data = UserDefaults.standard.data(forKey: Self.settingsKey),
           let saved = try? JSONDecoder().decode(MonitorSettings.self, from: data) {
            settings = saved
            settings.intervalSeconds = min(max(settings.intervalSeconds, 30), 900)
        } else {
            settings = MonitorSettings()
        }
    }

    func runOnce() {
        guard !isLocationChecking else { return }
        launchCycle(includeDeepChecks: true)
    }

    func compareDeviceLocation() {
        guard !isChecking, !isLocationChecking, !isClearingHistory else { return }
        isLocationChecking = true
        latestCycleCheckIDs.insert(.locationProximity)
        results[.locationProximity] = CheckResult(
            id: .locationProximity,
            status: .unknown,
            detail: "正在请求一次 macOS 近似位置；坐标仅用于本机内存中的距离比较。",
            englishDetail: "Requesting one approximate macOS location; coordinates are used only for an in-memory comparison on this Mac.",
            observedAt: .now
        )

        let probe = DeviceLocationProbe()
        locationProbe = probe
        locationTask = Task { [weak self] in
            let outcome = await probe.requestOneShot()
            guard let self, !Task.isCancelled else { return }

            let result: CheckResult
            switch outcome {
            case .sample(let sample):
                result = await engine.compareDeviceLocation(sample)
            case .denied:
                result = CheckResult(
                    id: .locationProximity,
                    status: .unknown,
                    detail: "未获得 macOS 定位权限。可在“系统设置 → 隐私与安全性 → 定位服务”中允许后重试。",
                    englishDetail: "Location permission was not granted. Allow it in System Settings → Privacy & Security → Location Services, then try again.",
                    observedAt: .now
                )
            case .unavailable:
                result = CheckResult(
                    id: .locationProximity,
                    status: .unknown,
                    detail: "macOS 未能提供精度足够的新位置；这不代表 IP 与设备位置一致。",
                    englishDetail: "macOS could not provide a recent location with sufficient accuracy; this does not mean the IP and device locations match.",
                    observedAt: .now
                )
            case .cancelled:
                result = CheckResult(
                    id: .locationProximity,
                    status: .unknown,
                    detail: "位置比较已取消。",
                    englishDetail: "The location comparison was cancelled.",
                    observedAt: .now
                )
            }

            guard !Task.isCancelled else { return }
            results[.locationProximity] = result
            isLocationChecking = false
            locationProbe = nil
            locationTask = nil
        }
    }

    func cancelLocationCheck() {
        guard isLocationChecking else { return }
        locationProbe?.cancel()
        locationTask?.cancel()
        results[.locationProximity] = CheckResult(
            id: .locationProximity,
            status: .unknown,
            detail: "位置比较已取消。",
            englishDetail: "The location comparison was cancelled.",
            observedAt: .now
        )
        isLocationChecking = false
        locationProbe = nil
        locationTask = nil
    }

    func startMonitoring() {
        guard !isMonitoring, !isLocationChecking else { return }
        isMonitoring = true
        launchCycle(includeDeepChecks: false)

        monitorTask = Task { [weak self] in
            while let self, !Task.isCancelled, self.isMonitoring {
                do {
                    try await Task.sleep(for: .seconds(self.settings.intervalSeconds))
                } catch {
                    break
                }
                guard self.isMonitoring, !Task.isCancelled else { break }
                self.launchCycle(includeDeepChecks: false)
            }
        }
    }

    func stopMonitoring() {
        isMonitoring = false
        monitorTask?.cancel()
        monitorTask = nil
        cycleTask?.cancel()
    }

    func clearHistory() {
        guard !isClearingHistory else { return }
        isClearingHistory = true
        cycleTask?.cancel()
        let activeCycle = cycleTask
        Task { [weak self] in
            await activeCycle?.value
            guard let self else { return }
            await history.clear()
            results[.ipConsistency] = CheckResult(
                id: .ipConsistency,
                status: .unknown,
                detail: "本地历史已清除；下一轮检测将重新记录",
                englishDetail: "Local history was cleared; it will be recorded again on the next check.",
                observedAt: .now
            )
            isClearingHistory = false
        }
    }

    private func launchCycle(includeDeepChecks: Bool) {
        guard !isChecking, !isLocationChecking, !isClearingHistory else { return }
        isChecking = true
        let currentSettings = settings
        cycleTask = Task { [weak self] in
            guard let self else { return }
            let freshResults = await engine.runAll(settings: currentSettings, history: history, includeDeepChecks: includeDeepChecks)
            guard !Task.isCancelled else {
                isChecking = false
                cycleTask = nil
                return
            }
            for result in freshResults {
                results[result.id] = result
            }
            latestCycleCheckIDs = Set(freshResults.map(\.id))
            lastRun = .now
            isChecking = false
            cycleTask = nil
        }
    }

    private func saveSettings() {
        guard let data = try? JSONEncoder().encode(settings) else { return }
        UserDefaults.standard.set(data, forKey: Self.settingsKey)
    }

    private static let settingsKey = "MacNetworkAudit.monitorSettings.v1"
    private static let languageKey = "MacNetworkAudit.interfaceLanguage.v1"
}
