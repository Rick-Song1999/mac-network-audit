import SwiftUI

struct DashboardView: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var model: AppModel
    @State private var confirmsHistoryClear = false

    private var summaryText: LocalizedStringKey {
        if model.isChecking { return "正在检测" }
        if model.isMonitoring { return "持续监测中" }
        if model.lastRun == nil { return "尚未检测" }
        return "检测完成"
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ScrollView {
                VStack(spacing: 16) {
                    privacyNotice
                    riskDisclaimer
                    deepChecksNotice
                    locationPrivacyNotice
                    summary
                    checks
                    controls
                }
                .padding(22)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .navigationTitle(model.interfaceLanguage.usesEnglish ? "Network Risk Monitor" : "网络风险监测")
        .confirmationDialog(
            "清除本地出口 IP 历史？",
            isPresented: $confirmsHistoryClear,
            titleVisibility: .visible
        ) {
            Button("清除历史", role: .destructive) { model.clearHistory() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("只会删除本应用保留的出口 IP 变化记录。")
        }
        .onDisappear {
            model.stopMonitoring()
            model.cancelLocationCheck()
        }
        .environment(\.locale, model.interfaceLocale)
    }

    private var header: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 13)
                    .fill(Color.accentColor.opacity(0.13))
                    .frame(width: 46, height: 46)
                Image(systemName: "network")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(Color.accentColor)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text("网络风险监测")
                    .font(.title2.weight(.semibold))
                Text("IP 与系统环境一致性检查")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            HStack(spacing: 7) {
                Circle()
                    .fill(model.isMonitoring ? Color.green : Color.secondary.opacity(0.45))
                    .frame(width: 8, height: 8)
                Text(summaryText)
                    .font(.callout.weight(.medium))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(.quaternary.opacity(0.45), in: Capsule())
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
        .background(.regularMaterial)
        .overlay(alignment: .bottom) { Divider() }
    }

    private var privacyNotice: some View {
        Label {
            Text("出口 IP / GeoIP 查询访问 Cloudflare Trace、ipinfo.io、ipapi.co 和 ipify；IP 信誉查询会把取得的公网出口地址（包括可获取的 IPv4 / IPv6）发送给 IPfastcheck。相关服务可看到被查询的出口 IP。IPfastcheck 说明其 IP 记录可保留最长 180 天。手动 DNS 检查访问 dnsleak.dev，服务可观察到测试查询的解析器地址。STUN 探测访问 Google 与 Cloudflare。")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "hand.raised")
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(13)
        .background(Color.accentColor.opacity(0.07), in: RoundedRectangle(cornerRadius: 11))
    }

    private var riskDisclaimer: some View {
        Label("风险等级综合本机检查与第三方 IP 资料，不是通用安全评分，也不预测特定网站的处理结果。未发现风险信号不代表绝对安全。", systemImage: "info.circle")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var deepChecksNotice: some View {
        Label("DNS 解析器路径和 WebKit 深度检查只在手动点击“立即检测”时运行；定时监测会保留这些项目上次的结果和时间。", systemImage: "clock.badge.checkmark")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var locationPrivacyNotice: some View {
        Label("设备位置比较需单独点击并授权；只读取一次 macOS 近似位置，坐标仅在本机内存中比对，不会保存或发送给 GeoIP 服务。", systemImage: "location")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var summary: some View {
        HStack(spacing: 12) {
            summaryCard(title: "通过", status: .pass)
            summaryCard(title: "风险信号", status: .warning)
            summaryCard(title: "高风险", status: .failure)
            summaryCard(title: "待判断 / 配置", status: nil)
            Spacer(minLength: 4)
            VStack(alignment: .trailing, spacing: 4) {
                Text("上次检测")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(model.lastRun?.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened, locale: model.interfaceLocale)) ?? "—")
                    .font(.callout.monospacedDigit())
            }
        }
    }

    private func summaryCard(title: LocalizedStringKey, status: CheckStatus?) -> some View {
        let count = model.results.values.filter { result in
            guard model.latestCycleCheckIDs.contains(result.id) else { return false }
            if let status { return result.status == status }
            return result.status == .unknown || result.status == .needsConfiguration
        }.count
        let color = status.map(color(for:)) ?? .secondary
        return HStack(spacing: 8) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("\(count)")
                .font(.callout.weight(.semibold).monospacedDigit())
                .foregroundStyle(.primary)
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 9))
    }

    private var checks: some View {
        LazyVStack(spacing: 0) {
            ForEach(Array(CheckID.allCases.enumerated()), id: \.element.id) { index, check in
                checkRow(check, index: index)
                if index < CheckID.allCases.count - 1 {
                    Divider().padding(.leading, 54)
                }
            }
        }
        .padding(.horizontal, 16)
        .background(.background, in: RoundedRectangle(cornerRadius: 13))
        .overlay {
            RoundedRectangle(cornerRadius: 13)
                .strokeBorder(.quaternary, lineWidth: 1)
        }
    }

    private func checkRow(_ check: CheckID, index: Int) -> some View {
        let result = model.results[check] ?? .initial(check)
        return HStack(alignment: .top, spacing: 13) {
            Text(String(format: "%02d", index + 1))
                .font(.caption.monospacedDigit().weight(.medium))
                .foregroundStyle(.tertiary)
                .frame(width: 24, alignment: .leading)
                .padding(.top, 2)
            Image(systemName: symbol(for: result.status))
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(color(for: result.status))
                .frame(width: 20)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(LocalizedStringKey(check.title))
                        .font(.body.weight(.semibold))
                    Text(LocalizedStringKey(result.status.title))
                        .font(.caption.weight(.medium))
                        .foregroundStyle(color(for: result.status))
                }
                Text(result.displayDetail(for: model.interfaceLanguage))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if check == .locationProximity {
                    Button {
                        model.compareDeviceLocation()
                    } label: {
                        Label(
                            LocalizedStringKey(model.isLocationChecking ? "正在获取位置…" : "读取近似位置并比对"),
                            systemImage: model.isLocationChecking ? "location.circle" : "location.magnifyingglass"
                        )
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(model.isChecking || model.isLocationChecking || model.isClearingHistory)
                }
            }
            Spacer(minLength: 4)
            if result.observedAt != .distantPast {
                Text(result.observedAt.formatted(Date.FormatStyle(date: .omitted, time: .shortened, locale: model.interfaceLocale)))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.tertiary)
                    .padding(.top, 2)
            }
        }
        .padding(.vertical, 12)
    }

    private var controls: some View {
        HStack(spacing: 10) {
            Button {
                model.runOnce()
            } label: {
                Label(
                    LocalizedStringKey(model.isClearingHistory ? "正在清除…" : model.isChecking ? "检测中…" : "立即检测"),
                    systemImage: "arrow.clockwise"
                )
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isChecking || model.isLocationChecking || model.isClearingHistory)
            .keyboardShortcut("r", modifiers: [.command])

            Button {
                if model.isMonitoring {
                    model.stopMonitoring()
                } else {
                    model.startMonitoring()
                }
            } label: {
                Label(
                    LocalizedStringKey(model.isMonitoring ? "停止监测" : "开始监测"),
                    systemImage: model.isMonitoring ? "stop.fill" : "waveform.path"
                )
            }
            .buttonStyle(.bordered)
            .tint(model.isMonitoring ? .orange : .accentColor)
            .disabled(model.isLocationChecking)

            Button {
                openWindow(id: "settings")
            } label: {
                Label("设置", systemImage: "slider.horizontal.3")
            }
            .buttonStyle(.bordered)

            Button {
                confirmsHistoryClear = true
            } label: {
                Label("清除 IP 历史", systemImage: "trash")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .disabled(model.isLocationChecking)

            Spacer()
            Text("间隔 \(model.settings.intervalSeconds) 秒")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(.top, 2)
    }

    private func symbol(for status: CheckStatus) -> String {
        switch status {
        case .pass: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .failure: "xmark.octagon.fill"
        case .unknown: "questionmark.circle"
        case .needsConfiguration: "slider.horizontal.3"
        }
    }

    private func color(for status: CheckStatus) -> Color {
        switch status {
        case .pass: .green
        case .warning: .orange
        case .failure: .red
        case .unknown, .needsConfiguration: .secondary
        }
    }
}
