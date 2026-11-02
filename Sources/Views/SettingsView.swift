import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: AppModel
    @State private var routeDomainsDraft = ""
    @State private var reachabilityURLsDraft = ""

    var body: some View {
        NavigationStack {
        Form {
            Section("界面语言") {
                Picker("界面语言", selection: $model.interfaceLanguage) {
                    ForEach(InterfaceLanguage.allCases) { language in
                        Text(LocalizedStringKey(language.titleKey)).tag(language)
                    }
                }
                .pickerStyle(.segmented)
            }

            Section("预期环境") {
                TextField("国家 / 地区代码", text: $model.settings.expectedCountryCode)
                    .textCase(.uppercase)
                    .help("例如 US、GB、JP。留空时优先参考出口 IP 的地区。")
                TextField("预期时区", text: $model.settings.expectedTimeZoneID)
                    .help("例如 America/Los_Angeles。留空时参考出口 IP 的时区。")
                TextField("预期系统地区格式", text: $model.settings.expectedLocaleIdentifier)
                    .help("例如 en_US、ja_JP；留空时可参考出口地区。")
            }

            Section("本机代理") {
                Picker("代理客户端", selection: $model.settings.proxyClient) {
                    ForEach(ProxyClient.allCases) { client in
                        Text(LocalizedStringKey(client.title)).tag(client)
                    }
                }
                Text("发现代理客户端、系统代理或隧道接口时会记录为风险信号；进程检测只读取本机进程，不能单独证明实际流量路径。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("DNS 与路由") {
                TextField("DNS 测试域名", text: $model.settings.dnsTestDomain)
                    .help("只填写主机名，例如 example.com。")
                TextField("预期虚拟 IP 网段", text: $model.settings.fakeIPCIDR)
                    .font(.system(.body, design: .monospaced))
                VStack(alignment: .leading, spacing: 7) {
                    Text("路由测试域名（每行一个）")
                        .font(.callout)
                    TextEditor(text: $routeDomainsDraft)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 72, maxHeight: 120)
                        .scrollContentBackground(.hidden)
                        .padding(5)
                        .overlay(RoundedRectangle(cornerRadius: 7).stroke(.quaternary))
                    Text("每次最多检查 20 个域名的 DNS / Fake-IP 表现；不读取代理凭据，也不能确认客户端策略组的最终去向。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("HTTPS 可达性") {
                TextEditor(text: $reachabilityURLsDraft)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 66, maxHeight: 110)
                    .scrollContentBackground(.hidden)
                    .padding(5)
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(.quaternary))
                Text("每行填写一个 HTTPS 地址，最多检查 10 个。默认使用 Cloudflare，你可以替换成自己的测试站点。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("监测") {
                Stepper(value: $model.settings.intervalSeconds, in: 30...900, step: 30) {
                    HStack {
                        Text("自动检测间隔")
                        Spacer()
                        Text("\(model.settings.intervalSeconds) 秒")
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                }
                Text("默认 60 秒。停止监测或关闭窗口后不会继续在后台运行。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("网络请求与本地数据") {
                Text("GeoIP 查询：Cloudflare Trace、ipinfo.io、ipapi.co。IP 信誉与网络类型查询：IPfastcheck；会提交取得的公网出口地址（包括可获取的 IPv4 / IPv6），服务说明记录最长保留 180 天。IPv4 / IPv6 出口：api.ipify.org、api6.ipify.org。手动 DNS 解析器测试使用 dnsleak.dev 的一次性随机主机名；服务可看到出口 IP 和查询其权威服务器的解析器地址。内嵌 WebKit ICE 探测访问 Google 与 Cloudflare STUN，只描述本应用，不代表 Safari 或 Chrome。HK/MO/TW 与中国大陆 CN 分开显示；GeoIP 不能证明物理位置。")
                    .fixedSize(horizontal: false, vertical: true)
                Text("位置比较只在手动点击专用按钮并授权后使用 macOS 定位服务；坐标只在本机内存中比较，不会发送给 GeoIP 服务或保存。距离和 IP 位置都是估算值。")
                    .fixedSize(horizontal: false, vertical: true)
                Text("IP 信誉分和网络类型来自第三方服务，结果可能不完整或误判；这不是通用安全评分，也不预测特定网站的处理结果。本机规则与第三方结果只保存在当前检测内存中，不上传检测报告。出口 IP 变化历史只保存在本机，保留 48 小时，可在主界面清除。")
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .navigationTitle(Text(verbatim: model.interfaceLanguage.usesEnglish ? "Settings" : "设置"))
        .padding(20)
        .frame(minWidth: 620, minHeight: 640)
        .environment(\.locale, model.interfaceLocale)
        .onAppear {
            routeDomainsDraft = model.settings.routeDomains.joined(separator: "\n")
            reachabilityURLsDraft = model.settings.reachabilityURLs.joined(separator: "\n")
        }
        .onChange(of: routeDomainsDraft) { value in
            model.settings.routeDomains = Self.lines(from: value)
        }
        .onChange(of: reachabilityURLsDraft) { value in
            model.settings.reachabilityURLs = Self.lines(from: value)
        }
        }
    }

    private static func lines(from value: String) -> [String] {
        value.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}
