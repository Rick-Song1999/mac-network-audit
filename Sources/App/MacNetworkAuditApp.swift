import SwiftUI

@main
struct MacNetworkAuditApp: App {
    @StateObject private var model: AppModel

    init() {
        _model = StateObject(wrappedValue: AppModel())
    }

    var body: some Scene {
        WindowGroup(model.interfaceLanguage.usesEnglish ? "Network Risk Monitor" : "网络风险监测") {
            DashboardView(model: model)
                .frame(minWidth: 860, minHeight: 700)
                .environment(\.locale, model.interfaceLocale)
        }
        .windowResizability(.contentSize)

        Window(model.interfaceLanguage.usesEnglish ? "Settings" : "设置", id: "settings") {
            SettingsView(model: model)
                .environment(\.locale, model.interfaceLocale)
        }
    }
}
