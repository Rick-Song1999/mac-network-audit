import Foundation

enum CheckStatus: String, Codable, Sendable {
    case pass
    case warning
    case failure
    case unknown
    case needsConfiguration

    var title: String {
        switch self {
        case .pass: "通过"
        case .warning: "风险信号"
        case .failure: "高风险"
        case .unknown: "无法判断"
        case .needsConfiguration: "待配置"
        }
    }
}

struct CheckResult: Identifiable, Codable, Sendable {
    var id: CheckID
    var status: CheckStatus
    var detail: String
    var englishDetail: String
    var observedAt: Date

    func displayDetail(for language: InterfaceLanguage) -> String {
        language.usesEnglish ? englishDetail : detail
    }

    static func initial(_ id: CheckID) -> CheckResult {
        CheckResult(id: id, status: .unknown, detail: "尚未检测", englishDetail: "Not checked yet", observedAt: .distantPast)
    }
}
