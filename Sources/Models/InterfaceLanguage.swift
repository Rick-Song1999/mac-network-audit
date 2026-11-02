import Foundation

enum InterfaceLanguage: String, CaseIterable, Codable, Identifiable, Sendable {
    case system
    case simplifiedChinese
    case english

    var id: String { rawValue }

    var titleKey: String {
        switch self {
        case .system: "跟随系统"
        case .simplifiedChinese: "简体中文"
        case .english: "English"
        }
    }

    var usesEnglish: Bool {
        switch self {
        case .english:
            return true
        case .simplifiedChinese:
            return false
        case .system:
            let preferred = Locale.preferredLanguages.first ?? Locale.current.identifier
            return !preferred.lowercased().hasPrefix("zh")
        }
    }

    var locale: Locale {
        Locale(identifier: usesEnglish ? "en" : "zh-Hans")
    }
}
