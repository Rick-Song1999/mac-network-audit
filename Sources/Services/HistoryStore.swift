import Foundation

struct EgressObservation: Codable, Equatable, Sendable {
    var ip: String
    var observedAt: Date
}

struct EgressHistorySummary: Sendable {
    var previousIP: String?
    var changeCount: Int
}

actor HistoryStore {
    private let fileURL: URL
    private let maximumAge: TimeInterval = 48 * 60 * 60
    private let maximumEntries = 6_000
    private var observations: [EgressObservation]

    init(directoryURL: URL? = nil) {
        let supportDirectory = directoryURL ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MacNetworkAudit", isDirectory: true)
        fileURL = supportDirectory.appendingPathComponent("egress-history.json")
        let loaded = Self.load(from: fileURL)
        let trimmed = Self.trim(loaded, keepingSince: .now.addingTimeInterval(-maximumAge))
        observations = trimmed
        if trimmed != loaded {
            Self.persist(trimmed, to: fileURL)
        }
    }

    func recordAndCompare(ip: String, since cutoff: Date, at date: Date = .now) -> EgressHistorySummary {
        let normalized = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else {
            return EgressHistorySummary(previousIP: nil, changeCount: 0)
        }
        let trimmed = Self.trim(observations, keepingSince: date.addingTimeInterval(-maximumAge))
        let didTrim = trimmed != observations
        observations = trimmed

        let previous = observations.last(where: { $0.observedAt >= cutoff })
        if observations.last?.ip != normalized || observations.last.map({ $0.observedAt < cutoff }) == true {
            observations.append(EgressObservation(ip: normalized, observedAt: date))
            if observations.count > maximumEntries {
                observations.removeFirst(observations.count - maximumEntries)
            }
            Self.persist(observations, to: fileURL)
        } else if didTrim {
            Self.persist(observations, to: fileURL)
        }

        let recentCount = observations.lazy.filter { $0.observedAt >= cutoff }.count
        return EgressHistorySummary(
            previousIP: previous?.ip,
            changeCount: max(0, recentCount - 1)
        )
    }

    func clear() {
        observations.removeAll()
        try? FileManager.default.removeItem(at: fileURL)
    }

    private static func trim(_ entries: [EgressObservation], keepingSince cutoff: Date) -> [EgressObservation] {
        entries.filter { $0.observedAt >= cutoff }
    }

    private static func persist(_ observations: [EgressObservation], to fileURL: URL) {
        do {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(observations)
            try data.write(to: fileURL, options: .atomic)
        } catch {
            // Monitoring remains usable in memory when local persistence is unavailable.
        }
    }

    private static func load(from url: URL) -> [EgressObservation] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([EgressObservation].self, from: data)) ?? []
    }
}
