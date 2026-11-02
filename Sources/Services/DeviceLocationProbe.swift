@preconcurrency import CoreLocation
import Foundation

struct DeviceLocationSample: Sendable {
    var coordinate: GeoCoordinate
    var horizontalAccuracy: Double
    var timestamp: Date
}

enum DeviceLocationOutcome: Sendable {
    case sample(DeviceLocationSample)
    case denied
    case unavailable
    case cancelled
}

@MainActor
final class DeviceLocationProbe: NSObject, @preconcurrency CLLocationManagerDelegate {
    private var manager: CLLocationManager?
    private var continuation: CheckedContinuation<DeviceLocationOutcome, Never>?
    private var timeoutTask: Task<Void, Never>?
    private var hasRequestedOneShot = false

    func requestOneShot() async -> DeviceLocationOutcome {
        guard CLLocationManager.locationServicesEnabled() else { return .unavailable }

        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            let manager = CLLocationManager()
            self.manager = manager
            manager.desiredAccuracy = kCLLocationAccuracyThreeKilometers
            manager.delegate = self

            timeoutTask = Task { @MainActor [weak self] in
                do {
                    try await Task.sleep(for: .seconds(20))
                } catch {
                    return
                }
                self?.finish(.unavailable)
            }

            switch manager.authorizationStatus {
            case .authorizedAlways, .authorizedWhenInUse:
                requestLocationIfNeeded(manager)
            case .notDetermined:
                manager.requestWhenInUseAuthorization()
            case .denied, .restricted:
                finish(.denied)
            @unknown default:
                finish(.unavailable)
            }
        }
    }

    func cancel() {
        finish(.cancelled)
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            requestLocationIfNeeded(manager)
        case .denied, .restricted:
            finish(.denied)
        case .notDetermined:
            break
        @unknown default:
            finish(.unavailable)
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.last,
              location.horizontalAccuracy >= 0,
              let coordinate = GeoCoordinate.validated(
                latitude: location.coordinate.latitude,
                longitude: location.coordinate.longitude
              ) else {
            finish(.unavailable)
            return
        }
        finish(.sample(DeviceLocationSample(
            coordinate: coordinate,
            horizontalAccuracy: location.horizontalAccuracy,
            timestamp: location.timestamp
        )))
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        if let error = error as? CLError, error.code == .denied {
            finish(.denied)
        } else {
            finish(.unavailable)
        }
    }

    private func finish(_ outcome: DeviceLocationOutcome) {
        timeoutTask?.cancel()
        timeoutTask = nil
        manager?.delegate = nil
        manager = nil
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(returning: outcome)
    }

    private func requestLocationIfNeeded(_ manager: CLLocationManager) {
        guard !hasRequestedOneShot else { return }
        hasRequestedOneShot = true
        manager.requestLocation()
    }
}
