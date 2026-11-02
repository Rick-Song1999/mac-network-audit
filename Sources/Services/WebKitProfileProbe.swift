import Darwin
import Foundation
@preconcurrency import WebKit

struct WebKitProfileSnapshot: Sendable {
    var languages: [String]
    var platform: String?
    var timeZone: String?
    var publicICEAddresses: [String]
    var completed: Bool
    var error: String?
}

@MainActor
enum WebKitProfileProbe {
    static func run(timeout: TimeInterval = 16) async -> WebKitProfileSnapshot {
        let worker = WebKitProbeWorker()
        return await worker.run(timeout: timeout)
    }
}

@MainActor
private final class WebKitProbeWorker: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    private var webView: WKWebView?
    private var continuation: CheckedContinuation<WebKitProfileSnapshot, Never>?
    private var timeoutTask: Task<Void, Never>?

    func run(timeout: TimeInterval) async -> WebKitProfileSnapshot {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                self.continuation = continuation
                let configuration = WKWebViewConfiguration()
                configuration.websiteDataStore = .nonPersistent()
                configuration.userContentController.add(self, name: "audit")
                let view = WKWebView(frame: CGRect(x: 0, y: 0, width: 1, height: 1), configuration: configuration)
                view.navigationDelegate = self
                webView = view
                timeoutTask = Task { @MainActor [weak self] in
                    do { try await Task.sleep(for: .seconds(timeout)) } catch { return }
                    self?.finish(error: "Timed out while gathering WebKit ICE candidates")
                }
                view.loadHTMLString(Self.html, baseURL: URL(string: "https://network-audit.invalid"))
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.finish(error: "WebKit probe was cancelled")
            }
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any] else {
            finish(error: "WebKit returned an invalid profile payload")
            return
        }
        let languages = body["languages"] as? [String] ?? []
        let platform = body["platform"] as? String
        let timeZone = body["timeZone"] as? String
        let candidates = (body["publicCandidates"] as? [String] ?? []).filter(isPublicAddress)
        let error = body["error"] as? String
        let completed = (body["completed"] as? Bool) ?? false
        finish(snapshot: WebKitProfileSnapshot(
            languages: Array(languages.prefix(8)),
            platform: platform,
            timeZone: timeZone,
            publicICEAddresses: Array(Set(candidates)).sorted(),
            completed: completed,
            error: error
        ))
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finish(error: "WebKit page failed: \(error.localizedDescription)")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finish(error: "WebKit page could not start: \(error.localizedDescription)")
    }

    private func finish(snapshot: WebKitProfileSnapshot? = nil, error: String = "") {
        let value = snapshot ?? WebKitProfileSnapshot(
            languages: [],
            platform: nil,
            timeZone: nil,
            publicICEAddresses: [],
            completed: false,
            error: error
        )
        finish(value)
    }

    private func finish(_ snapshot: WebKitProfileSnapshot) {
        guard let continuation else { return }
        self.continuation = nil
        timeoutTask?.cancel()
        timeoutTask = nil
        webView?.stopLoading()
        webView?.navigationDelegate = nil
        webView?.configuration.userContentController.removeScriptMessageHandler(forName: "audit")
        webView = nil
        continuation.resume(returning: snapshot)
    }

    private func isPublicAddress(_ rawAddress: String) -> Bool {
        let address = rawAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard address.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else { return false }
        let octets = address.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt8($0) }
        if octets.count == 4, address.split(separator: ".", omittingEmptySubsequences: false).count == 4 {
            let (a, b, c, _) = (octets[0], octets[1], octets[2], octets[3])
            if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
            if a == 169 && b == 254 { return false }
            if a == 172 && (16...31).contains(b) { return false }
            if a == 192 && (b == 168 || (b == 0 && c == 0) || (b == 0 && c == 2)) { return false }
            if a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)) { return false }
            if a == 203 && b == 0 && c == 113 { return false }
            if a == 100 && (64...127).contains(b) { return false }
            return true
        }

        var parsed = in6_addr()
        guard address.withCString({ inet_pton(AF_INET6, $0, &parsed) == 1 }) else { return false }
        let bytes = withUnsafeBytes(of: parsed) { Array($0) }
        guard bytes.count == 16 else { return false }
        let allZero = bytes.allSatisfy { $0 == 0 }
        let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
        let ipv4Mapped = bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
        let isUniqueLocal = bytes[0] & 0xfe == 0xfc
        let isLinkLocal = bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
        let isGlobalUnicast = bytes[0] & 0xe0 == 0x20
        let isDocumentation = bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8
        return !allZero && !loopback && !ipv4Mapped && !isUniqueLocal && !isLinkLocal && isGlobalUnicast && !isDocumentation
    }

    private static let html = #"""
    <!doctype html>
    <html><head><meta charset="utf-8"></head><body>
    <script>
    (() => {
      const profile = {
        languages: Array.isArray(navigator.languages) ? navigator.languages : [navigator.language].filter(Boolean),
        platform: navigator.platform || "",
        timeZone: (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) { return ""; } })(),
        publicCandidates: [],
        completed: false,
        error: ""
      };
      const send = () => {
        if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.audit) {
          window.webkit.messageHandlers.audit.postMessage(profile);
        }
      };
      if (!window.RTCPeerConnection) {
        profile.error = "RTCPeerConnection is unavailable";
        send();
        return;
      }
      let finished = false;
      let peer;
      const finish = (error = "") => {
        if (finished) return;
        finished = true;
        profile.completed = !error;
        profile.error = error;
        try { peer && peer.close(); } catch (_) {}
        send();
      };
      try {
        peer = new RTCPeerConnection({ iceServers: [
          { urls: "stun:stun.l.google.com:19302" },
          { urls: "stun:stun.cloudflare.com:3478" }
        ] });
        peer.createDataChannel("audit");
        peer.onicecandidate = event => {
          if (!event.candidate) { finish(); return; }
          const candidate = event.candidate;
          let type = candidate.type || "";
          let address = candidate.address || "";
          if (!type || !address) {
            const fields = (candidate.candidate || "").split(/\s+/);
            const typeIndex = fields.indexOf("typ");
            if (!type && typeIndex >= 0) type = fields[typeIndex + 1] || "";
            if (!address && fields.length > 4) address = fields[4];
          }
          if (["host", "srflx", "prflx"].includes(type) && address && !address.toLowerCase().endsWith(".local") && !profile.publicCandidates.includes(address)) {
            profile.publicCandidates.push(address);
          }
        };
        peer.createOffer().then(offer => peer.setLocalDescription(offer)).catch(error => finish(String(error)));
        setTimeout(() => finish("ICE gathering timed out"), 10000);
      } catch (error) {
        finish(String(error));
      }
    })();
    </script></body></html>
    """#
}
