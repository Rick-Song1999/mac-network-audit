# macOS Network Risk Monitor

A native SwiftUI app for monitoring network and system-environment risk signals. It is independent of Claude and proxy-client products. It targets macOS 13 and later; the current Xcode project is configured for Apple Silicon (`arm64`). It runs as the current user and needs no administrator privileges, Python runtime, extra framework, or background daemon. It does not start or manage other apps, or change proxy, DNS, routes, time zone, or system-region settings.

[简体中文](README.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

## Get and build

This repository contains source code. There is currently no prebuilt or notarized release. Build with Xcode 16 or later:

1. Open `MacNetworkAudit.xcodeproj`.
2. Select the `MacNetworkAudit` scheme and your Mac as the run destination.
3. Click Run, or use Product → Build.

The minimum deployment target is macOS 13. The project currently targets Apple Silicon (`arm64`) only. Local app bundles and archives are written to `build/` and are not committed to Git.

## Checks

| Check | Method and limits |
|---|---|
| Proxy process | Reads the process list and flags commonly used proxy clients as a risk signal. A running process does not prove that all traffic passes through it. |
| TUN interface | Looks for active tunnel interfaces. A tunnel is a risk signal and should be considered together with egress IP and routes. |
| Public IP egress | Queries Cloudflare Trace, falling back to ipinfo.io when needed. |
| IP consistency | Compares with this Mac's recent 48-hour history; history is saved only when the IP changes. |
| Time zone | Compares the system time zone with the time zone associated with the public IP, and checks an optional expected time zone. |
| System region and language | Compares the system region and region tags in preferred languages with the public-IP country/region. A language without a region tag is not used to infer location. |
| Mac sales-region code | Reads the Apple platform region code. `CH/A` is treated as a China-related sales-region risk signal; `LL/A` is treated as a non-China sales region and passes regardless of the configured expected country. Unknown codes remain inconclusive. A code is only a sales-channel reference, not proof of current location or purchase history. |
| Approximate device and IP location | Requires a separate click and macOS Location Services permission. One approximate location is compared in memory with IP geolocation from ipinfo.io and ipapi.co; device coordinates are not sent to those services or saved. Only an approximate distance is shown. GeoIP or location errors and conflicting sources can make the result inconclusive; distance alone does not confirm a leak. |
| IPv6 egress | Uses an IPv6-specific egress probe. Detecting IPv6 is not itself a leak; region attribution requires an expected region. |
| Fake-IP DNS | Resolves a user-entered domain through the system resolver and compares the result with an expected Fake-IP range. |
| WebRTC / STUN | Sends UDP Binding requests to Google and Cloudflare STUN servers and compares mapped addresses with HTTP egress. Missing responses do not count as a pass. |
| Route behavior | Checks DNS/Fake-IP behavior for up to 20 user-entered domains. It cannot read a proxy controller's policy groups or verify final routing decisions. |
| IP network type and ISP | Separately shows available IPv4/IPv6 ISP, organization, ASN, and third-party labels such as residential, mobile, or hosting. These labels do not prove the physical access method. |
| IP reputation | Shows IPfastcheck's risk score and flags for proxy, VPN, Tor, hosting, fraud, abuse, scam, and blocklists for available IPv4/IPv6 addresses. Its thresholds follow that service's own rules; a low score is not a universal safety rating. |
| Endpoint reachability | Sends a HEAD request to a configured HTTPS URL without following redirects. An HTTP response means the endpoint was reachable, not that its service works correctly. |
| Mainland-China egress attribution | Compares country/region results from Cloudflare Trace, ipinfo.io, and ipapi.co. A result is shown when at least two available sources agree. `CN` means mainland China; `HK`, `MO`, and `TW` are shown separately. This describes public-IP attribution, not the Mac's physical location. |
| Dual-stack egress | Gets IPv4 and IPv6 egress separately and compares their regions. Different addresses alone do not prove a leak. Missing address or region evidence is inconclusive. |
| DNS resolver path | During a manual full scan, obtains a one-time random hostname from dnsleak.dev, resolves it with the macOS system resolver, and reads the resolver group observed by the authoritative service. `split` is a risk signal; `no_leak` means no split was observed in that run. Partial results or service errors are inconclusive. |
| Route profile | Reads macOS `scutil --dns`, the interface used for routes to fixed public IPv4/IPv6 targets, and `scutil --proxy`. A system proxy or public route through a tunnel is shown as a risk signal; these observations alone cannot prove the path of all traffic. |
| WebKit profile | During a manual full scan, reads language, time zone, platform, and STUN `srflx` mappings from an embedded WKWebView and compares them with macOS and HTTP egress. It describes this app's embedded WebKit only, not Safari or Chrome, and does not expose private or mDNS candidates. |

DNS/Fake-IP, route-behavior, and endpoint checks require values in Settings. Endpoint reachability defaults to Cloudflare, and you can replace it with your own HTTPS test endpoint. Missing configuration or an unresponsive service is shown as “Needs setup” or “Inconclusive,” never as a pass.

See the [IPfastcheck API documentation](https://ipfastcheck.com/api) for its fields, risk categories, and cache behavior.

## Monitoring and local data

- Supports manual scans and periodic monitoring. The default interval is 60 seconds, configurable from 30 seconds to 15 minutes.
- A manual full scan runs regular and deep checks. Periodic monitoring runs quick checks and keeps the last DNS-resolver and WebKit deep-check results with their original timestamps. Device-location comparison runs only when you click its row and grant permission; it is not started by a full scan or periodic monitoring.
- Closing the main window or stopping monitoring stops the timer and current scan.
- Settings are stored in the current user's macOS preferences.
- IP-change history is stored at `~/Library/Application Support/MacNetworkAudit/egress-history.json`, retained for up to 48 hours, and can be cleared from the main window. The first scan establishes a baseline, so IP consistency is initially inconclusive.
- Successful IPfastcheck responses are cached in app memory for 24 hours; failed responses for 15 minutes. Result details show the service record date and when the app retrieved the data. Its API documentation says IP records may be cached by the service for up to 180 days.
- Subprocess probes have hard timeouts. Stopping monitoring or clearing history cancels the active scan; when clearing, the app waits for the active cycle to finish before deleting the history.
- Scan reports are not uploaded. Cloudflare Trace, ipinfo.io, ipapi.co, ipify, and IPfastcheck can see the public egress IP involved in each request. IPfastcheck receives available IPv4/IPv6 addresses; its API documentation says records may be retained for up to 180 days. The manual DNS test sends a random hostname query to dnsleak.dev, which can see the public IP and the resolver that queried its authoritative server; its API documentation says test results remain in memory for ten minutes. STUN probes contact Google and Cloudflare. The optional location comparison starts macOS Location Services only after you click and grant permission; device coordinates are not uploaded or saved and are compared in local memory with IP-based GeoIP estimates. DNS and WebKit probe details stay in app memory and are not written to the 48-hour IP history.
- Risk levels combine local observations with third-party IP data. They are not universal safety scores and do not predict how a particular website will treat a connection. IP geolocation, network-type labels, and risk scores can be inaccurate.

The current local build is ad-hoc signed and is not notarized with a Developer ID certificate.

## License

This project is licensed under the MIT License. Some monitoring logic was adapted with reference to an upstream project; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and the preserved upstream license.
