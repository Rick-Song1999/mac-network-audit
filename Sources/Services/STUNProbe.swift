import Foundation
@preconcurrency import Dispatch
import Network

enum STUNProbeError: LocalizedError {
    case timedOut
    case cancelled
    case invalidResponse
    case missingMappedAddress

    var errorDescription: String? {
        switch self {
        case .timedOut: "STUN 请求超时"
        case .cancelled: "STUN 请求已取消"
        case .invalidResponse: "STUN 响应格式无效"
        case .missingMappedAddress: "STUN 响应未包含映射地址"
        }
    }
}

enum STUNProbe {
    static func publicAddress(server: NWEndpoint.Host, port: NWEndpoint.Port, timeout: TimeInterval) async throws -> String {
        let connection = NWConnection(host: server, port: port, using: .udp)
        let queue = DispatchQueue(label: "com.codex.MacNetworkAudit.stun")
        let request = bindingRequest()
        let gate = ContinuationGate()

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let timeoutWork = DispatchWorkItem {
                    gate.resolve {
                        connection.cancel()
                        continuation.resume(throwing: STUNProbeError.timedOut)
                    }
                }

                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        connection.send(content: request, completion: .contentProcessed { error in
                            if let error {
                                gate.resolve {
                                    timeoutWork.cancel()
                                    connection.cancel()
                                    continuation.resume(throwing: error)
                                }
                                return
                            }
                            connection.receiveMessage { content, _, _, error in
                                gate.resolve {
                                    timeoutWork.cancel()
                                    connection.cancel()
                                    if let error {
                                        continuation.resume(throwing: error)
                                    } else if let content {
                                        do {
                                            let address = try parseBindingResponse(content, transactionID: Array(request[8..<20]))
                                            continuation.resume(returning: address)
                                        } catch {
                                            continuation.resume(throwing: error)
                                        }
                                    } else {
                                        continuation.resume(throwing: STUNProbeError.invalidResponse)
                                    }
                                }
                            }
                        })
                    case .failed(let error):
                        gate.resolve {
                            timeoutWork.cancel()
                            connection.cancel()
                            continuation.resume(throwing: error)
                        }
                    case .cancelled:
                        gate.resolve {
                            timeoutWork.cancel()
                            continuation.resume(throwing: STUNProbeError.cancelled)
                        }
                    default:
                        break
                    }
                }

                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout, execute: timeoutWork)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func bindingRequest() -> Data {
        var bytes: [UInt8] = [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42]
        bytes.append(contentsOf: (0..<12).map { _ in UInt8.random(in: 0...255) })
        return Data(bytes)
    }

    private static func parseBindingResponse(_ data: Data, transactionID: [UInt8]) throws -> String {
        guard data.count >= 20,
              readUInt16(data, at: 0) == 0x0101,
              readUInt32(data, at: 4) == 0x2112A442,
              Array(data[8..<20]) == transactionID else {
            throw STUNProbeError.invalidResponse
        }

        let messageLength = Int(readUInt16(data, at: 2))
        guard messageLength % 4 == 0,
              messageLength == data.count - 20 else { throw STUNProbeError.invalidResponse }
        let messageEnd = 20 + messageLength
        var offset = 20
        var mappedAddress: String?

        while offset + 4 <= messageEnd {
            let type = readUInt16(data, at: offset)
            let length = Int(readUInt16(data, at: offset + 2))
            let valueStart = offset + 4
            let valueEnd = valueStart + length
            guard valueEnd <= messageEnd else { throw STUNProbeError.invalidResponse }
            if type == 0x0020 || type == 0x0001 {
                guard length >= 4, data[valueStart] == 0 else { throw STUNProbeError.invalidResponse }
                let family = data[valueStart + 1]
                let xorAddress = type == 0x0020
                if family == 0x01, length == 8 {
                    var bytes = Array(data[(valueStart + 4)..<(valueStart + 8)])
                    if xorAddress {
                        let mask: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
                        bytes = zip(bytes, mask).map(^)
                    }
                    mappedAddress = bytes.map(String.init).joined(separator: ".")
                    if xorAddress { break }
                } else if family == 0x02, length == 20 {
                    var bytes = Array(data[(valueStart + 4)..<(valueStart + 20)])
                    if xorAddress {
                        let mask = [UInt8](arrayLiteral: 0x21, 0x12, 0xA4, 0x42) + transactionID
                        bytes = zip(bytes, mask).map(^)
                    }
                    mappedAddress = stride(from: 0, to: 16, by: 2).map { index in
                        String(format: "%x", (UInt16(bytes[index]) << 8) | UInt16(bytes[index + 1]))
                    }.joined(separator: ":")
                    if xorAddress { break }
                } else {
                    throw STUNProbeError.invalidResponse
                }
            }
            let nextOffset = valueStart + ((length + 3) / 4 * 4)
            guard nextOffset <= messageEnd else { throw STUNProbeError.invalidResponse }
            offset = nextOffset
        }

        guard let mappedAddress else { throw STUNProbeError.missingMappedAddress }
        return mappedAddress
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
        (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        (UInt32(data[offset]) << 24) | (UInt32(data[offset + 1]) << 16) | (UInt32(data[offset + 2]) << 8) | UInt32(data[offset + 3])
    }
}

private final class ContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var hasResolved = false

    func resolve(_ body: () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard !hasResolved else { return }
        hasResolved = true
        body()
    }
}
