import Foundation

public enum GuardFailure: Error, Equatable, Sendable, Codable {
    case invalidEndpoint(String)
    case unsupported(String)
    case rejected(String)
    case invalidTransition(String)
}

public struct Endpoint: Equatable, Sendable, Codable {
    public let gateway: String
    public let port: UInt16
    public let expectedEgress: String
    public let configurationFingerprint: String

    public init(gateway: String, port: UInt16, expectedEgress: String,
                configurationFingerprint: String, providerConfirmed: Bool,
                confirmedGateway: String, confirmedPort: UInt16,
                confirmedFingerprint: String, protocolName: String) throws {
        guard IPv4.isPublic(gateway) else { throw GuardFailure.unsupported("Provider numeric public IPv4 endpoint required") }
        guard IPv4.isPublic(expectedEgress), port > 0 else { throw GuardFailure.invalidEndpoint("Invalid egress or port") }
        guard protocolName == "http" else { throw GuardFailure.unsupported("Only direct HTTP/TCP is supported") }
        guard providerConfirmed, gateway == confirmedGateway, port == confirmedPort,
              !configurationFingerprint.isEmpty, configurationFingerprint == confirmedFingerprint else {
            throw GuardFailure.invalidEndpoint("Provider confirmation must bind the exact endpoint and configuration")
        }
        self.gateway = gateway
        self.port = port
        self.expectedEgress = expectedEgress
        self.configurationFingerprint = configurationFingerprint
    }
}

public enum IPv4 {
    public static func octets(_ value: String) -> [UInt8]? {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for part in parts {
            guard !part.isEmpty, part.utf8.allSatisfy({ (48...57).contains($0) }),
                  part.count == 1 || part.first != "0", let byte = UInt8(part) else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    public static func isPublic(_ value: String) -> Bool {
        guard let b = octets(value) else { return false }
        return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224
            || (b[0] == 100 && (64...127).contains(b[1]))
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 172 && (16...31).contains(b[1]))
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2))
            || (b[0] == 192 && b[1] == 88 && b[2] == 99)
            || (b[0] == 198 && (b[1] == 18 || b[1] == 19))
            || (b[0] == 198 && b[1] == 51 && b[2] == 100)
            || (b[0] == 203 && b[1] == 0 && b[2] == 113))
    }
}
