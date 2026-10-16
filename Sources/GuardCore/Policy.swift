import Foundation
import CryptoKit

public struct InterfaceIdentity: Equatable, Hashable, Sendable, Codable {
    public var name: String
    public var index: UInt32
    /// Collector-assigned lifetime identity; changes if an interface is recreated.
    public var generation: UInt64
    public var ipv4: String

    public init(name: String, index: UInt32, generation: UInt64, ipv4: String) {
        self.name = name; self.index = index; self.generation = generation; self.ipv4 = ipv4
    }
}

public enum Transport: String, Sendable, Codable { case tcp, udp, other }
public enum AddressFamily: Sendable, Codable { case ipv4, ipv6 }

public struct Packet: Sendable, Codable {
    public var interface: String
    public var family: AddressFamily
    public var transport: Transport
    public var source: String
    public var destination: String
    public var sourcePort: UInt16
    public var destinationPort: UInt16

    public init(interface: String, family: AddressFamily = .ipv4, transport: Transport = .tcp,
                source: String = "172.21.191.84", destination: String,
                sourcePort: UInt16 = 52000, destinationPort: UInt16 = 443) {
        self.interface = interface; self.family = family; self.transport = transport
        self.source = source; self.destination = destination
        self.sourcePort = sourcePort; self.destinationPort = destinationPort
    }
}

public struct GuardPolicy: Equatable, Sendable, Codable {
    public let endpoint: Endpoint
    public let physical: InterfaceIdentity
    public let tun: InterfaceIdentity
    public let dhcpServer: String?
    public let sessionID: UUID
    public static let anchor = "com.apple/000.local.claudesafelauncher"

    public init(endpoint: Endpoint, physical: InterfaceIdentity, tun: InterfaceIdentity,
                dhcpServer: String? = nil, sessionID: UUID = UUID()) throws {
        func isName(_ name: String, prefix: String) -> Bool {
            let suffix = name.dropFirst(prefix.count)
            return name.hasPrefix(prefix) && !suffix.isEmpty && name.utf8.count < 16
                && suffix.utf8.allSatisfy { (48...57).contains($0) }
        }
        guard isName(physical.name, prefix: "en"), isName(tun.name, prefix: "utun"),
              physical.index > 0, tun.index > 0, physical.index != tun.index,
              physical.generation > 0, tun.generation > 0,
              IPv4.octets(physical.ipv4) != nil, IPv4.octets(tun.ipv4) != nil else {
            throw GuardFailure.rejected("Unverified or unsupported interface identity")
        }
        if let dhcpServer {
            guard let b = IPv4.octets(dhcpServer),
                  b[0] == 10 || (b[0] == 172 && (16...31).contains(b[1])) || (b[0] == 192 && b[1] == 168) else {
                throw GuardFailure.rejected("Only explicitly verified private DHCPv4 server is supported")
            }
        }
        guard !(endpoint.gateway == "1.1.1.1" && endpoint.port == 443) else {
            throw GuardFailure.unsupported("Gateway overlaps reserved TCP probe destination")
        }
        self.endpoint = endpoint; self.physical = physical; self.tun = tun
        self.dhcpServer = dhcpServer; self.sessionID = sessionID
    }

    public func probeLabel(_ kind: ProbeKind) -> String {
        "csg_" + sessionID.uuidString.replacingOccurrences(of: "-", with: "").lowercased() + "_" + kind.rawValue
    }

    public var rules: String {
        let tag = "csg_" + sessionID.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        var lines = [
            "pass out quick on lo0 all no state label \"\(tag)_loop\"",
            "pass out quick on \(tun.name) inet all no state label \"\(tag)_tun\"",
            "pass out quick on \(physical.name) inet proto tcp from \(physical.ipv4) to \(endpoint.gateway) port \(endpoint.port) flags any no state label \"\(tag)_gateway\""
        ]
        if let dhcpServer {
            lines.append("pass out quick on \(physical.name) inet proto udp from { 0.0.0.0, \(physical.ipv4) } port 68 to { 255.255.255.255, \(dhcpServer) } port 67 no state label \"\(tag)_dhcp\"")
        }
        // Reserved probe tuples: the future probe worker must reserve these sockets
        // and reject a busy port; counters are not per-process attribution.
        lines += [
            "block drop out quick on \(physical.name) inet proto tcp from \(physical.ipv4) port 61001 to 1.1.1.1 port 443 label \"\(probeLabel(.boundTCP))\"",
            "block drop out quick on \(physical.name) inet proto udp from \(physical.ipv4) port 61002 to 1.1.1.1 port 53 label \"\(probeLabel(.boundUDP))\"",
            "block drop out quick on \(physical.name) inet proto udp from \(physical.ipv4) port 61003 to 74.125.250.129 port 19302 label \"\(probeLabel(.boundSTUN))\"",
            "block drop out quick on \(physical.name) inet6 proto udp from any port 61004 to 2606:4700:4700::1111 port 53 label \"\(probeLabel(.boundIPv6))\""
        ]
        // No interface constraint: newly created interfaces are denied immediately.
        lines.append("block drop out quick all label \"\(tag)_deny\"")
        return lines.joined(separator: "\n") + "\n"
    }
    public var rulesFingerprint: String {
        SHA256.hash(data: Data(rules.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    /// Offline model only. Not proof that a kernel PF ruleset is effective.
    public func permits(_ packet: Packet) -> Bool {
        if packet.interface == "lo0" { return true }
        guard packet.family == .ipv4 else { return false }
        if packet.interface == tun.name { return true }
        guard packet.interface == physical.name else { return false }
        if packet.transport == .tcp && packet.source == physical.ipv4
            && packet.destination == endpoint.gateway && packet.destinationPort == endpoint.port { return true }
        if let dhcpServer, packet.transport == .udp, packet.sourcePort == 68, packet.destinationPort == 67,
           ["0.0.0.0", physical.ipv4].contains(packet.source),
           ["255.255.255.255", dhcpServer].contains(packet.destination) { return true }
        return false
    }
}
