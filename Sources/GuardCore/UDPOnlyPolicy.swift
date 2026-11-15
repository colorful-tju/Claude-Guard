import Foundation

public enum ProtectionMode:String,Codable,Sendable {
    case claude,udpOnly
    public var managesClaude:Bool {self == .claude}
    public static func mayBegin(current:Self?)->Bool {current == nil}
}

/// Deliberately does not authorize TCP, verify an exit IP, or classify applications.
public struct UDPOnlyPolicy:Codable,Sendable,Equatable {
    public let physical:String
    public let sessionID:UUID
    public let physicalIPv4:String?
    public let dhcpServer:String?
    public init(physical:String,physicalIPv4:String?=nil,dhcpServer:String?=nil,sessionID:UUID=UUID()) throws {
        guard physical.hasPrefix("en"),physical.count>2,physical.count<16,
              physical.dropFirst(2).utf8.allSatisfy({(48...57).contains($0)}) else {
            throw GuardFailure.unsupported("UDP protection requires a verified en interface")
        }
        if let physicalIPv4,IPv4.octets(physicalIPv4)==nil {throw GuardFailure.unsupported("Invalid UDP physical address")}
        if let dhcpServer {
            guard let a=IPv4.octets(dhcpServer),a[0]==10 || (a[0]==172 && (16...31).contains(a[1])) || (a[0]==192 && a[1]==168),physicalIPv4 != nil else{throw GuardFailure.unsupported("UDP DHCP server must be a verified private IPv4")}
        }
        self.physical=physical;self.sessionID=sessionID;self.physicalIPv4=physicalIPv4;self.dhcpServer=dhcpServer
    }
    public var label:String {"csg_udp_"+sessionID.uuidString.replacingOccurrences(of:"-",with:"").lowercased()}
    public func probeLabel(_ kind:ProbeKind)->String {label+"_"+kind.rawValue}
    public var rules:String {
        var rows=["pass out quick on lo0 proto udp all no state label \"\(label)_loop\"",
         // Broadcast DHCP bootstrap/rebind only. No arbitrary public destination exception.
         "pass out quick on \(physical) inet proto udp from 0.0.0.0 port 68 to 255.255.255.255 port 67 no state label \"\(label)_dhcp\"",
         "block drop out quick on \(physical) inet proto udp from any port 61002 to 1.1.1.1 port 53 label \"\(probeLabel(.boundUDP))\"",
         "block drop out quick on \(physical) inet proto udp from any port 61003 to 74.125.250.129 port 19302 label \"\(probeLabel(.boundSTUN))\"",
         "block drop out quick proto udp all label \"\(label)_deny\""]
        if let physicalIPv4 {
            // pfctl expands address lists into separate rules. Emit each exact
            // destination ourselves so dry parsing cannot change the rule count.
            let destinations=["255.255.255.255"]+(dhcpServer.map{[$0]} ?? [])
            let renewals=destinations.map { destination in
                "pass out quick on \(physical) inet proto udp from \(physicalIPv4) port 68 to \(destination) port 67 no state label \"\(label)_renew\""
            }
            rows.insert(contentsOf:renewals,at:2)
        }
        return rows.joined(separator:"\n")+"\n"
    }
    /// Offline model only, not a kernel-enforcement claim.
    public func permitsUDP(interface:String,family:AddressFamily,source:String,destination:String,sourcePort:UInt16,destinationPort:UInt16)->Bool {
        interface=="lo0" || (interface==physical && family == .ipv4 && sourcePort==68 && destinationPort==67 &&
            ((source=="0.0.0.0" && destination=="255.255.255.255") ||
             (source==physicalIPv4 && (destination=="255.255.255.255" || destination==dhcpServer))))
    }
}
