import Testing
import Foundation
@testable import GuardCore

@Suite struct UDPPolicyTests {
    @Test func deniesUDPOnEveryNonLoopbackInterface() throws {
        let policy=try UDPOnlyPolicy(physical:"en0")
        for iface in ["en0","en9","utun7","bridge100"] {
            for family in [AddressFamily.ipv4,.ipv6] {
                #expect(!policy.permitsUDP(interface:iface,family:family,source:"192.0.2.2",destination:"1.1.1.1",sourcePort:50000,destinationPort:443))
            }
        }
        #expect(policy.permitsUDP(interface:"lo0",family:.ipv4,source:"127.0.0.1",destination:"127.0.0.1",sourcePort:50000,destinationPort:53))
        #expect(policy.rules.contains("block drop out quick proto udp all"))
        #expect(!policy.rules.contains("proto tcp"))
        #expect(!policy.rules.contains("keep state"))
    }
    @Test func dhcpIsNarrowAndCannotBecomePublicUDPPermission() throws {
        let p=try UDPOnlyPolicy(physical:"en0")
        #expect(p.permitsUDP(interface:"en0",family:.ipv4,source:"0.0.0.0",destination:"255.255.255.255",sourcePort:68,destinationPort:67))
        #expect(!p.permitsUDP(interface:"en9",family:.ipv4,source:"0.0.0.0",destination:"255.255.255.255",sourcePort:68,destinationPort:67))
        #expect(!p.permitsUDP(interface:"en0",family:.ipv4,source:"0.0.0.0",destination:"1.1.1.1",sourcePort:68,destinationPort:67))
        #expect(throws:(any Error).self){try UDPOnlyPolicy(physical:"en0\npass out all")}
    }
    @Test func renewalsAuthorizeOnlyExactDHCPDestinationsAndPorts() throws {
        let p=try UDPOnlyPolicy(physical:"en0",physicalIPv4:"192.168.1.2",dhcpServer:"192.168.1.1")
        for target in ["255.255.255.255","192.168.1.1"] {
            #expect(p.permitsUDP(interface:"en0",family:.ipv4,source:"192.168.1.2",destination:target,sourcePort:68,destinationPort:67))
            #expect(!p.permitsUDP(interface:"en0",family:.ipv4,source:"192.168.1.2",destination:target,sourcePort:50000,destinationPort:67))
            #expect(!p.permitsUDP(interface:"en0",family:.ipv4,source:"192.168.1.2",destination:target,sourcePort:68,destinationPort:443))
            #expect(!p.permitsUDP(interface:"en9",family:.ipv4,source:"192.168.1.2",destination:target,sourcePort:68,destinationPort:67))
        }
        #expect(!p.permitsUDP(interface:"en0",family:.ipv4,source:"192.168.1.2",destination:"1.1.1.1",sourcePort:68,destinationPort:67))
        #expect(throws:(any Error).self){try UDPOnlyPolicy(physical:"en0",physicalIPv4:"192.168.1.2",dhcpServer:"1.1.1.1")}
        #expect(p.rules.split(separator:"\n").count==7)
        #expect(!p.rules.contains("{"))
    }
    @Test func lifecycleIsModeSpecificAndMutuallyExclusive() throws {
        #expect(!ProtectionMode.udpOnly.managesClaude)
        #expect(ProtectionMode.claude.managesClaude)
        #expect(ProtectionMode.mayBegin(current:nil))
        #expect(!ProtectionMode.mayBegin(current:.udpOnly))
        #expect(!ProtectionMode.mayBegin(current:.claude))
    }
}
