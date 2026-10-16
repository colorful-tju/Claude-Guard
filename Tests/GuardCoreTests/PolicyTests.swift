import Foundation
import Testing
@testable import GuardCore

func fixturePolicy(gateway: String = "23.20.10.8", physical: String = "en0",
                   tun: String = "utun4", dhcp: String? = nil) throws -> GuardPolicy {
    let endpoint = try EndpointTests().make(gateway)
    return try GuardPolicy(endpoint: endpoint,
        physical: .init(name: physical, index: 6, generation: 1, ipv4: "172.21.191.84"),
        tun: .init(name: tun, index: 20, generation: 2, ipv4: "198.18.0.1"), dhcpServer: dhcp,
        sessionID: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)
}

struct PolicyTests {
    @Test func onlyGatewayTCPMayUsePhysicalInterface() throws {
        let p = try fixturePolicy()
        #expect(p.permits(.init(interface: "en0", destination: "23.20.10.8", destinationPort: 5376)))
        #expect(!p.permits(.init(interface: "en0", destination: "1.1.1.1", destinationPort: 5376)))
        #expect(!p.permits(.init(interface: "en0", transport: .udp, destination: "23.20.10.8", destinationPort: 5376)))
        #expect(!p.permits(.init(interface: "en0", destination: "23.20.10.8", destinationPort: 80)))
        #expect(!p.permits(.init(interface: "en0", source: "172.21.191.85", destination: "23.20.10.8", destinationPort: 5376)))
    }

    @Test func unobservedNewInterfaceIsDeniedWithoutMonitor() throws {
        let p = try fixturePolicy()
        for interface in ["en1", "en99", "utun5", "bridge0", "awdl0"] {
            #expect(!p.permits(.init(interface: interface, destination: "23.20.10.8", destinationPort: 5376)))
            #expect(!p.permits(.init(interface: interface, transport: .udp, destination: "74.125.250.129", destinationPort: 19302)))
        }
    }

    @Test func loopbackAndOnlyVerifiedTunAreAllowed() throws {
        let p = try fixturePolicy()
        #expect(p.permits(.init(interface: "lo0", destination: "127.0.0.1")))
        #expect(p.permits(.init(interface: "utun4", destination: "1.1.1.1")))
        #expect(!p.permits(.init(interface: "en0", destination: "172.21.128.1")))
        #expect(!p.permits(.init(interface: "utun4", family: .ipv6, destination: "2606:4700:4700::1111")))
    }

    @Test func dhcpIsNarrowAndOptIn() throws {
        let packet = Packet(interface: "en0", transport: .udp, source: "0.0.0.0",
                            destination: "255.255.255.255", sourcePort: 68, destinationPort: 67)
        #expect(!(try fixturePolicy()).permits(packet))
        let p = try fixturePolicy(dhcp: "172.21.128.1")
        #expect(p.permits(packet))
        #expect(p.permits(.init(interface: "en0", transport: .udp, destination: "172.21.128.1", sourcePort: 68, destinationPort: 67)))
        #expect(!p.permits(.init(interface: "en1", transport: .udp, destination: "172.21.128.1", sourcePort: 68, destinationPort: 67)))
        #expect(!p.permits(.init(interface: "en0", transport: .udp, destination: "8.8.8.8", sourcePort: 68, destinationPort: 67)))
        expectThrows(try fixturePolicy(dhcp: "8.8.8.8"))
    }

    @Test func compilerHasNoPersistentStateAndUnscopedFinalDeny() throws {
        let rules = try fixturePolicy().rules
        let lines = rules.split(separator: "\n")
        #expect(lines.filter { $0.hasPrefix("pass ") }.count == 3)
        #expect(lines.filter { $0.hasPrefix("pass ") }.allSatisfy { $0.contains("no state") })
        #expect(lines.last?.hasPrefix("block drop out quick all label") == true)
        #expect(!rules.contains("keep state"))
        #expect(rules.contains("to 23.20.10.8 port 5376"))
        #expect(!rules.contains("to 1.1.1.1 port 5376"))
    }

    @Test func rejectsRuleInjectionAndInterfaceAlias() {
        expectThrows(try fixturePolicy(physical: "en0\npass out all"))
        expectThrows(try fixturePolicy(physical: "lo0"))
        expectThrows(try fixturePolicy(tun: "en0"))
        expectThrows(try fixturePolicy(tun: "utun*"))
    }
    @Test func probeCountersHaveExactGeneratedRules() throws {
        let p = try fixturePolicy()
        for kind in ProbeKind.allCases {
            #expect(p.rules.contains("label \"\(p.probeLabel(kind))\""))
        }
        #expect(p.rules.contains("port 61001 to 1.1.1.1 port 443"))
        #expect(p.rules.contains("port 61003 to 74.125.250.129 port 19302"))
    }
}
