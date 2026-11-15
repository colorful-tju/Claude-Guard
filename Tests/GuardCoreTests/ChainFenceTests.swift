import Foundation
import Testing
@testable import GuardCore
struct ChainFenceTests {
    func policy() throws -> GuardPolicy {
        let old=try fixturePolicy()
        let c=ChainBoundary(landingGateway:"8.8.4.4",landingPort:5230,entryName:"Entry",entryProtocol:"vless",entryHost:"entry.example")
        let e=try Endpoint(gateway:"1.2.3.4",port:443,expectedEgress:"9.9.9.9",configurationFingerprint:"chain",providerConfirmed:true,confirmedGateway:"1.2.3.4",confirmedPort:443,confirmedFingerprint:"chain",protocolName:"vless",chain:c)
        return try GuardPolicy(endpoint:e,physical:old.physical,tun:old.tun)
    }
    @Test func physicalAllowlistIsExactlyEntryTCP() throws {
        let p=try policy()
        #expect(p.permits(.init(interface:p.physical.name,source:p.physical.ipv4,destination:"1.2.3.4",destinationPort:443)))
        for ip in ["8.8.4.4","8.8.8.8"] {#expect(!p.permits(.init(interface:p.physical.name,source:p.physical.ipv4,destination:ip,destinationPort:443)))}
        #expect(!p.permits(.init(interface:"en9",source:p.physical.ipv4,destination:"1.2.3.4",destinationPort:443)))
        #expect(!p.permits(.init(interface:p.physical.name,transport:.udp,source:p.physical.ipv4,destination:"1.2.3.4",destinationPort:443)))
    }
    @Test func startupRequiresLiveEntryButIdleMonitoringRetainsRealFenceChecks() throws {
        let p=try policy();var s=fixtureSnapshot(p);s.chain=p.endpoint.chain;s.protocolName="vless"
        try SafetyGate.validateLocal(s,policy:p)
        var idle=s;idle.connection.established=false;idle.connection.localPort=0
        #expect(throws:(any Error).self){try SafetyGate.validateLocal(idle,policy:p)}
        try MonitoringGate.validate(idle,baseline:s,policy:p)
        idle.pfEnabled=false
        #expect(throws:(any Error).self){try MonitoringGate.validate(idle,baseline:s,policy:p)}
    }
    @Test func changedEntryOrLandingStillRejects() throws {
        let p=try policy();var s=fixtureSnapshot(p);s.chain=p.endpoint.chain;s.protocolName="vless"
        var c=s;c.gateway="8.8.8.8"
        #expect(throws:(any Error).self){try MonitoringGate.validate(c,baseline:s,policy:p)}
        c=s;c.chain=nil
        #expect(throws:(any Error).self){try MonitoringGate.validate(c,baseline:s,policy:p)}
        var d=fixtureSnapshot(try fixturePolicy());d.connection.established=false;d.connection.localPort=0
        #expect(throws:(any Error).self){try MonitoringGate.validate(d,baseline:fixtureSnapshot(try fixturePolicy()),policy:fixturePolicy())}
    }
}
