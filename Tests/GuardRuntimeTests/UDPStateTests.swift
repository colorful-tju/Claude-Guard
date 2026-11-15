import Testing
@testable import GuardRuntime
@Suite struct UDPStateTests {
    @Test func allowsTCPButRejectsAnyExistingUDPState() throws {
        try UDPStateEvidence.validate("")
        try UDPStateEvidence.validate("ALL tcp 192.0.2.1:1234 -> 1.1.1.1:443 ESTABLISHED:ESTABLISHED\n   age 00:00:01, expires in 00:00:30\n   id: 123 creatorid: 0\n")
        #expect(throws:(any Error).self){try UDPStateEvidence.validate("ALL udp 192.0.2.1:1234 -> 1.1.1.1:53 MULTIPLE:SINGLE\n")}
        #expect(throws:(any Error).self){try UDPStateEvidence.validate("unrecognized state format")}
        #expect(throws:(any Error).self){try UDPStateEvidence.validate("    udp state hidden as metadata")}
    }
}
