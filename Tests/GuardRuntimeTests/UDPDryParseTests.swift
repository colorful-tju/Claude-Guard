import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

struct UDPDryParseTests {
    func withFilter(_ output:String?=nil,body:(PacketFilter)throws->Void) throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        defer{try? FileManager.default.removeItem(at:root)}
        let pf=PacketFilter(commands:Commands(),root:root.path,execute:{args,_,_ in
            // Even a future regression must not load/enable real PF from this test.
            guard args.count==8,args[0...3]==["-n","-v","-o","none"],args[4]=="-a",args[6]=="-f" else{throw fail("non-dry PF operation forbidden in test")}
            if let output {return .init(output:output,error:"",status:0)}
            return try Commands().run("/sbin/pfctl",args,timeout:8)
        })
        try body(pf)
    }
    @Test func realMacOSParserAcceptsExplicitDHCPVariants() throws {
        for (address,server) in [(nil,nil),("192.168.1.2",nil),("192.168.1.2","192.168.1.1"),("172.21.1.2","172.21.0.1")] as [(String?,String?)] {
            let policy=try UDPOnlyPolicy(physical:"en0",physicalIPv4:address,dhcpServer:server)
            try withFilter {pf in
                let parsed=try pf.prepareUDP(policy)
                #expect(parsed.split(separator:"\n").count==policy.rules.split(separator:"\n").count)
                #expect(!policy.rules.contains("{"))
                #expect(parsed.contains("block drop out quick proto udp all"))
            }
        }
    }
    @Test func exactTUNDNSRuleSurvivesRealDryParser() throws {
        let policy=try UDPOnlyPolicy(physical:"en0",dnsTUN:"utun7")
        try withFilter {pf in
            let parsed=try pf.prepareUDP(policy)
            #expect(parsed.contains("on utun7 inet proto udp from any to any port = 53 no state"))
        }
        for replacement in ["on en0", "on utun8"] {
            let altered=policy.rules.replacingOccurrences(of:" port ",with:" port = ").replacingOccurrences(of:"on utun7",with:replacement)
            try withFilter(altered) {pf in #expect(throws:(any Error).self){try pf.prepareUDP(policy)}}
        }
    }
    @Test func sameCountSemanticChangesMustBeRejected() throws {
        let p=try UDPOnlyPolicy(physical:"en0",physicalIPv4:"192.168.1.2",dhcpServer:"192.168.1.1")
        let canonical=p.rules.replacingOccurrences(of:" port ",with:" port = ")
        try withFilter(canonical) {pf in
            let parsed=try pf.prepareUDP(p);#expect(parsed==canonical)
        }
        let altered=[
            canonical.replacingOccurrences(of:"to 192.168.1.1",with:"to any"),
            canonical.replacingOccurrences(of:"on en0",with:"on en9"),
            canonical.replacingOccurrences(of:"port = 67",with:"port = 443"),
            canonical.replacingOccurrences(of:"proto udp from 192.168.1.2",with:"proto tcp from 192.168.1.2"),
            canonical.replacingOccurrences(of:"no state",with:"keep state"),
            canonical.replacingOccurrences(of:"block drop out quick proto udp all",with:"block drop out quick inet proto udp all"),
            canonical.replacingOccurrences(of:"port = 61002",with:"port = 61004"),
            canonical.replacingOccurrences(of:"_renew",with:"_different")]
        for text in altered {
            try withFilter(text) {pf in #expect(throws:(any Error).self){try pf.prepareUDP(p)}}
        }
    }
    @Test func missingExtraAndReorderedRulesAreRejected() throws {
        let p=try UDPOnlyPolicy(physical:"en0")
        let canonical=p.rules.replacingOccurrences(of:" port ",with:" port = ")
        try withFilter(canonical) {pf in
            let parsed=try pf.prepareUDP(p);#expect(parsed==canonical)
        }
        let lines=canonical.split(separator:"\n").map(String.init)
        for text in [lines.dropFirst().joined(separator:"\n"),canonical+"pass out quick proto udp all no state\n",lines.reversed().joined(separator:"\n")] {
            try withFilter(text) {pf in #expect(throws:(any Error).self){try pf.prepareUDP(p)}}
        }
    }
}
