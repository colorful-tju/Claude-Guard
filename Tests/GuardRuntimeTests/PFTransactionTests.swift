import Foundation
import Darwin
import Testing
import GuardCore
@testable import GuardRuntime

private final class PFExecutionFixture:@unchecked Sendable {
    var calls:[[String]]=[]
    var rootInventoryReads=0
    var inventoryChanges=false
    var ownNAT=""
    var tokenOutput="Token : 9\n"
    var enableFails=false
    var cancellationObserved=false
    func execute(_ args:[String],_ recording:Int32?,_ cancelled:@escaping ControllerCancellation) throws -> CommandResult {
        calls.append(args)
        if args==["-E"] {
            cancellationObserved=cancelled()
            if let recording {
                try FileHandle(fileDescriptor:recording,closeOnDealloc:false).write(contentsOf:Data(tokenOutput.utf8))
            }
            if enableFails{throw fail("Injected enable timeout after partial result")}
            return .init(output:"",error:"",status:0)
        }
        var output=""
        switch args {
        case ["-s","Anchors"]:
            rootInventoryReads += 1;output=inventoryChanges && rootInventoryReads>1 ? "com.apple\nforeign\n":"com.apple\n"
        case ["-a","com.apple","-s","Anchors"]:output="com.apple/000.local.claudesafelauncher\n"
        case ["-sr"]:output="anchor \"com.apple/*\" all\n"
        case ["-s","Interfaces","-v"]:output="en0\nlo0\n"
        case ["-a",GuardPolicy.anchor,"-sr"]:output="owned stateless rules\n"
        case ["-a",GuardPolicy.anchor,"-sn"]:output=ownNAT
        case ["-s","References"]:output="No pf starter references held\n"
        case ["-s","info"]:output="Status: Enabled for 0 days 00:00:01\n"
        default:break
        }
        return .init(output:output,error:"No ALTQ support in kernel\nALTQ related functions disabled\n",status:0)
    }
}
struct PFTransactionTests {
    private func policy() throws -> GuardPolicy {
        let endpoint=try Endpoint(gateway:"23.20.10.8",port:5376,expectedEgress:"1.1.1.1",configurationFingerprint:"config",providerConfirmed:true,confirmedGateway:"23.20.10.8",confirmedPort:5376,confirmedFingerprint:"config",protocolName:"http")
        return try .init(endpoint:endpoint,physical:.init(name:"en0",index:6,generation:1,ipv4:"172.21.191.84"),tun:.init(name:"utun4",index:20,generation:1,ipv4:"198.18.0.1"))
    }
    @Test func dryParseRequiresFinalUnconditionalDeny() throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent("pf-dry-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        defer{try? FileManager.default.removeItem(at:root)}
        let policy=try policy()
        for altered in [false,true] {
            let text=altered ? policy.rules.replacingOccurrences(of:"block drop out quick all",with:"block drop out quick on en0 all") : policy.rules
            let pf=PacketFilter(commands:Commands(),root:root.path,execute:{_,_,_ in .init(output:text,error:"",status:0)})
            if altered {reject{_ = try pf.prepareRules(policy)}}
            else {#expect(try pf.prepareRules(policy)==policy.rules)}
        }
    }
    @Test func actualPFViewBracketsOwnRulesAndStatesInOneFreshInventory() throws {
        let fake=PFExecutionFixture(),pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
        let view=try pf.view(policy())
        #expect(view.enabled && view.states.isEmpty && view.canonical=="owned stateless rules\n")
        #expect(fake.rootInventoryReads==2)
        #expect(!fake.calls.contains(where:{$0.contains("labels")}))
        let states=fake.calls.firstIndex(of:["-ss","-vv"])!,lastInventory=fake.calls.lastIndex(of:["-s","Anchors"])!
        #expect(states<lastInventory)
    }
    @Test func actualPFViewRejectsInventoryChangeAndForeignOwnNAT() throws {
        for inventory in [false,true] {
            let fake=PFExecutionFixture();fake.inventoryChanges=inventory;fake.ownNAT=inventory ? "":"rdr pass on en0\n"
            let pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
            reject{_ = try pf.view(policy())}
        }
    }
    @Test func actualEnablePersistsOwnedTokenAndForwardsCancellation() throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent("pf-enable-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
        let fake=PFExecutionFixture(),pf=PacketFilter(commands:Commands(),root:root.path,execute:fake.execute)
        #expect(try pf.enable(cancelled:{true})=="9")
        #expect(fake.cancellationObserved)
        #expect(try String(contentsOf:root.appendingPathComponent("enable-result.txt"),encoding:.utf8)=="Token : 9\n")
        reject{_ = try pf.enable()}
        #expect(fake.calls.filter{$0==["-E"]}.count==1)
    }
    @Test func ambiguousEnableRetainsItsPartialOutputForRecovery() throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent("pf-ambiguous-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:root)}
        let fake=PFExecutionFixture();fake.enableFails=true;fake.tokenOutput="Token :"
        let pf=PacketFilter(commands:Commands(),root:root.path,execute:fake.execute)
        reject{_ = try pf.enable()}
        #expect(try String(contentsOf:root.appendingPathComponent("enable-result.txt"),encoding:.utf8)=="Token :")
        reject{_ = try pf.recoveredToken()}
    }
}
