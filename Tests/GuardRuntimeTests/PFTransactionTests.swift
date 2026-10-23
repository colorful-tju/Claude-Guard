import Foundation
import Darwin
import Testing
import GuardCore
@testable import GuardRuntime

private final class PFExecutionFixture:@unchecked Sendable {
    var calls:[[String]]=[]
    var rootInventoryReads=0
    var rootInventory="com.apple\n"
    var mainExtra=""
    var natExtra=""
    var sharing=PFAnchorContents(filter:"",nat:"",children:"com.apple.internet-sharing/host_v4\ncom.apple.internet-sharing/host_v6\n")
    var sharingLeaf=PFAnchorContents(filter:"",nat:"",children:"")
    var sharingReadFails=false
    var sharingInventoryChanges=false
    var sharingInventoryReads=0
    var stateText=""
    var inventoryChanges=false
    var ownNAT=""
    var tokenOutput="Token : 9\n"
    var enableFails=false
    var cancellationObserved=false
    func execute(_ args:[String],_ recording:Int32?,_ cancelled:@escaping ControllerCancellation) throws -> CommandResult {
        calls.append(args)
        if sharingReadFails,args.contains("com.apple.internet-sharing/host_v4") {throw fail("fixture read failed")}
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
            rootInventoryReads += 1;output=inventoryChanges && rootInventoryReads>1 ? "com.apple\nforeign\n":rootInventory
        case ["-a","com.apple","-s","Anchors"]:output="com.apple/000.local.claudesafelauncher\n"
        case ["-sr"]:output="anchor \"com.apple/*\" all\n"+mainExtra
        case ["-sn"]:output=natExtra
        case ["-a","com.apple.internet-sharing","-sr"]:output=sharing.filter
        case ["-a","com.apple.internet-sharing","-sn"]:output=sharing.nat
        case ["-a","com.apple.internet-sharing","-s","Anchors"]:
            sharingInventoryReads += 1
            output=sharingInventoryChanges && sharingInventoryReads>1 ? "":sharing.children
        case ["-a","com.apple.internet-sharing/host_v4","-sr"],["-a","com.apple.internet-sharing/host_v6","-sr"]:output=sharingLeaf.filter
        case ["-a","com.apple.internet-sharing/host_v4","-sn"],["-a","com.apple.internet-sharing/host_v6","-sn"]:output=sharingLeaf.nat
        case ["-a","com.apple.internet-sharing/host_v4","-s","Anchors"],["-a","com.apple.internet-sharing/host_v6","-s","Anchors"]:output=sharingLeaf.children
        case ["-s","Interfaces","-v"]:output="en0\nlo0\n"
        case ["-a",GuardPolicy.anchor,"-sr"]:output="owned stateless rules\n"
        case ["-a",GuardPolicy.anchor,"-sn"]:output=ownNAT
        case ["-s","References"]:output="No pf starter references held\n"
        case ["-s","info"]:output="Status: Enabled for 0 days 00:00:01\n"
        case ["-ss","-vv"]:output=stateText
        default:break
        }
        return .init(output:output,error:"No ALTQ support in kernel\nALTQ related functions disabled\n",status:0)
    }
}
struct PFTransactionTests {
    private func sharingFixture()->PFExecutionFixture {
        let fake=PFExecutionFixture();fake.rootInventory="com.apple\ncom.apple.internet-sharing\n"
        fake.mainExtra="scrub-anchor \"com.apple.internet-sharing\" all fragment reassemble\nanchor \"com.apple.internet-sharing\" all\n"
        fake.natExtra="nat-anchor \"com.apple.internet-sharing\" all\nrdr-anchor \"com.apple.internet-sharing\" all\n"
        return fake
    }
    @Test func emptySharingTreeAfterServiceExitIsAcceptedAndFingerprintTracksIt() throws {
        let fake=sharingFixture(),pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
        let before=try pf.environment().0
        #expect(before.contains("com.apple.internet-sharing") && before.contains("host_v4"))
        fake.sharing.children=""
        #expect(try pf.environment().0 != before)
        fake.sharingLeaf.filter="pass on bridge100 inet6 from fe80::/10 to any flags any keep state\n"
        fake.sharing.children="host_v4\nhost_v6\n"
        reject{_ = try pf.view(policy())}
    }
    @Test func emptySharingDoesNotBypassMissingReadsOrStateValidation() throws {
        let fake=sharingFixture(),pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
        fake.sharingReadFails=true
        reject{_ = try pf.view(policy())}
        fake.sharingReadFails=false
        fake.stateText="all udp 10.0.0.2:1200 -> 8.8.8.8:53 MULTIPLE:SINGLE\n"
        reject{_ = try pf.view(policy())}
        fake.stateText="";fake.rootInventory="com.apple\n"
        reject{_ = try pf.view(policy())} // sharing main references without positive empty-tree evidence
    }
    @Test func sharingIsNeverNameOnlyWhitelisted() throws {
        for variant in 0..<7 {
            let fake=sharingFixture()
            switch variant {
            case 0:fake.sharing.filter="anchor \"host_v4\" all\n"
            case 1:fake.sharing.nat="nat-anchor \"host_v4\" all\n"
            case 2:fake.sharing.children="unknown\n"
            case 3:fake.sharingLeaf.filter="pass on bridge100 all keep state\n"
            case 4:fake.sharingLeaf.nat="nat on bridge100 from any to any -> (en0)\n"
            case 5:fake.sharingLeaf.children="nested\n"
            default:fake.mainExtra="anchor \"com.apple.internet-sharing\" out quick all\n"
            }
            let pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
            reject{_ = try pf.environment()}
            #expect(fake.calls.allSatisfy{!$0.contains(where:["-f","-F","-E","-X","-d"].contains)})
        }
    }
    @Test func sharingChildrenChangingDuringReadCannotPassAsEmpty() throws {
        let fake=sharingFixture();fake.sharingInventoryChanges=true
        let pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
        do {_ = try pf.environment();Issue.record("changing sharing tree accepted")}
        catch {#expect(String(describing:error).contains("PF Internet Sharing inventory changed"))}
        #expect(fake.calls.allSatisfy{!$0.contains(where:["-f","-F","-E","-X","-d"].contains)})
    }
    @Test func unknownRootReportsObservedNamesAndNeverChangesPF() throws {
        let fake=PFExecutionFixture();fake.rootInventory="  com.apple\n  vendor.test\n"
        let pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
        do {_ = try pf.environment();Issue.record("unknown root accepted")}
        catch {
            #expect(String(describing:error).contains("vendor.test"))
            #expect(String(describing:error).contains("com.apple"))
        }
        #expect(fake.calls.allSatisfy{!$0.contains(where:["-f","-F","-E","-X","-d"].contains)})
    }
    @Test func friendRootInventoryWithIndentAndALTQIsAccepted() throws {
        let fake=PFExecutionFixture();fake.rootInventory="  com.apple\n"
        let pf=PacketFilter(commands:Commands(),root:"/nonexistent",execute:fake.execute)
        #expect(try pf.environment().2)
    }
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
        #expect(fake.calls.filter{$0.contains("labels")}.count==1)
        let states=fake.calls.firstIndex(of:["-ss","-vv"])!,lastInventory=fake.calls.lastIndex(of:["-s","Anchors"])!
        #expect(states<lastInventory)
        #expect(fake.calls.firstIndex(of:["-a",GuardPolicy.anchor,"-s","labels"])!<lastInventory)
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
