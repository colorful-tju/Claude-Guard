import Testing
import Foundation
import Darwin
import GuardCore
@testable import GuardRuntime

private final class UDPFixture:@unchecked Sendable {
    let root=NSTemporaryDirectory()+UUID().uuidString
    var rules="",enabled=false,token=false,states="",calls:[[String]]=[]
    var counters:[String:UInt64]=[:]
    var failEnable=false,failBeforeEnable=false,failRemove=false,reply=false
    let boot=UUID().uuidString
    init() throws {try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)}
    deinit {try? FileManager.default.removeItem(atPath:root)}
    func run(_ args:[String],_ recording:Int32?,_ cancel:@escaping ControllerCancellation) throws -> CommandResult {
        calls.append(args)
        var out=""
        if args.contains("-f") {
            let text=try String(contentsOfFile:args.last!,encoding:.utf8)
            if args.contains("-n"){out=text}else{rules=text}
        } else {switch args {
        case ["-s","Anchors"]:out="com.apple\n"
        case ["-a","com.apple","-s","Anchors"]:out=rules.isEmpty ? "":"000.local.claudesafelauncher\n"
        case ["-sr"]:out="anchor \"com.apple/*\" all\n"
        case ["-s","Interfaces","-v"]:out="lo0\nen0\n"
        case ["-s","info"]:out="Status: \(enabled ? "Enabled":"Disabled")\n"
        case ["-s","References"]:
            out=token ? "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n"+String(format:"%8d %-28s %24d %@\n",getpid(),("pfctl" as NSString).utf8String!,9,"0 days 00:00:01"):"No pf starter references held\n"
        case ["-a",GuardPolicy.anchor,"-sr"]:out=rules
        case ["-a",GuardPolicy.anchor,"-s","labels"]:
            let labels=rules.components(separatedBy:"label \"").dropFirst().compactMap{$0.split(separator:"\"").first.map(String.init)}
            out=labels.map{"\($0) 0 \(counters[$0,default:0]) 0 0 0 0 0"}.joined(separator:"\n")
        case ["-ss","-vv"]:out=states
        case ["-E"]:
            if failBeforeEnable {throw fail("cancelled before spawn")}
            if let recording {try FileHandle(fileDescriptor:recording,closeOnDealloc:false).write(contentsOf:Data("Token : 9\n".utf8))}
            token=true;enabled=true
            if failEnable{throw fail("injected enable error after durable token")}
        case ["-a",GuardPolicy.anchor,"-F","rules"]:
            if failRemove{throw fail("injected remove failure")};rules=""
        case ["-X","9"]:token=false;enabled=false
        default:break
        }}
        return .init(output:out,error:"",status:0)
    }
    func engine() throws -> UDPProtection {
        let commands=Commands()
        return try UDPProtection(commands:commands,root:root,pf:PacketFilter(commands:commands,root:root,execute:run),owner:getuid(),physicalReader:{_ in .init(name:"en0",index:4,generation:1,ipv4:"192.0.2.2")},bootReader:{self.boot},dhcpReader:{_ in nil},probeRunner:{kind,_,_ in
            let label=self.rules.components(separatedBy:"label \"").dropFirst().compactMap{$0.split(separator:"\"").first.map(String.init)}.first{$0.hasSuffix("_"+kind.rawValue)}!
            self.counters[label,default:0]+=1
            return .init(attempted:true,reply:self.reply,setupError:false,kind:kind)
        })
    }
}
@Suite struct UDPTransactionTests {
    @Test func startStopAndRestartRecoveryDoNotNeedClaude() throws {
        let f=try UDPFixture(),e=try f.engine()
        try e.start(physical:"en0",cancelled:{false},record:{_ in})
        #expect(e.active && e.verified && f.enabled)
        #expect(throws:(any Error).self){try e.start(physical:"en0",cancelled:{false},record:{_ in})}
        let restarted=try f.engine()
        #expect(restarted.active && !restarted.verified)
        try restarted.stop()
        #expect(!restarted.active && !f.enabled && !f.token && f.rules.isEmpty)
        #expect(!FileManager.default.fileExists(atPath:f.root+"/udp-session.json"))
        #expect(!f.calls.contains{ $0.contains("-k") || $0.contains("-d") })
    }
    @Test func foreignUDPStateRejectsBeforeMutation() throws {
        let f=try UDPFixture();f.states="ALL udp 192.0.2.2:123 -> 1.1.1.1:53 SINGLE:SINGLE\n"
        let e=try f.engine()
        #expect(throws:(any Error).self){try e.start(physical:"en0",cancelled:{false},record:{_ in})}
        #expect(!e.active && f.rules.isEmpty && !f.enabled)
    }
    @Test func failedEnableWithRecordedTokenRecovers() throws {
        let f=try UDPFixture();f.failEnable=true;let e=try f.engine()
        #expect(throws:(any Error).self){try e.start(physical:"en0",cancelled:{false},record:{_ in})}
        #expect(!e.active && !f.token && f.rules.isEmpty)
    }
    @Test func cancelledBeforeEnableDoesNotStrandLoadedRules() throws {
        let f=try UDPFixture();f.failBeforeEnable=true;let e=try f.engine()
        #expect(throws:(any Error).self){try e.start(physical:"en0",cancelled:{false},record:{_ in})}
        #expect(!e.active && !f.enabled && f.rules.isEmpty)
    }
    @Test func interruptedMutationCannotRecoverFromEmptyNewWorkerTable() throws {
        let f=try UDPFixture(),e=try f.engine()
        try e.start(physical:"en0",cancelled:{false},record:{_ in})
        var journal=try PrivateFiles.read(f.root+"/udp-session.json",as:UDPJournal.self,owner:getuid())
        journal.stage="loading";try PrivateFiles.write(journal,to:f.root+"/udp-session.json")
        let restarted=try f.engine()
        #expect(throws:(any Error).self){try restarted.stop()}
        #expect(restarted.active && !f.rules.isEmpty)
    }
    @Test func repliedProbeNeverArmsAndRecoveryCanRetry() throws {
        let f=try UDPFixture();f.reply=true;f.failRemove=true;let e=try f.engine()
        #expect(throws:(any Error).self){try e.start(physical:"en0",cancelled:{false},record:{_ in})}
        #expect(e.active && !e.verified && !f.rules.isEmpty)
        f.failRemove=false;try e.stop();#expect(!e.active && !f.enabled)
    }
}
