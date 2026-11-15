import Foundation
import Darwin
import GuardCore

struct UDPJournal:Codable {
    var version=1
    var policy:UDPOnlyPolicy
    var boot:String
    var main:String
    var references:String
    var enabled:Bool
    var canonical:String
    var token:String?
    var stage="prepared"
}

/// Independent transaction. No process inventory, Claude launch or signal APIs.
/// A separate journal makes lifecycle ownership explicit even after daemon restart.
final class UDPProtection {
    let pf:PacketFilter
    let commands:Commands
    let root:String
    private let physicalReader:(String)throws->InterfaceIdentity
    private let probeRunner:(ProbeKind,InterfaceIdentity,@escaping ControllerCancellation)throws->ProbeResult
    private let bootReader:()->String
    private let dhcpReader:(String)throws->String?
    private(set) var journal:UDPJournal?
    private(set) var verified=false
    private var priorWorkersUnproven=false
    private(set) var packets:UInt64?
    private var initialCounts:[String:UInt64]=[:]
    var active:Bool {journal != nil}
    init(commands:Commands,root:String=Paths.root,pf:PacketFilter?=nil,owner:UInt32=0,
         physicalReader:@escaping (String)throws->InterfaceIdentity=UDPProtection.physical,
         bootReader:@escaping ()->String=bootID,
         dhcpReader:((String)throws->String?)?=nil,
         probeRunner:((ProbeKind,InterfaceIdentity,@escaping ControllerCancellation)throws->ProbeResult)?=nil) throws {
        self.commands=commands;self.root=root;self.pf=pf ?? PacketFilter(commands:commands,root:root)
        self.physicalReader=physicalReader;self.bootReader=bootReader
        self.dhcpReader=dhcpReader ?? {name in
            let result=try commands.run("/usr/sbin/ipconfig",["getoption",name,"server_identifier"],timeout:3)
            guard result.status==0 else{return nil}
            let ip=result.output.trimmingCharacters(in:.whitespacesAndNewlines)
            guard IPv4.octets(ip) != nil else{throw fail("UDP protection: DHCP identifier unreadable")}
            return ip
        }
        self.probeRunner=probeRunner ?? {kind,identity,cancelled in
            let r=try commands.run(root+"/guard-probe",["--negative",kind.rawValue,identity.name,identity.ipv4,String(identity.index)],timeout:4,cancelled:cancelled)
            guard r.status==0 else{throw fail("UDP protection: probe worker failed")}
            return try JSONDecoder().decode(ProbeResult.self,from:Data(r.output.utf8))
        }
        if FileManager.default.fileExists(atPath:root+"/udp-session.json") {
            journal=try PrivateFiles.read(root+"/udp-session.json",as:UDPJournal.self,owner:owner)
            guard journal?.version==1 else{throw fail("UDP protection: unsupported recovery journal")}
            if let j=journal,j.boot==bootReader(),!["prepared","active"].contains(j.stage) {
                priorWorkersUnproven=true
            }
        }
    }
    private func persist() throws {if let journal {try PrivateFiles.write(journal,to:root+"/udp-session.json")}}
    private func states() throws {try UDPStateEvidence.validate(pf.pf(["-ss","-vv"]))}
    private func remove(_ name:String) throws {
        let path=root+"/"+name
        guard unlink(path)==0 || errno==ENOENT else{throw fail("UDP protection: transaction cleanup failed")}
        let fd=open(root,O_RDONLY);guard fd>=0 else{throw fail("UDP protection: directory unavailable")};defer{close(fd)}
        guard fsync(fd)==0 else{throw fail("UDP protection: cleanup not durable")}
    }
    static func physical(_ name:String) throws -> InterfaceIdentity {
        _=try UDPOnlyPolicy(physical:name)
        var list:UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list)==0 else{throw fail("UDP protection: interface inventory unavailable")}
        defer{freeifaddrs(list)}
        var addresses=Set<String>(),p=list
        while let row=p {
            defer{p=row.pointee.ifa_next}
            guard String(cString:row.pointee.ifa_name)==name,
                  row.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  let a=row.pointee.ifa_addr,Int32(a.pointee.sa_family)==AF_INET else{continue}
            var out=[CChar](repeating:0,count:1025)
            guard getnameinfo(a,socklen_t(a.pointee.sa_len),&out,socklen_t(out.count),nil,0,NI_NUMERICHOST)==0 else{throw fail("UDP protection: address unavailable")}
            addresses.insert(String(cString:out))
        }
        let index=if_nametoindex(name)
        guard index>0,addresses.count==1,let address=addresses.first,IPv4.octets(address) != nil else{throw fail("UDP protection: select an active physical IPv4 interface")}
        return .init(name:name,index:index,generation:1,ipv4:address)
    }
    func start(physical:String,cancelled:@escaping @Sendable ()->Bool,record:@escaping @Sendable (String)throws->Void) throws {
        guard !active,!FileManager.default.fileExists(atPath:root+"/session.json"),
              !FileManager.default.fileExists(atPath:root+"/enable-result.txt"),
              try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("UDP protection: stop or recover the existing session first")}
        let identity=try physicalReader(physical)
        let policy=try UDPOnlyPolicy(physical:physical,physicalIPv4:identity.ipv4,dhcpServer:dhcpReader(physical))
        let env=try pf.environment();try states()
        let boot=bootReader();guard UUID(uuidString:boot) != nil else{throw fail("UDP protection: boot identity unavailable")}
        let canonical=try pf.prepareUDP(policy)
        guard !cancelled() else{throw fail("UDP protection: cancelled")}
        journal=UDPJournal(policy:policy,boot:boot,main:env.0,references:try pf.foreignReferences(nil),enabled:env.2,canonical:canonical)
        try persist()
        do {
            try states()
            journal!.stage="loading";try persist()
            try pf.activateUDP(policy,expected:canonical)
            guard !cancelled() else{throw fail("UDP protection: cancelled")}
            journal!.stage="enabling";try persist()
            journal!.token=try pf.enable(cancelled:cancelled);journal!.stage="validating";try persist()
            try check()
            // Negative probes only; no IP echo prerequisite and no Claude process access.
            for kind in [ProbeKind.boundUDP,.boundSTUN] {
                guard !cancelled() else{throw fail("UDP protection: cancelled")}
                let before=try PFText.counter(pf.labels(),label:policy.probeLabel(kind))
                let probe=try probeRunner(kind,identity,cancelled)
                let after=try PFText.counter(pf.labels(),label:policy.probeLabel(kind))
                guard probe.kind==kind,probe.attempted,!probe.reply,!probe.setupError,after>before else{throw fail("UDP protection: negative probe/counter verification failed")}
                try record("UDP-only probe \(kind.rawValue) counter=\(before)->\(after); TCP and egress not verified")
            }
            try commands.assertQuiescent();try check()
            guard try physicalReader(physical)==identity,!cancelled() else{throw fail("UDP protection: final interface/operation changed")}
            initialCounts=try counters(policy)
            journal!.stage="active";try persist();verified=true;packets=0
        }catch {
            let cause=error;verified=false
            do{try stop()}catch{throw fail("UDP protection: startup failed and recovery blocked: \(error)")}
            throw cause
        }
    }
    private func counters(_ policy:UDPOnlyPolicy) throws -> [String:UInt64] {
        let text=try pf.labels()
        return try Dictionary(uniqueKeysWithValues:[policy.label+"_deny",policy.probeLabel(.boundUDP),policy.probeLabel(.boundSTUN)].map{($0,try PFText.counter(text,label:$0))})
    }
    func check() throws {
        guard let j=journal,let token=j.token else{throw fail("UDP protection: token unavailable")}
        let env=try pf.environment()
        guard env.2,env.0==j.main,try pf.canonical()==j.canonical,try pf.referencePresent(token),
              try pf.foreignReferences(token)==j.references else{verified=false;throw fail("UDP protection: PF rules/reference/environment changed")}
        try states()
        if let values=try? counters(j.policy),!initialCounts.isEmpty {
            var total:UInt64=0
            for (label,count) in values {
                guard let before=initialCounts[label],count>=before else{packets=nil;return}
                let sum=total.addingReportingOverflow(count-before)
                guard !sum.overflow else{packets=nil;return};total=sum.partialValue
            }
            packets=total
        } else {packets=nil}
    }
    func stop() throws {
        verified=false
        guard var j=journal else{return}
        try commands.assertQuiescent()
        let currentBoot=bootReader()
        guard !priorWorkersUnproven || journal?.boot != currentBoot else{throw fail("UDP protection: interrupted worker ownership unproven after daemon restart; keep restrictions; use explicit recovery or reboot")}
        let own=try pf.canonical()
        guard UUID(uuidString:currentBoot) != nil else{throw fail("UDP protection: boot identity unavailable")}
        if j.boot != currentBoot {
            guard own.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("UDP protection: foreign rules after reboot")}
            // Never release a token from an earlier boot.
            try remove("udp-session.json");try remove("enable-result.txt");journal=nil;return
        }
        if j.token==nil,FileManager.default.fileExists(atPath:root+"/enable-result.txt") {
            do {j.token=try pf.recoveredToken();journal=j;try persist()}
            catch {
                guard try pf.foreignReferences(nil)==j.references,try pf.environment().2==j.enabled else{throw fail("UDP protection: PF enable outcome uncertain; token output incomplete")}
            }
        }
        guard own.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty || own==j.canonical else{throw fail("UDP protection: anchor ownership changed; use recovery tool")}
        let env=try pf.environment()
        guard env.0==j.main,try pf.foreignReferences(j.token)==j.references else{throw fail("UDP protection: foreign PF assets changed")}
        try states()
        j.stage="removing";journal=j;try persist();try pf.removeOwnRules()
        try states()
        j.stage="releasing";journal=j;try persist()
        if let token=j.token,try pf.referencePresent(token){try pf.release(token)}
        let final=try pf.environment()
        guard final.0==j.main,final.2==j.enabled,try pf.foreignReferences(nil)==j.references,
              try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("UDP protection: OFF assets not verified")}
        try remove("udp-session.json");try remove("enable-result.txt");journal=nil
    }
}
