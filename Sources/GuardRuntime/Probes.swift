import Foundation
import GuardCore
import NativeGuard
public struct EchoResult:Codable,Sendable {
    public var ipv4:String;public var measuredAt:UInt64
    public init(ipv4:String,measuredAt:UInt64){self.ipv4=ipv4;self.measuredAt=measuredAt}
}
public struct ProbeResult:Codable,Sendable {public var attempted:Bool;public var reply:Bool;public var setupError:Bool;public var kind:ProbeKind}
public enum ProbeExecutor {
    /// Called only by explicit probe tool/verification transaction, never by inspect/status.
    public static func negative(kind:ProbeKind,physical:InterfaceIdentity) throws -> ProbeResult {
        let spec:(Int32,Int32,String,UInt16,UInt16,Int32)
        switch kind {
        case .boundTCP:spec=(4,1,"1.1.1.1",61001,443,0)
        case .boundUDP:spec=(4,0,"1.1.1.1",61002,53,0)
        case .boundSTUN:spec=(4,0,"74.125.250.129",61003,19302,1)
        case .boundIPv6:throw GuardFailure.unsupported("IPv6 route exists: physical IPv6 probe source requires dedicated validation; MVP refuses to arm")
        }
        var sent:Int32=0;var diagnostics=CSGProbeDiagnostics()
        ProbeWorker.diagnostic("native-start kind=\(kind.rawValue)")
        let r=csg_probe_detailed(spec.0,spec.1,physical.index,physical.ipv4,spec.2,spec.3,spec.4,800,spec.5,&sent,&diagnostics)
        ProbeWorker.diagnostic("native-finish kind=\(kind.rawValue) stage=\(diagnostics.stage) errno=\(diagnostics.error) elapsed_ms=\(diagnostics.elapsed_ms) result=\(r) sent=\(sent)")
        return .init(attempted:sent==1,reply:r==1,setupError:r<0,kind:kind)
    }
    /// Emit fixed diagnostic tags only; raw stderr may contain addresses or credentials.
    static func echoFailure(service:EgressService,status:Int32,stderr:String)->String {
        let text=String(stderr.prefix(4096)).lowercased()
        let known:[(String,String)] = [
            ("ssl_error_syscall","ssl-error-syscall"),
            ("connection reset","connection-reset"),
            ("unexpected eof","unexpected-eof"),
            ("ssl_error_zero_return","tls-closed"),
            ("certificate verify failed","certificate-verification-failed"),
            ("ssl certificate problem","certificate-verification-failed"),
            ("alert handshake failure","tls-handshake-alert"),
            ("alert protocol version","tls-version-alert"),
            ("tlsv1 alert","tls-alert"),
            ("sslv3 alert","tls-alert"),
            ("wrong version number","tls-version-mismatch"),
            ("failed to connect","connect-failed"),
            ("could not resolve host","dns-resolution-failed"),
            ("timed out","timeout")
        ]
        let tags=known.filter{text.contains($0.0)}.map{$0.1}
        let detail=Array(Set(tags)).sorted().joined(separator:",")
        return "HTTPS echo \(service.rawValue) curl exit=\(status) detail="+(detail.isEmpty ? "unclassified":detail)
    }
    public static func egress(service:EgressService,commands:Commands,cancelled:@escaping @Sendable ()->Bool={false}) throws -> String {
        let url=service == .ipify ? "https://api.ipify.org" : "https://ipv4.webshare.io/"
        // -q first suppresses ~/.curlrc. Empty proxy + noproxy suppresses all ambient proxy settings.
        let result=try commands.run("/usr/bin/curl",["-q","--proxy","","--noproxy","*","--ipv4","--proto","=https","--connect-timeout","5","--max-time","8","--fail","--silent","--show-error",url],timeout:10,cancelled:cancelled)
        guard result.status==0 else {
            // curl exit status distinguishes DNS, TCP, TLS, HTTP and timeout failures.
            throw fail(echoFailure(service:service,status:result.status,stderr:result.error))
        }
        let ip=result.output.trimmingCharacters(in:.whitespacesAndNewlines)
        guard IPv4.isPublic(ip) else{throw fail("Invalid HTTPS echo response")};return ip
    }
}
public final class ValidationProbes: @unchecked Sendable {
    private let pf:PacketFilter;private let commands:Commands
    private let record:@Sendable (String)throws->Void
    private let cancelled:@Sendable ()->Bool
    public init(pf:PacketFilter,commands:Commands,record:@escaping @Sendable (String)throws->Void={_ in},cancelled:@escaping @Sendable ()->Bool={false}) {
        self.pf=pf;self.commands=commands;self.record=record;self.cancelled=cancelled
    }
    public static func preflightWorker(commands:Commands,record:@escaping @Sendable (String)throws->Void={_ in},cancelled:@escaping @Sendable ()->Bool={false}) throws -> String {
        try WorkerPreflight.check(run:{path,args,timeout,cancel in try commands.run(path,args,timeout:timeout,cancelled:cancel)},quiescent:{try commands.assertQuiescent()},record:record,cancelled:cancelled)
    }
    private func worker(_ args:[String],stage:String,timeout:TimeInterval) throws -> Data {
        guard !cancelled() else{throw fail("Probe cancelled before worker")}
        try record("worker-start stage=\(stage) deadline=\(timeout)s build=\(BuildIdentity.buildID)")
        do {
            let r=try commands.run(Paths.root+"/guard-probe",args,timeout:timeout,cancelled:cancelled)
            try record("worker-finish stage=\(stage) exit=\(r.status) diagnostics=\(r.error.trimmingCharacters(in:.whitespacesAndNewlines))")
            guard r.status==0 else{throw fail("Probe worker failed at \(stage), exit=\(r.status)")}
            return Data(r.output.utf8)
        }catch let error as CommandFailure {
            try record("worker-error stage=\(stage) \(error) diagnostics=\(error.stderrPrefix.trimmingCharacters(in:.whitespacesAndNewlines))")
            throw error
        }
    }
    public func run(policy:GuardPolicy,baseline:LocalSnapshot,installedAt:UInt64) throws -> ValidationBundle {
        guard !baseline.ipv6Routable else{throw GuardFailure.unsupported("IPv6 path appeared; no real IPv6 probe support in this test build")}
        var negative:[NegativeProbe]=[]
        for kind in [ProbeKind.boundTCP,.boundUDP,.boundSTUN] {
            guard !cancelled() else{throw fail("Probe transaction cancelled")}
            try record("probe-start kind=\(kind.rawValue) counter-read=before")
            let before=try PFText.counter(pf.labels(),label:policy.probeLabel(kind))
            let args=["--negative",kind.rawValue,policy.physical.name,policy.physical.ipv4,String(policy.physical.index)]
            let result=try JSONDecoder().decode(ProbeResult.self,from:worker(args,stage:kind.rawValue,timeout:3))
            try record("probe-worker-returned kind=\(kind.rawValue) counter-read=after")
            let after=try PFText.counter(pf.labels(),label:policy.probeLabel(kind))
            guard result.kind==kind,result.attempted,!result.setupError,!result.reply,after>before else{throw fail("\(kind.rawValue): attempted=\(result.attempted), setupError=\(result.setupError), reply=\(result.reply), packets=\(before)->\(after); blocking unverified")}
            try record("probe-finish kind=\(kind.rawValue) counter=\(before)->\(after) blocked=true")
            negative.append(.init(kind:kind,sessionID:policy.sessionID,epoch:baseline.epoch,ruleFingerprint:policy.rulesFingerprint,dedicatedLabel:policy.probeLabel(kind),tupleMatched:true,failed:true,counterBefore:before,counterAfter:after,measuredAt:monotonic()))
        }
        // Run both HTTPS echoes concurrently in the standalone worker; same kernel protection context.
        let output=try worker(["--egress"],stage:"dual-https",timeout:11)
        let observations=try JSONDecoder().decode([String:EchoResult].self,from:output)
        let egress=try EgressService.allCases.map { service -> EgressObservation in
            guard let sample=observations[service.rawValue],sample.ipv4==policy.endpoint.expectedEgress else{throw fail("Expected egress mismatch")}
            return .init(sessionID:policy.sessionID,epoch:baseline.epoch,ruleFingerprint:policy.rulesFingerprint,service:service,ipv4:sample.ipv4,bypassesSystemProxy:true,tlsVerified:true,measuredAt:sample.measuredAt)
        }
        return .init(sessionID:policy.sessionID,startedAt:installedAt,baseline:baseline,egress:egress,negative:negative)
    }
}
