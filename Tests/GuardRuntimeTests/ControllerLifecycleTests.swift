import Foundation
import Darwin
import Testing
import GuardCore
import NativeGuard
@testable import GuardRuntime

private final class TestClock:GuardClock,@unchecked Sendable {
    private let lock=NSLock();private var uptime:Double=100;private var slept:Double=0
    func sample()->GuardClockSample {lock.lock();defer{lock.unlock()};return .init(uptime:uptime,continuous:uptime+slept)}
    func advance(_ seconds:Double,sleep:Double=0) {lock.lock();uptime += seconds;slept += sleep;lock.unlock()}
}
private final class LifecycleFixture:PacketFiltering,ControllerStorage,RuntimeInspecting,@unchecked Sendable {
    let root:String
    let clock=TestClock()
    var controller:Controller!
    var ipv6:TemporaryIPv6?
    var calls:[String]=[]
    var failure:String?
    func networkEventDiagnostics()->[String] {["type=14 interface=en0 index=12 epoch=2 decision=invalidate signature=test"]}
    var epochValue:UInt64=1
    var identityGeneration:UInt64=1
    var routeFingerprint="routes",routeDetail="route details"
    var localPort:UInt16=50000
    var rules="",reference=false,enabled=false
    var denyPackets:UInt64=10,probePackets:UInt64=3,invalidLabels=false
    var views=0,launches=0
    var beforeView:((Int)->Void)?
    var beforeDiagnostic:(()->Void)?
    var beforeVerify:(()->Void)?
    var onLaunch:(()->Void)?
    var beforeProbe:(()->Void)?
    var healthOverride:(@Sendable ()throws->EgressReport)?
    var afterStage:((String)->Void)?
    var busyWorkers=false,uiPresent=true
    var claude:[ProcessRecord]=[]
    var inventoryIssues:[String]=[]
    var adoptedPath:String?
    var configurationReads=0
    var onConfigurationCheck:(()->Void)?
    var savedInstallation:Installation?
    var saveOverride:((Installation)throws->Void)?
    var onOfficialCheck:(()->Void)?
    var verifiedClaudeHashes:[String]=[]
    var claudeBuildChanged=false
    var socketRows:[CSGSocket]=[]
    let privateFiles:PrivateControllerStorage
    let installation=Installation(uid:501,home:"/nonexistent",clients:[],coreHash:"core",flclashHash:"flclash",claudeHash:"claude")
    init() throws {
        root=FileManager.default.temporaryDirectory.appendingPathComponent("controller-lifecycle-"+UUID().uuidString).path
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        privateFiles=PrivateControllerStorage(root:root,owner:geteuid())
    }
    deinit {try? FileManager.default.removeItem(atPath:root)}
    func step(_ name:String) throws {calls.append(name);if failure==name{throw fail("Injected failure: "+name)}}
    var settings:Settings {var s=Settings();s.gateway="23.20.10.8";s.port=5376;s.expectedEgress="1.1.1.1";s.confirmationFingerprint="config";s.providerConfirmed=true;return s}
    func makeController() throws -> Controller {
        let effects=ControllerEffects(commands:Commands(),pf:self,inspector:self,storage:self,clock:clock,
            uiIdentity:{pid in .init(pid:pid,startTime:1,executableIdentity:"ui")},uiAlive:{[self] _ in uiPresent},
            inventory:{[self] in .init(records:claude,issues:inventoryIssues)},
            terminateClaude:{[self] in try step("terminate");claude=[]},observeSockets:{[self] policy,_ in try step("sockets");return SocketObservationReport.collect(policy:policy,processes:claude.map(\.identity),readProcess:{pid in try #require(self.claude.first{$0.pid==pid})},readSockets:{_ in self.socketRows})},
            preflightWorker:{[self] _,_ in try step("worker-preflight");return "test-worker"},verifyClaude:{[self] expected in verifiedClaudeHashes.append(expected);try step("verify-app");beforeVerify?();if claudeBuildChanged {throw ClaudeBuildChanged()}},
            officialClaudeHash:{[self] _ in try step("official-claude");onOfficialCheck?();return "updated-claude"},
            persistInstallation:{[self] updated in try step("save-installation");if let saveOverride {try saveOverride(updated)} else {savedInstallation=updated}},
            launchClaude:{[self] cancelled in try step("launch");if cancelled(){throw fail("cancelled launch")};launches += 1;onLaunch?()},
            runProbes:{[self] policy,baseline,startedAt,record,cancelled in
                try step("probes");beforeProbe?();if cancelled(){throw fail("cancelled probes")};try record("fake probe complete")
                let measured=UInt64(clock.sample().uptime)
                return .init(sessionID:policy.sessionID,startedAt:startedAt,baseline:baseline,
                    egress:EgressService.allCases.map{.init(sessionID:policy.sessionID,epoch:baseline.epoch,ruleFingerprint:policy.rulesFingerprint,service:$0,ipv4:"1.1.1.1",bypassesSystemProxy:true,tlsVerified:true,measuredAt:measured)},
                    negative:[ProbeKind.boundTCP,.boundUDP,.boundSTUN].map{.init(kind:$0,sessionID:policy.sessionID,epoch:baseline.epoch,ruleFingerprint:policy.rulesFingerprint,dedicatedLabel:policy.probeLabel($0),tupleMatched:true,failed:true,counterBefore:0,counterAfter:1,measuredAt:measured)})
            },healthProbe:{[self] _ in if let healthOverride{return try healthOverride()};throw fail("Injected echo failure")},assertQuiescent:{[self] in try step("quiescent");if busyWorkers{throw fail("workers active")}},boot:{"00000000-0000-0000-0000-000000000001"},ipv6:ipv6)
        let value=try Controller(installation:installation,effects:effects);controller=value;return value
    }
    func configuration(path:String) throws -> NodeConfiguration {try step("candidate");configurationReads+=1;onConfigurationCheck?();var result=try node();if failure=="changed" && configurationReads>1 {result.fingerprint="changed"};return result}
    func adoptConfiguration(path:String) {adoptedPath=path}
    func node() throws -> NodeConfiguration {.init(name:"Webshare-Canada",type:"http",server:"23.20.10.8",port:5376,fingerprint:"config",numeric:true,tunDevice:"utun4")}
    func runtime(settings:Settings) throws -> RuntimeEvidence {
        try step("runtime")
        let core=ProcessIdentity(pid:2345,startTime:100,executableIdentity:"core")
        let physical=InterfaceIdentity(name:"en0",index:6,generation:identityGeneration,ipv4:"172.21.191.84")
        let tun=InterfaceIdentity(name:"utun4",index:20,generation:identityGeneration,ipv4:"198.18.0.1")
        return .init(node:try node(),core:core,connection:.init(owner:core,gateway:"23.20.10.8",port:5376,localAddress:physical.ipv4,localPort:localPort,established:true),network:.init(interfaces:[physical,tun],detail:"interfaces",physical:physical,tun:tun,ipv6Routable:false),inventory:.init(records:claude,issues:inventoryIssues),routeFingerprint:routeFingerprint,routeDetail:routeDetail,epoch:epochValue,claude:claude.map(\.identity))
    }
    func epoch() throws -> UInt64 {try step("epoch");return epochValue}
    func exists(_ name:String)->Bool {privateFiles.exists(name)}
    func readJournal() throws -> Journal {try privateFiles.readJournal()}
    func writeJournal(_ journal:Journal) throws {try step("persist:"+journal.stage);try privateFiles.writeJournal(journal);afterStage?(journal.stage)}
    func remove(_ name:String) throws {try step("remove:"+name);try privateFiles.remove(name)}
    func appendEvent(_ data:Data) throws {try step("log");try privateFiles.appendEvent(data)}
    func writeDiagnostic(_ value:ValidationDiagnostics) throws {try step("diagnostic");try privateFiles.writeDiagnostic(value);beforeDiagnostic?()}
    func writeInventoryDiagnostic(_ json:String) throws {try privateFiles.writeInventoryDiagnostic(json)}
    func writeSocketDiagnostic(_ report:SocketObservationReport) throws {try step("socket-diagnostic");try privateFiles.writeSocketDiagnostic(report)}
    func writeMonitoringDiagnostic(_ value:MonitoringDiagnostics) throws {try step("monitor-diagnostic");try privateFiles.writeMonitoringDiagnostic(value)}
    func environment() throws -> (String,String,Bool) {try step("environment");return("main","",enabled)}
    func states(_ policy:GuardPolicy) throws -> [ExistingState] {try step("states");return []}
    func canonical() throws -> String {try step("canonical");return rules}
    func prepareRules(_ policy:GuardPolicy) throws -> String {try step("prepare");return "owned rules\n"}
    func activateRules(_ policy:GuardPolicy,expected:String) throws {try step("activate");rules=expected}
    func enable(cancelled:@escaping @Sendable ()->Bool) throws -> String {
        try step("enable");if cancelled(){throw fail("cancelled enable")}
        reference=true;enabled=true;try Data("Token : 9\n".utf8).write(to:URL(fileURLWithPath:root+"/enable-result.txt"))
        try step("enable-result");return "9"
    }
    func recoveredToken() throws -> String {try step("recover-token");return "9"}
    func referencePresent(_ token:String) throws -> Bool {try step("reference");return token=="9" && reference}
    func foreignReferences(_ token:String?) throws -> String {try step("foreign-reference");return reference && token != "9" ? "owned-reference":""}
    func view(_ policy:GuardPolicy) throws -> PFView {views += 1;beforeView?(views);try step("view:\(views)");return .init(enabled:enabled,main:"main",references:"",states:[],canonical:rules,labels:invalidLabels ? "unknown" : policy.rules.split(separator:"\n").filter{$0.hasPrefix("block ")}.map { row in
            let label=String(row.split(separator:"\"")[1]);return "\(label) 100 \(label.hasSuffix("_deny") ? denyPackets:probePackets) 100 0 0 0 0"
        }.joined(separator:"\n"))}
    func removeOwnRules() throws {try step("remove-rules");rules=""}
    func release(_ token:String) throws {try step("release");reference=false;enabled=false}
}

struct ControllerLifecycleTests {
    @Test func statusDoesNotCollectOrStopActiveSession() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.inventoryIssues=["unrelated pid transient"]
        let reply=c.handle(.init(.status))
        #expect(reply.ok && c.status.phase=="armed" && c.status.verified)
        #expect(!f.calls.contains("terminate"))
    }
    @Test func incompleteMonitorRecoversWithoutStopButTimeoutStops() throws {
        for recover in [true,false] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            f.inventoryIssues=["unrelated pid transient"];c.tick()
            #expect(c.status.phase=="armed" && !c.status.processInventoryComplete)
            f.clock.advance(recover ? 6:5);c.heartbeat()
            if recover {f.inventoryIssues=[]}
            c.tick()
            #expect(c.status.phase==(recover ? "armed":"recoveryBlocked"))
            #expect(c.status.report.contains(recover ? "recovered":"持续至少 5 秒"))
        }
    }
    @Test func lateCompleteInventoryCannotMaskBrokenPF() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.inventoryIssues=["transient"];c.tick()
        f.clock.advance(6);c.heartbeat();f.inventoryIssues=[];f.reference=false;c.tick()
        #expect(c.status.phase != "armed" && f.calls.contains("terminate"))
    }
    @Test func partialInventoryDoesNotMaskBrokenPFOrInterface() throws {
        for change in ["pf","interface","heartbeat","sleep"] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            f.inventoryIssues=["transient"];c.tick()
            if change=="pf" {f.reference=false}
            else if change=="interface" {f.identityGeneration += 1}
            else if change=="heartbeat" {f.clock.advance(31)}
            else {f.clock.advance(0,sleep:1)}
            c.tick()
            #expect(c.status.phase != "armed")
            #expect(f.calls.contains("terminate"))
        }
    }
    @Test func partialScanCannotClaimClaudeExitedOrAuthorizeStart() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.inventoryIssues=["transient"]
        reject{try c.begin(f.settings,launch:true)}
        #expect(f.launches==0)
        f.inventoryIssues=[];c.heartbeat();try c.begin(f.settings,launch:true)
        f.inventoryIssues=["transient"];c.tick()
        #expect(c.status.phase=="armed" && c.status.claudeKnown==false)
    }

    @Test func ordinaryEpochAtPFInstallationStillGetsCompleteProbes() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.afterStage={if $0=="protected" {f.epochValue += 1}}
        try c.begin(f.settings,launch:true)
        #expect(f.launches==1 && c.status.phase=="armed")
        #expect(f.calls.filter{$0=="probes"}.count==1)
    }
    @Test func armedLaunchBoundaryEventsAreRevalidatedButIdentityChangeStops() throws {
        for stage in ["armed","launch"] {
            for dangerous in [false,true] {
                let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
                f.routeFingerprint=hash(Data(f.routeDetail.utf8))
                let change={f.epochValue += 1;if dangerous {f.identityGeneration += 1}}
                if stage=="armed" {f.afterStage={if $0=="armed" {change()}}}
                else {f.onLaunch=change}
                if dangerous {reject{try c.begin(f.settings,launch:true)};#expect(c.status.phase=="off")}
                else {try c.begin(f.settings,launch:true);#expect(c.status.phase=="armed" && f.launches==1)}
            }
        }
    }
    @Test func retryRejectsRealChangeAndHonorsOFFBeforeSecondProbe() throws {
        for kind in ["interface","path","cancel"] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
            f.beforeProbe={
                if f.calls.filter({$0=="probes"}).count==1 {
                    f.epochValue += 1
                    if kind=="interface" {f.identityGeneration += 1}
                    if kind=="path" {f.routeFingerprint="changed"}
                } else if kind=="cancel" {c.requestStop()}
            }
            reject{try c.begin(f.settings,launch:true)}
            #expect(f.launches==0 && c.status.phase=="off")
            #expect(f.calls.filter{$0=="probes"}.count == (kind=="cancel" ? 2:1))
            #expect(c.status.report.contains("startup network-event"))
        }
    }

    @Test func singleRouteEventRerunsAllStartupProbesBeforeLaunch() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.beforeProbe={if f.calls.filter({$0=="probes"}).count==1 {f.epochValue += 1}}
        try c.begin(f.settings,launch:true)
        #expect(c.status.phase=="armed" && f.launches==1)
        #expect(f.calls.filter{$0=="probes"}.count==2)
        #expect(f.calls.filter{$0=="enable"}.count==1)
        #expect(!f.calls.contains("remove-rules"))
        #expect(c.status.report.contains("startup validation retry"))
    }
    @Test func singleRouteEventDuringAppCheckAlsoRerunsProbes() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.beforeVerify={if f.calls.filter({$0=="verify-app"}).count==1 {f.epochValue += 1}}
        try c.begin(f.settings,launch:true)
        #expect(c.status.phase=="armed" && f.launches==1)
        #expect(f.calls.filter{$0=="probes"}.count==2)
    }

    @Test func offlineSelfTestDoesNotTouchProtectionOrLaunchClaude() throws {
        let f=try LifecycleFixture(),c=try f.makeController();f.calls=[];c.heartbeat()
        let reply=c.handle(.init(.selfTest))
        #expect(reply.ok && reply.status.phase=="off" && !reply.status.verified)
        #expect(f.calls.contains("worker-preflight"))
        #expect(!f.calls.contains("runtime") && !f.calls.contains("activate") && f.launches==0)
        try c.begin(f.settings,launch:false)
        #expect(!c.handle(.init(.selfTest)).ok && c.status.phase=="armed")
        try c.stop(reason:"test")
    }

    @Test func persistentRecoveryFailureIsBoundedAndContinuesAssetChecks() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="terminate";reject{try c.stop(reason:"persistent failure")}
        for _ in 0..<5 {f.clock.advance(5);c.tick()}
        #expect(c.status.phase=="recoveryBlocked" && !c.status.verified && f.reference && !f.rules.isEmpty)
        #expect(f.calls.filter{$0=="terminate"}.count==4)
        #expect(c.status.message.contains("3 次"))
        let views=f.views;f.clock.advance(5);c.tick();#expect(f.views>views)
        #expect(!f.calls.contains("remove-rules"))
        f.failure=nil;_ = c.handle(.init(.stop));#expect(c.status.phase=="off")
    }
    @Test func unknownChangedRulesAreNeverRemovedByAutomaticRecovery() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="terminate";reject{try c.stop(reason:"failure")}
        f.failure=nil;f.rules="foreign change"
        f.clock.advance(5);c.tick()
        #expect(c.status.phase=="recoveryBlocked" && !c.status.verified)
        #expect(f.rules=="foreign change" && !f.calls.contains("remove-rules"))
        #expect(!c.status.monitor.contains("PF 防护运行"))
    }
    @Test func recoveryBlockedRetriesAfterTransientTerminationFailure() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="terminate";reject{try c.stop(reason:"test transient process read")}
        #expect(c.status.phase=="recoveryBlocked" && f.reference && !f.rules.isEmpty)
        #expect(!c.status.monitor.contains("PF 防护运行"))
        f.failure=nil;f.clock.advance(5);c.tick()
        #expect(c.status.phase=="off" && !f.reference && f.rules.isEmpty)
        #expect(!f.exists("session.json"))
    }

    @Test func UDPMetadataDoesNotStopClaudeButPFIntegrityFailureStillDoes() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:true)
        f.claude=[.init(pid:67679,ppid:1,uid:501,started:100,path:"/Applications/Claude.app/Contents/MacOS/Claude",name:"Claude")]
        var socket=CSGSocket();socket.fd=4;socket.family=AF_INET;socket.kind=1
        socket.socket_type=Int32(SOCK_DGRAM);socket.protocol_number=Int32(IPPROTO_UDP);socket.local_port=50000
        withUnsafeMutableBytes(of:&socket.local){$0.copyBytes(from:Array("172.21.191.84".utf8)+[0])}
        f.socketRows=[socket];c.tick()
        #expect(c.status.phase=="armed" && c.status.claude && c.status.verified)
        let data=try Data(contentsOf:URL(fileURLWithPath:f.root+"/last-socket-observation.json"))
        let report=try #require(JSONSerialization.jsonObject(with:data) as? [String:Any])
        let rows=try #require(report["records"] as? [[String:Any]])
        #expect(rows.first?["transport"] as? String=="udp")
        #expect(rows.first?["localScope"] as? String=="physical-source")
        #expect(rows.first?["localPort"] as? Int==50000)
        #expect(report["sessionID"] as? String==(try f.readJournal()).policy.sessionID.uuidString)
        // Diagnostic work is bounded/rate limited; primary PF verification is not skipped.
        let samples=f.calls.filter{$0=="sockets"}.count
        c.tick();#expect(f.calls.filter{$0=="sockets"}.count==samples)
        f.clock.advance(5);c.heartbeat();c.tick();#expect(f.calls.filter{$0=="sockets"}.count==samples+1)
        f.rules="tampered rules";c.tick()
        #expect(c.status.phase=="recoveryBlocked" || c.status.phase=="off")
        #expect(!c.status.verified && f.claude.isEmpty)
        #expect(c.status.lastRisk.contains("PF rule history integrity lost"))
    }
    @Test func optionalSocketDiagnosticDiskFailureDoesNotClaimLeakage() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="socket-diagnostic";c.tick()
        #expect(c.status.phase=="armed" && c.status.verified)
        #expect(c.status.monitor.contains("诊断保存失败"))
        #expect(c.status.lastRisk.isEmpty)
    }
    @Test func passiveSocketReadFailureDoesNotTerminateProtectedClaude() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        try c.begin(f.settings,launch:true)
        f.claude=[.init(pid:67679,ppid:1,uid:501,started:100,path:"/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",name:"Claude Helper")]
        let terminations=f.calls.filter{$0=="terminate"}.count
        f.failure="sockets";c.tick()
        #expect(c.status.phase=="armed" && c.status.verified)
        #expect(f.reference && !f.rules.isEmpty)
        #expect(f.calls.filter{$0=="terminate"}.count==terminations)
    }

    @Test func actualControllerCompletesVerifyAndOrderedOFFWithoutExternalEffects() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        #expect(c.status.phase=="armed" && c.status.verified);#expect(f.launches==0);#expect(f.exists("session.json"))
        try c.stop(reason:"test OFF")
        #expect(c.status.phase=="off" && !c.status.verified);#expect(!f.reference && f.rules.isEmpty)
        #expect(!f.exists("session.json") && !f.exists("enable-result.txt"))
        let terminate=f.calls.firstIndex(of:"terminate")!,remove=f.calls.firstIndex(of:"remove-rules")!,release=f.calls.firstIndex(of:"release")!
        #expect(terminate<remove && remove<release)
        #expect(f.calls.contains("worker-preflight"));#expect(f.calls.contains("quiescent"))
    }
    @Test func startRequiresFreshIndependentUIHeartbeatBeforeAnyPFEffect() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        reject{try c.begin(f.settings,launch:true)}
        #expect(!f.calls.contains("activate") && f.launches==0)
    }
    @Test func lostHeartbeatDuringFinalDiagnosticCannotArmOrLaunch() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.beforeDiagnostic={f.clock.advance(7)}
        reject{try c.begin(f.settings,launch:true)}
        #expect(f.launches==0 && c.status.phase=="off");#expect(!f.calls.contains("persist:armed"))
    }
    @Test func exitedUIWithinHeartbeatGraceCannotLaunch() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.beforeVerify={f.uiPresent=false}
        reject{try c.begin(f.settings,launch:true)}
        #expect(f.launches==0 && c.status.phase=="off")
    }
    @Test func independentOFFDuringValidationCancelsBeforeArming() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();f.beforeProbe={c.requestStop()}
        reject{try c.begin(f.settings,launch:true)}
        #expect(f.launches==0 && c.status.phase=="off" && f.rules.isEmpty && !f.reference)
    }
    @Test func networkEventDuringFinalPFReadCannotPassTheFinalSnapshot() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.beforeView={if $0==3{f.epochValue += 1}}
        reject{try c.begin(f.settings,launch:true)}
        #expect(f.launches==0 && c.status.phase=="off");#expect(!f.calls.contains("persist:armed"))
    }
    @Test func cancellationOrEpochChangeDuringAppIdentityCheckCannotLaunch() throws {
        for cancel in [false,true] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
            f.beforeVerify={if cancel{c.requestStop()}else{f.epochValue += 1}}
            reject{try c.begin(f.settings,launch:true)}
            #expect(f.launches==0 && c.status.phase=="off")
        }
    }
    @Test func probeFailureRollsBackOnlyAfterWorkersAreConfirmedStopped() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();f.failure="probes";f.busyWorkers=true
        reject{try c.begin(f.settings,launch:true)}
        #expect(c.status.phase=="recoveryBlocked");#expect(f.reference && !f.rules.isEmpty)
        #expect(!f.calls.contains("remove-rules"))
        f.failure=nil;f.busyWorkers=false;try c.stop(reason:"retry")
        #expect(c.status.phase=="off" && !f.exists("session.json"))
    }
    @Test func persistedStageAndEffectFailuresEitherRestoreOFFOrRetainRecoveryAssets() throws {
        for stage in ["worker-preflight","persist:intent","prepare","persist:prepared","persist:loading-rules","activate","persist:enabling","enable","enable-result","persist:protected","probes","view:3","diagnostic","persist:armed","verify-app","launch"] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();f.failure=stage
            reject{try c.begin(f.settings,launch:true)}
            #expect(f.launches==0)
            #expect(c.status.phase=="off" || c.status.phase=="recoveryBlocked")
            if c.status.phase=="off" {#expect(f.rules.isEmpty && !f.reference && !f.exists("session.json"))}
            else {#expect(f.exists("session.json") || f.exists("enable-result.txt"))}
        }
    }
    @Test func failedCleanupRetainsJournalAndRetryFinishesOFF() throws {
        for failure in ["remove-rules","states","release","remove:session.json","remove:enable-result.txt"] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            f.failure=failure;reject{try c.stop(reason:"injected OFF failure")}
            #expect(c.status.phase=="recoveryBlocked" && !c.status.verified)
            #expect(f.exists("session.json") || f.exists("enable-result.txt"))
            f.failure=nil;try c.stop(reason:"retry")
            #expect(c.status.phase=="off" && !f.exists("session.json") && !f.exists("enable-result.txt"))
        }
    }
    @Test func longActiveSnapshotDoesNotMasqueradeAsSystemSleep() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.beforeView={_ in f.clock.advance(4);c.heartbeat()}
        c.tick();#expect(c.status.phase=="armed")
        f.clock.advance(1,sleep:10);c.heartbeat();c.tick()
        #expect(c.status.phase=="off" && f.rules.isEmpty)
    }
    @Test func sameBootHelperRestartDoesNotMistakeEmptyRegistryForWorkerAbsence() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        let recovered=try f.makeController()
        #expect(recovered.status.phase=="recoveryBlocked" && f.launches==0)
        #expect(f.reference && !f.rules.isEmpty && f.exists("session.json"))
        reject{try recovered.stop(reason:"attempt after crash")}
        #expect(!f.calls.contains("remove-rules"))
        recovered.tick();#expect(f.reference && !f.rules.isEmpty)
    }
}

struct MonitoringDiagnosticLifecycleTests {
    private func report(_ f:LifecycleFixture) throws -> [String:Any] {
        try #require(JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:f.root+"/last-monitoring-failure.json"))) as? [String:Any])
    }
    @Test func recordsFailedSnapshotAndLastSuccessfulSampleBeforeTheyAreDiscardedByOFF() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.localPort=60000;c.tick();#expect(c.status.phase=="armed")
        f.routeFingerprint="routes-changed";f.routeDetail="changed gateway/flags";c.tick()
        #expect(c.status.phase=="off" && !c.status.verified)
        #expect(c.status.lastRisk.contains("routeFingerprint"))
        let value=try report(f)
        #expect(value["changedFields"] as? [String]==["routeFingerprint"])
        #expect((value["baseline"] as? [String:Any])?["routeFingerprint"] as? String=="routes")
        #expect((value["previousHealthy"] as? [String:Any])?["routeFingerprint"] as? String=="routes")
        #expect((value["current"] as? [String:Any])?["routeFingerprint"] as? String=="routes-changed")
        #expect(value["currentRoutes"] as? String=="changed gateway/flags")
        #expect(value["recoveryPhase"] as? String=="off")
        #expect((value["networkEvents"] as? [String])==f.networkEventDiagnostics())
        #expect(c.status.report.contains("network-event type=14 interface=en0"))
        let previous=try #require(value["previousHealthy"] as? [String:Any]),original=try #require(value["baseline"] as? [String:Any])
        #expect((previous["connection"] as? [String:Any])?["localPort"] as? Int==60000)
        #expect((original["connection"] as? [String:Any])?["localPort"] as? Int==50000)
        #expect(f.calls.lastIndex(of:"remove-rules")! < f.calls.lastIndex(of:"monitor-diagnostic")!)
        let data=try Data(contentsOf:URL(fileURLWithPath:f.root+"/last-monitoring-failure.json"))
        #expect(!String(decoding:data,as:UTF8.self).contains("\"ownReference\":\"9\""))
        var st=stat();#expect(lstat(f.root+"/last-monitoring-failure.json",&st)==0 && st.st_mode&0o077==0)
    }
    @Test func incompleteRuntimeIsMarkedUnavailableAndNeverInventsAFailedSnapshot() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="runtime";c.tick()
        let value=try report(f)
        #expect(value["stage"] as? String=="runtimeCollection")
        #expect(value["current"]==nil || value["current"] is NSNull)
        #expect(value["currentComplete"] as? Bool==false)
        #expect(c.status.phase=="off")
    }
    @Test func diagnosticWriteFailureCannotPreventOFFOrRestoreGreen() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="monitor-diagnostic";f.routeFingerprint="routes-changed";c.tick()
        #expect(c.status.phase=="off" && !c.status.verified && f.rules.isEmpty && !f.reference)
        #expect(c.status.report.contains("monitor diagnostic persistence failed"))
    }
}

struct MonitoringHealthDiagnosticTests {
    @Test func failedAsynchronousHealthEchoDoesNotPretendToHaveAFailedLocalSnapshot() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        try c.queue.sync {c.heartbeat();try c.begin(f.settings,launch:false);f.clock.advance(16);c.heartbeat();c.tick()}
        for round in 1...3 {
            for _ in 0..<100 {
                if c.queue.sync(execute:{(c.status.periodicEgress?.failures ?? 0)>=round}){break}
                Thread.sleep(forTimeInterval:0.005)
            }
            if round<3 {
                #expect(c.queue.sync{c.status.phase}=="armed")
                #expect(c.queue.sync{c.status.egressRechecking}==true)
                c.queue.sync {f.clock.advance(300);c.heartbeat();c.tick()}
            }
        }
        #expect(c.queue.sync{c.status.phase}=="armed")
        #expect(c.queue.sync{c.status.egressWarning != nil && c.status.periodicEgress?.failures==3})
        #expect(!FileManager.default.fileExists(atPath:f.root+"/last-monitoring-failure.json"))
        #expect(c.queue.sync{f.reference && !f.rules.isEmpty && !f.calls.contains("terminate")})
    }
}

struct MonitoringBlockedRecoveryTests {
    @Test func automaticRecoveryRefreshesExitConfirmation() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:true)
        f.failure="terminate";f.routeFingerprint="routes-changed";c.tick()
        #expect(c.status.phase=="recoveryBlocked")
        #expect(c.status.interruption?.exitConfirmed==false)
        f.failure=nil;f.clock.advance(5);c.tick()
        #expect(c.status.phase=="off")
        #expect(c.status.interruption?.exitConfirmed==true)
    }

    @Test func diagnosticAccuratelyRecordsRecoveryBlockedWithoutRemovingTheRemainingProtection() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.failure="remove-rules";f.routeFingerprint="routes-changed";c.tick()
        #expect(c.status.phase=="recoveryBlocked" && !c.status.verified)
        #expect(f.reference && !f.rules.isEmpty && f.exists("session.json"))
        let data=try Data(contentsOf:URL(fileURLWithPath:f.root+"/last-monitoring-failure.json"))
        let value=try #require(JSONSerialization.jsonObject(with:data) as? [String:Any])
        #expect(value["recoveryPhase"] as? String=="recoveryBlocked")
        #expect(value["changedFields"] as? [String]==["routeFingerprint"])
    }
}


// Replays the captured 0.2.9 failure through the real Controller. Only external effects are substituted.
struct PublicRouteCloneLifecycleTests {
    @Test func routeRevalidationCannotHidePFOrInterfaceChanges() throws {
        for change in ["identity","route","pf"] {
            let f=try LifecycleFixture(),c=try f.makeController()
            f.routeFingerprint=hash(Data(f.routeDetail.utf8))
            c.heartbeat();try c.begin(f.settings,launch:false)
            f.epochValue += 1
            if change=="identity" {f.identityGeneration += 1}
            if change=="route" {f.routeDetail="changed";f.routeFingerprint=hash(Data(f.routeDetail.utf8))}
            if change=="pf" {f.rules="tampered"}
            c.tick()
            #expect(c.status.phase != "armed")
            #expect(f.calls.contains("terminate"))
        }
    }
    @Test func repeatedStartupRouteNotificationsExhaustOneRetry() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        f.routeFingerprint=hash(Data(f.routeDetail.utf8))
        c.heartbeat();f.beforeProbe={f.epochValue += 1}
        reject {try c.begin(f.settings,launch:true)}
        #expect(f.launches==0)
        #expect(f.calls.filter{$0=="probes"}.count==2)
        #expect(c.status.lastRisk.contains("retry exhausted"))
        let data=try Data(contentsOf:URL(fileURLWithPath:f.root+"/last-validation.json"))
        let diagnostic=try JSONDecoder().decode(ValidationDiagnostics.self,from:data)
        #expect(diagnostic.attempt==2 && diagnostic.networkEvents?.isEmpty==false)
    }
    @Test func routeNotificationWithIdenticalProtectedEvidenceDoesNotStop() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        f.routeFingerprint=hash(Data(f.routeDetail.utf8))
        c.heartbeat();try c.begin(f.settings,launch:false)
        f.epochValue += 1;c.tick()
        #expect(c.status.phase=="armed")
        #expect(f.reference && !f.rules.isEmpty)
        #expect(!f.calls.contains("terminate"))
        #expect(c.status.report.contains("route notification revalidated"))
    }

    private func routes() throws -> (parent:String,clone:String) {
        let file=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/public-route-clone-029.json")
        let data=try #require(JSONSerialization.jsonObject(with:Data(contentsOf:file)) as? [String:String])
        return (try #require(data["parent"]),try #require(data["clone"]))
    }
    private func setRoute(_ text:String,on f:LifecycleFixture) {f.routeDetail=text;f.routeFingerprint=hash(Data(text.utf8))}
    @Test func auxiliaryLinkLocalRotationDoesNotStopButOtherChangesDo() throws {
        let r=try routes()
        let before=r.parent.replacingOccurrences(of:"fe80::ac85:eaff:fe76:69f7",with:"fe80::1")
        let rotated=before.replacingOccurrences(of:"fe80::1%awdl0",with:"fe80::2%awdl0").replacingOccurrences(of:"fe80::1%llw0",with:"fe80::2%llw0")
        let f=try LifecycleFixture();setRoute(before,on:f)
        let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        setRoute(rotated,on:f);c.tick()
        #expect(c.status.phase=="armed")
        for changed in [rotated.replacingOccurrences(of:"fe80::1%lo0",with:"fe80::2%lo0"),
                        rotated.replacingOccurrences(of:"fe80::2%awdl0",with:"192.0.2.1"),
                        rotated.replacingOccurrences(of:"fe80::2%awdl0",with:"2001:db8::2%awdl0"),
                        rotated.replacingOccurrences(of:"awdl0:13:",with:"awdl0:99:"),
                        rotated.replacingOccurrences(of:"awdl0:13:34915",with:"awdl0:13:1"),
                        rotated.replacingOccurrences(of:"gateway=198.18.0.1",with:"gateway=198.18.0.2")] {
            let f=try LifecycleFixture();setRoute(before,on:f)
            let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            setRoute(changed,on:f);c.tick();#expect(c.status.phase=="off")
        }
        let startup=try LifecycleFixture();setRoute(before,on:startup)
        let launch=try startup.makeController();launch.heartbeat()
        startup.beforeProbe={setRoute(rotated,on:startup)}
        reject{try launch.begin(startup.settings,launch:true)}
        #expect(startup.launches==0)
    }
    @Test func automaticStopReportsOnlyConfirmedTerminationAndManualOFFDoesNotAlert() throws {
        let r=try routes()
        for terminationFails in [false,true] {
            let f=try LifecycleFixture();setRoute(r.parent,on:f)
            let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:true)
            if terminationFails {f.failure="terminate"}
            setRoute(r.parent.replacingOccurrences(of:"gateway=172.21.128.1",with:"gateway=172.21.128.2"),on:f)
            c.tick()
            let event=try #require(c.status.interruption)
            #expect(event.requestedClaudeStop)
            #expect(event.exitConfirmed == !terminationFails)
            #expect(c.status.phase == (terminationFails ? "recoveryBlocked":"off"))
        }
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:true)
        try c.stop(reason:"用户关闭安全模式")
        #expect(c.status.interruption==nil)
    }
    @Test func capturedSlowStartChangeIsRuntimeEquivalentButPathChangesStillStop() throws {
        let file=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/route-ssthresh-043.json")
        let data=try JSONDecoder().decode([String:String].self,from:Data(contentsOf:file))
        let before=try #require(data["baseline"]),after=try #require(data["current"])
        let f=try LifecycleFixture();setRoute(before,on:f)
        let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        setRoute(after,on:f);c.tick()
        #expect(c.status.phase=="armed" && c.status.verified)
        for changed in [after.replacingOccurrences(of:"ssthresh=1680",with:"ssthresh=1680L"),
                        after.replacingOccurrences(of:"gateway=172.21.128.1",with:"gateway=172.21.128.2"),
                        after.replacingOccurrences(of:"mtu=1500",with:"mtu=1400"),
                        after.replacingOccurrences(of:"ssthresh=1680",with:"ssthresh=invalid")] {
            let f=try LifecycleFixture();setRoute(before,on:f)
            let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            setRoute(changed,on:f);c.tick();#expect(c.status.phase=="off")
            #expect(c.status.interruption?.requestedClaudeStop==false)
            #expect(c.status.interruption?.exitConfirmed==false)
        }
        let g=try LifecycleFixture();setRoute(before,on:g)
        let startup=try g.makeController();startup.heartbeat();g.beforeProbe={setRoute(after,on:g)}
        reject{try startup.begin(g.settings,launch:true)}
        #expect(g.launches==0)
    }
    @Test func capturedParentToCloneAndBackDoesNotEndAnArmedSession() throws {
        let r=try routes(),f=try LifecycleFixture();setRoute(r.parent,on:f)
        let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        for text in [r.clone,r.clone,r.parent,r.clone] {
            setRoute(text,on:f);f.localPort += 1;c.tick()
            #expect(c.status.phase=="armed" && c.status.verified)
        }
        #expect(c.status.report.components(separatedBy:"monitor route equivalent").count-1==2)
        #expect(!f.exists("last-monitoring-failure.json"))
        try c.stop(reason:"normal OFF after clone replay")
        #expect(c.status.phase=="off" && f.rules.isEmpty && !f.reference && !f.exists("session.json"))
    }
    @Test func cloneBaselineCanReturnToItsCoveringParentDuringMonitoring() throws {
        let r=try routes(),f=try LifecycleFixture();setRoute(r.clone,on:f)
        let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        setRoute(r.parent,on:f);c.tick()
        #expect(c.status.phase=="armed" && c.status.verified)
        try c.stop(reason:"test OFF")
    }
    @Test func startupStillRejectsTheSameCloneTransitionBeforeFinalSnapshot() throws {
        let r=try routes(),f=try LifecycleFixture();setRoute(r.parent,on:f)
        let c=try f.makeController();c.heartbeat();f.beforeProbe={setRoute(r.clone,on:f)}
        reject{try c.begin(f.settings,launch:true)}
        #expect(c.status.phase=="off" && !c.status.verified && f.launches==0)
        #expect(c.status.lastRisk.contains("Final premises changed"))
    }
    @Test func validCloneCannotHideAnotherChangedPremiseAndDiagnosticKeepsTheRawEvidence() throws {
        let r=try routes(),f=try LifecycleFixture();setRoute(r.parent,on:f)
        let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        setRoute(r.clone,on:f);f.epochValue += 1;f.identityGeneration += 1;c.tick()
        #expect(c.status.phase=="off" && !c.status.verified && c.status.lastRisk.contains("Incomplete runtime"))
        let value=try #require(JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:f.root+"/last-monitoring-failure.json"))) as? [String:Any])
        #expect(value["acceptedRouteEquivalence"] as? Bool==false)
        #expect(value["changedFields"] as? [String]==["epoch","interfaces","routeFingerprint","verifiedTun"])
        #expect(value["rawChangedFields"] as? [String]==["epoch","interfaces","routeFingerprint","verifiedTun"])
        #expect(value["currentRoutes"] as? String==r.clone)
    }
    @Test func hashMismatchCannotBeUsedAsAnEquivalenceProof() throws {
        let r=try routes(),f=try LifecycleFixture();setRoute(r.parent,on:f)
        let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        setRoute(r.clone,on:f);f.routeFingerprint="unbound-hash";c.tick()
        #expect(c.status.phase=="off" && !c.status.verified)
    }
    @Test func invalidParentAndUnrecognizedCanonicalDataCannotAuthorizeAClone() throws {
        let r=try routes()
        let invalidParents=[
            r.parent.replacingOccurrences(of:"destination=1.0.0.0",with:"destination=2.0.0.0"),
            r.parent.replacingOccurrences(of:"destination=1.0.0.0",with:"destination=1.1.0.1"),
            r.parent.replacingOccurrences(of:"mask=255.0.0.0",with:"mask=255.0.255.0"),
            r.parent.replacingOccurrences(of:"mask=255.0.0.0",with:"mask=255.255.255.255"),
            r.parent.replacingOccurrences(of:"STATIC,PRCLONING",with:"STATIC,PRCLONING,REJECT"),
            r.parent.replacingOccurrences(of:"recvpipe=0",with:"recvpipe=0\nunknown=ignored"),
            r.parent.replacingOccurrences(of:"recvpipe=0",with:"recvpipe=0\nrecvpipe=0"),
            r.parent.replacingOccurrences(of:"rtt,msec=dynamic",with:"rtt,msec=1L")
        ]
        for parent in invalidParents {
            let f=try LifecycleFixture();setRoute(parent,on:f)
            let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            setRoute(r.clone,on:f);c.tick()
            #expect(c.status.phase=="off" && !c.status.verified)
        }
    }
    @Test func changedPathFlagsMetricsInventoryOrGatewaySectionsStillEndTheSession() throws {
        let r=try routes()
        let changes=[
            r.clone.replacingOccurrences(of:"gateway=198.18.0.1",with:"gateway=198.18.0.2"),
            r.clone.replacingOccurrences(of:"interface=utun4",with:"interface=en0"),
            r.clone.replacingOccurrences(of:"mtu=9000",with:"mtu=1500"),
            r.clone.replacingOccurrences(of:"HOST,DONE,WASCLONED",with:"HOST,DONE,BLACKHOLE,WASCLONED"),
            r.clone.replacingOccurrences(of:"HOST,DONE,WASCLONED",with:"HOST,DONE,WASCLONED,UNKNOWN"),
            r.clone.replacingOccurrences(of:"route to=1.1.1.1",with:"route to=1.1.1.2"),
            r.clone.replacingOccurrences(of:"utun4:19:",with:"utun4:99:"),
            r.clone.replacingOccurrences(of:"gateway=172.21.128.1",with:"gateway=172.21.128.2"),
            r.clone.replacingOccurrences(of:"destination=64.0.0.0",with:"destination=1.1.1.1"),
            r.parent.replacingOccurrences(of:"destination=1.0.0.0",with:"destination=2.0.0.0"),
            r.clone+"\nunknown=ignored"
        ]
        for changed in changes {
            let f=try LifecycleFixture();setRoute(r.parent,on:f)
            let c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            setRoute(changed,on:f);c.tick()
            #expect(c.status.phase=="off" && !c.status.verified)
            #expect(c.status.lastRisk.contains("routeFingerprint"))
            let diagnostic=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:f.root+"/last-monitoring-failure.json"))) as? [String:Any]
            #expect(diagnostic?["currentRoutes"] as? String==changed)
        }
    }
}

struct IPv6ControllerTests {
    @Test func noPFStopFailureCannotRemainOff() throws {
        let f=try LifecycleFixture(),box=IPv6Fixture()
        f.ipv6=TemporaryIPv6(store:box.store,backend:box.backend)
        let c=try f.makeController();c.heartbeat()
        #expect(c.handle(.init(.ipv6Off,settings:f.settings)).ok)
        f.failure="terminate"
        #expect(!c.handle(.init(.shutdown)).ok)
        #expect(c.status.phase=="recoveryBlocked" && !c.status.verified && box.saved != nil)
        #expect(box.current.method=="Off")
        f.failure=nil
        #expect(c.handle(.init(.shutdown)).ok)
        #expect(c.status.phase=="off" && box.saved==nil)
    }

    @Test func leaseRestoresOnHeartbeatLossAndRejectsArmedToggle() throws {
        let f=try LifecycleFixture(),box=IPv6Fixture()
        f.ipv6=TemporaryIPv6(store:box.store,backend:box.backend)
        let c=try f.makeController();c.heartbeat()
        #expect(c.handle(.init(.ipv6Off,settings:f.settings)).ok)
        #expect(box.current.method=="Off")
        try c.begin(f.settings,launch:false)
        #expect(!c.handle(.init(.ipv6Automatic,settings:f.settings)).ok)
        #expect(box.current.method=="Off" && c.status.phase=="armed")
        try c.stop(reason:"test")
        #expect(box.current==box.original && box.saved==nil)
        c.heartbeat();#expect(c.handle(.init(.ipv6Off,settings:f.settings)).ok)
        f.clock.advance(7);c.tick()
        #expect(box.saved==nil && c.status.phase=="off")
    }
    @Test func restoreConflictDoesNotClaimOffAndStartupRestoresPersistedLease() throws {
        let f=try LifecycleFixture(),box=IPv6Fixture()
        f.ipv6=TemporaryIPv6(store:box.store,backend:box.backend)
        try f.ipv6!.set(.off,interface:"en0")
        let c=try f.makeController()
        #expect(box.saved==nil)
        c.heartbeat();#expect(c.handle(.init(.ipv6Off,settings:f.settings)).ok)
        box.current=try .init(serviceID:"wifi",interface:"en0",enabled:true,configuration:["ConfigMethod":"LinkLocal"])
        #expect(!c.handle(.init(.shutdown)).ok)
        #expect(c.status.phase=="recoveryBlocked" && box.saved != nil)
    }
}

struct NormalStopIntentTests {
    @Test func monitoringTickBetweenStopAdmissionAndHandlingIsNormal() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        c.heartbeat();try c.begin(f.settings,launch:true)
        // The IPC listener receives OFF before the transaction queue handles it.
        c.requestStop();c.tick()
        #expect(c.status.phase=="off" && !c.status.verified)
        #expect(c.status.interruption==nil)
        #expect(c.status.lastRisk.isEmpty)
        #expect(f.calls.firstIndex(of:"terminate")! < f.calls.firstIndex(of:"remove-rules")!)
    }
    @Test func manualOffRetainsIPv6WhileAppAlive() throws {
        let f=try LifecycleFixture(),box=IPv6Fixture()
        f.ipv6=TemporaryIPv6(store:box.store,backend:box.backend)
        let c=try f.makeController();c.heartbeat()
        #expect(c.handle(.init(.ipv6Off,settings:f.settings)).ok)
        try c.begin(f.settings,launch:false)
        #expect(c.handle(.init(.stop)).ok)
        c.heartbeat();c.tick()
        #expect(c.status.phase=="off" && box.current.method=="Off" && box.saved != nil)
        f.clock.advance(7);c.tick()
        #expect(box.current==box.original && box.saved==nil)
    }
}

struct StopRaceAndLeaseTests {
    @Test func userStopDuringSnapshotDoesNotWriteIncident() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.beforeView={_ in f.beforeView=nil;c.requestStop()}
        c.tick()
        #expect(c.status.phase=="off" && c.status.interruption==nil)
        #expect(!FileManager.default.fileExists(atPath:f.root+"/last-monitoring-failure.json"))
    }
    @Test func realStopFailureKeepsProtectionAndDoesNotClaimNormalCompletion() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:true)
        f.failure="terminate"
        let reply=c.handle(.init(.stop))
        #expect(!reply.ok && c.status.phase=="recoveryBlocked" && !f.rules.isEmpty && f.reference)
    }
    @Test func quitRestoresLeaseAfterNormalStopAndSelfTestDoesNotRestoreIt() throws {
        let f=try LifecycleFixture(),box=IPv6Fixture();f.ipv6=TemporaryIPv6(store:box.store,backend:box.backend)
        let c=try f.makeController();c.heartbeat()
        #expect(c.handle(.init(.ipv6Off,settings:f.settings)).ok)
        #expect(c.handle(.init(.stop)).ok)
        #expect(c.handle(.init(.selfTest)).ok)
        c.tick();#expect(box.current.method=="Off" && box.saved != nil)
        #expect(c.handle(.init(.shutdown)).ok)
        #expect(box.current==box.original && box.saved==nil)
    }
}

struct HeartbeatLoadTests {
    @Test func armedAllowsBriefHeartbeatDelayWithoutRemovingPF() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.clock.advance(10);c.tick()
        #expect(c.status.phase=="armed" && c.status.verified)
        #expect(f.reference && !f.rules.isEmpty && !f.calls.contains("terminate"))
        #expect(c.status.heartbeatDiagnostic?.ageSeconds==10 && c.status.heartbeatDiagnostic?.delayed==true)
        c.heartbeat();c.tick();#expect(c.status.phase=="armed")
        #expect(c.status.heartbeatDiagnostic?.delayed==false && c.status.heartbeatDiagnostic?.maxGapSeconds==10)
    }
    @Test func delayedHeartbeatDoesNotExcusePFChangeOrExitedUI() throws {
        for exited in [true,false] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
            f.clock.advance(10)
            if exited {f.uiPresent=false} else {f.rules="tampered"}
            c.tick();#expect(c.status.phase != "armed");#expect(f.calls.contains("terminate"))
        }
    }
    @Test func prolongedHeartbeatLossStillTerminatesBeforeRemovingRules() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.clock.advance(30);c.tick()
        #expect(c.status.phase=="off" && c.status.lastRisk.contains("UI heartbeat lost"))
        #expect(try #require(f.calls.firstIndex(of:"terminate")) < #require(f.calls.firstIndex(of:"remove-rules")))
    }
}

struct BlockStatisticsLifecycleTests {
    @Test func excludesPreArmPacketsAndRetainsLastSampleOnOFF() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        #expect(c.status.blockedPackets==0)
        f.denyPackets+=7;f.probePackets+=1;c.tick()
        #expect(c.status.blockedPackets==11) // Four probe labels plus the default deny.
        #expect(c.status.phase=="armed")
        try c.stop(reason:"test");#expect(c.status.blockedPackets==11)
        c.heartbeat();try c.begin(f.settings,launch:false);#expect(c.status.blockedPackets==0)
    }
    @Test func unreadableOrResetStatisticsNeverFabricateZeroOrStopProtection() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        f.invalidLabels=true;c.tick();#expect(c.status.blockedPackets==nil && c.status.phase=="armed")
        f.invalidLabels=false;f.denyPackets+=2;c.tick();#expect(c.status.blockedPackets==2)
        f.denyPackets=0;c.tick();#expect(c.status.blockedPackets==nil && c.status.phase=="armed")
        f.denyPackets=100;c.tick();#expect(c.status.blockedPackets==nil) // Reset invalidates baseline for this session.
    }
}

struct PeriodicEgressControllerTests {
    func waitForResult(_ c:Controller) {
        for _ in 0..<200 {
            if c.queue.sync(execute:{c.status.periodicEgress != nil}) {return}
            Thread.sleep(forTimeInterval:0.005)
        }
    }
    @Test func echoCompletionRevalidatesChangedRouteEpochButNeverPFOrIdentity() throws {
        for change in ["route-only","identity","pf"] {
            let f=try LifecycleFixture(),c=try f.makeController()
            f.routeFingerprint=hash(Data(f.routeDetail.utf8))
            let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0)
            f.healthOverride={
                entered.signal()
                guard release.wait(timeout:.now()+5) == .success else{throw fail("test synchronization timeout")}
                let now=f.clock.sample().uptime
                return EgressMonitorTests().report("1.1.1.1","1.1.1.1",finished:now)
            }
            try c.queue.sync {c.heartbeat();try c.begin(f.settings,launch:false);f.clock.advance(15);c.heartbeat();c.tick()}
            #expect(entered.wait(timeout:.now()+5) == .success)
            c.queue.sync {
                f.epochValue += 1
                if change=="identity" {f.identityGeneration += 1}
                if change=="pf" {f.rules="tampered"}
            }
            release.signal()
            for _ in 0..<200 {
                if c.queue.sync(execute:{c.status.periodicEgress != nil || c.status.phase != "armed"}) {break}
                Thread.sleep(forTimeInterval:0.005)
            }
            if change=="route-only" {
                #expect(c.queue.sync{c.status.phase}=="armed")
                #expect(c.queue.sync{c.status.report.contains("revalidated before egress")})
            } else {#expect(c.queue.sync{c.status.phase} != "armed")}
        }
    }
    @Test func unavailableEgressWarnsAfterFiveMinutesWithoutRemovingProtection() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        f.healthOverride={let now=f.clock.sample().uptime;return EgressMonitorTests().report(nil,nil,finished:now)}
        func awaitFailures(_ count:Int) {
            for _ in 0..<200 {
                if c.queue.sync(execute:{c.status.periodicEgress?.failures==count}) {return}
                Thread.sleep(forTimeInterval:0.005)
            }
        }
        try c.queue.sync {c.heartbeat();try c.begin(f.settings,launch:false);f.clock.advance(15);c.heartbeat();c.tick()}
        awaitFailures(1)
        #expect(c.queue.sync{c.status.egressRechecking==true && c.status.egressWarning==nil && c.status.phase=="armed"})
        #expect(c.queue.sync{c.status.periodicEgress?.retryAfterSeconds}==300)
        c.queue.sync {f.clock.advance(299);c.heartbeat();c.tick()}
        #expect(c.queue.sync{c.status.periodicEgress?.failures}==1)
        c.queue.sync {f.clock.advance(1);c.heartbeat();c.tick()}
        awaitFailures(2)
        let id=c.queue.sync{c.status.egressWarning?.id}
        #expect(id != nil)
        #expect(c.queue.sync{c.status.phase=="armed" && f.reference && !f.rules.isEmpty && !f.calls.contains("terminate")})
        c.queue.sync {f.clock.advance(300);c.heartbeat();c.tick()}
        awaitFailures(3)
        #expect(c.queue.sync{c.status.egressWarning?.id}==id)
        f.healthOverride={let now=f.clock.sample().uptime;return EgressMonitorTests().report("1.1.1.1",nil,finished:now)}
        c.queue.sync {f.clock.advance(300);c.heartbeat();c.tick()}
        awaitFailures(0)
        #expect(c.queue.sync{c.status.egressWarning==nil && c.status.egressRechecking==false && c.status.phase=="armed"})
        f.healthOverride={let now=f.clock.sample().uptime;return EgressMonitorTests().report("8.8.8.8",nil,finished:now)}
        c.queue.sync {f.clock.advance(15);c.heartbeat();c.tick()}
        for _ in 0..<200 {if c.queue.sync(execute:{c.status.phase=="off"}) {break};Thread.sleep(forTimeInterval:0.005)}
        #expect(c.queue.sync{c.status.phase=="off" && c.status.lastRisk=="Periodic egress mismatch"})
    }
    @Test func realControllerRejectsMismatchingReportWithoutRetry() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        f.healthOverride={let now=f.clock.sample().uptime;return EgressMonitorTests().report("8.8.8.8","1.1.1.1",finished:now)}
        try c.queue.sync {c.heartbeat();try c.begin(f.settings,launch:false);f.clock.advance(15);c.heartbeat();c.tick()}
        waitForResult(c)
        #expect(c.queue.sync{c.status.phase}=="off")
        #expect(c.queue.sync{c.status.lastRisk}=="Periodic egress mismatch")
        #expect(c.queue.sync{c.status.periodicEgress?.report.samples.first?.ip}=="8.8.8.8")
    }
    @Test func queuedCorrectResultRetainsPFButPFChangeStillStopsWhileRechecking() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        f.healthOverride={let now=f.clock.sample().uptime;return EgressMonitorTests().report("1.1.1.1","1.1.1.1",finished:now-11)}
        try c.queue.sync {c.heartbeat();try c.begin(f.settings,launch:false);f.clock.advance(15);c.heartbeat();c.tick()}
        waitForResult(c)
        #expect(c.queue.sync{c.status.phase}=="armed" && f.reference && !f.rules.isEmpty)
        #expect(c.queue.sync{c.status.periodicEgress?.decision}=="retry: result-stale")
        c.queue.sync {f.rules="tampered";c.heartbeat();c.tick()}
        #expect(c.queue.sync{c.status.phase} != "armed")
        #expect(f.calls.contains("terminate"))
    }
    @Test func missingFreshProofAloneDoesNotRemovePFOrStopClaude() throws {
        let f=try LifecycleFixture(),c=try f.makeController()
        try c.queue.sync {c.heartbeat();try c.begin(f.settings,launch:false);f.clock.advance(45);c.heartbeat();c.tick()}
        #expect(c.queue.sync{c.status.phase}=="armed")
        #expect(c.queue.sync{c.status.lastRisk.isEmpty && f.reference && !f.rules.isEmpty})
    }
}

struct ClaudeRegistrationLifecycleTests {
    @Test func buildMismatchFlagsPromptOnlyAfterNormalCleanup() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();f.claudeBuildChanged=true
        let reply=c.handle(.init(.start,settings:f.settings))
        #expect(!reply.ok && reply.status.claudeRegistrationRequired==true && reply.status.phase=="off")
        #expect(f.launches==0 && !f.reference && f.rules.isEmpty)
    }

    @Test func registrationOnlyChangesClaudeHashAndNextLaunchUsesIt() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        let result=c.handle(.init(.refreshClaudeRegistration))
        #expect(result.ok && result.status.phase=="off")
        var expected=f.installation;expected.claudeHash="updated-claude"
        #expect(f.savedInstallation==expected && c.installation==expected)
        #expect(!f.calls.contains("activate") && !f.calls.contains("launch") && !f.calls.contains("terminate"))
        c.heartbeat();try c.begin(f.settings,launch:true)
        #expect(f.verifiedClaudeHashes==["updated-claude"])
    }
    @Test func activeOrUncertainSessionCannotUpdateRegistration() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat();try c.begin(f.settings,launch:false)
        #expect(!c.handle(.init(.refreshClaudeRegistration)).ok)
        #expect(f.savedInstallation==nil && c.status.phase=="armed" && f.reference)
    }
    @Test func failureOrLateProcessOrCancellationCannotUpdateRegistration() throws {
        for reason in ["official-claude","save-installation","incomplete","late-process","cancel","rules"] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
            if ["official-claude","save-installation"].contains(reason) {f.failure=reason}
            if reason=="incomplete" {f.inventoryIssues=["unreadable"]}
            if reason=="rules" {f.rules="foreign"}
            f.onOfficialCheck={
                if reason=="late-process" {f.claude=[.init(pid:123,ppid:1,uid:501,started:1,path:"/Applications/Claude.app/Contents/MacOS/Claude",name:"Claude")]}
                if reason=="cancel" {c.requestStop()}
            }
            #expect(!c.handle(.init(.refreshClaudeRegistration)).ok)
            #expect(c.installation.claudeHash=="claude" && f.savedInstallation==nil)
        }
    }
}

struct ProxyRegistrationLifecycleTests {
    @Test func postCommitFailureRestoresOldDiskAndMemoryRegistration() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        var writes=0
        f.saveOverride={updated in
            writes+=1;f.savedInstallation=updated
            if writes==1 {throw fail("Injected failure after rename")}
        }
        var request=Request(.registerProxyConfiguration);request.configurationPath="/Users/example/new.yaml"
        let reply=c.handle(request)
        #expect(!reply.ok && writes==2 && f.savedInstallation==f.installation)
        #expect(c.installation==f.installation && f.adoptedPath==nil)
        #expect(c.handle(.init(.inspect)).ok)
    }
    @Test func failedRollbackBlocksFurtherRegistrationAndProtectionWithoutPFChanges() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        var writes=0
        f.saveOverride={updated in
            writes+=1
            if writes==1 {f.savedInstallation=updated}
            throw fail("Injected uncertain persistence")
        }
        var request=Request(.registerProxyConfiguration);request.configurationPath="/Users/example/new.yaml"
        let reply=c.handle(request)
        #expect(!reply.ok && writes==2 && reply.error?.contains("重新运行安装器")==true)
        #expect(!c.handle(.init(.inspect)).ok && !c.handle(request).ok && !c.handle(.init(.refreshClaudeRegistration)).ok)
        #expect(throws:(any Error).self) {try c.begin(f.settings,launch:false)}
        #expect(!f.calls.contains("activate") && !f.calls.contains("launch") && !f.calls.contains("terminate"))
        #expect(c.handle(.init(.status)).ok && c.handle(.init(.export)).ok)
    }
    @Test func onlyConfigPathChangesNoNetworkAndCandidateNotVerified() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        var request=Request(.registerProxyConfiguration);request.configurationPath="/Users/example/current.yaml"
        let reply=c.handle(request)
        var expected=f.installation;expected.proxyConfigPath=request.configurationPath
        #expect(reply.ok && reply.status.phase=="off" && !reply.status.verified)
        #expect(c.installation==expected && f.savedInstallation==expected && f.adoptedPath==request.configurationPath)
        #expect(f.configurationReads==2 && !f.calls.contains("activate") && !f.calls.contains("launch") && !f.calls.contains("terminate"))
    }
    @Test func invalidSaveCancellationAndActiveProtectionPreserveOldRegistration() throws {
        for reason in ["candidate","save-installation","cancel","active","rules","changed"] {
            let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
            if reason=="active" {try c.begin(f.settings,launch:false)}
            if reason=="rules" {f.rules="unknown"}
            if reason=="cancel" {f.onConfigurationCheck={c.requestStop()}}
            f.failure=reason
            var request=Request(.registerProxyConfiguration);request.configurationPath="/Users/example/current.yaml"
            #expect(!c.handle(request).ok)
            #expect(c.installation==f.installation && f.savedInstallation==nil && f.adoptedPath==nil)
            if reason=="active" {#expect(c.status.phase=="armed" && f.reference)}
        }
    }
    @Test func inspectErrorPersistsInExportWithoutClaimingVerified() throws {
        let f=try LifecycleFixture(),c=try f.makeController();c.heartbeat()
        f.failure="candidate"
        var request=Request(.registerProxyConfiguration);request.configurationPath="/Users/example/current.yaml"
        #expect(!c.handle(request).ok)
        let report=c.handle(.init(.export))
        #expect(report.status.configurationError != nil && !report.status.report.isEmpty && !report.status.verified)
    }
}
