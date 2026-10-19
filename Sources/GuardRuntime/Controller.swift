import Foundation
import GuardCore
import Darwin
public final class Controller: @unchecked Sendable {
    public let installation:Installation;public let commands:Commands;public let pf:any PacketFiltering;public let inspector:any RuntimeInspecting
    private let effects:ControllerEffects;private let storage:any ControllerStorage;private let activity:ControllerActivity
    public private(set) var status=Status()
    private var journal:Journal?;private var session:SafetySession?;private var baseline:LocalSnapshot?;private var settings:Settings?
    public let queue=DispatchQueue(label:"guard.transaction")
    private let healthGroup=DispatchGroup();private var healthPending=false
    private var recoveryAttempts=0
    private var recoveryRestoresIPv6=true
    private var ipv6RecoveryAttempt:UInt64?
    private var ipv6RecoveryCount=0
    private var lastRecoveryCheck:UInt64?
    private var lastSocketObservation:UInt64?
    private var blockedStatistics:BlockedPacketStatistics?
    private var latestLabels=""
    private var heartbeatWasDelayed=false
    private var lastMonitorAt:Double?
    private var lastMonitorInterval:Double?
    private var launched=false;private var egressMonitor:EgressMonitor?
    private var logHealthy=true
    private var restartWorkersUnproven=false
    private var baselineRoutes=""
    private var previousHealthy:LocalSnapshot?
    private var previousRoutes:String?
    private var previousHealthyAt:String?
    
    private var eventsLog:[String]=[]
    private let progress=ProgressSnapshot()
    public func progressStatus()->Status {progress.read()}
    
    public convenience init(installation:Installation) throws {try self.init(installation:installation,effects:ControllerEffects.live(installation))}
    init(installation:Installation,effects:ControllerEffects) throws {
        self.installation=installation;self.effects=effects;commands=effects.commands;pf=effects.pf;inspector=effects.inspector;storage=effects.storage;activity=ControllerActivity(clock:effects.clock)
        if storage.exists("session.json") {
            do {journal=try storage.readJournal()}
            catch {try? effects.terminateClaude();throw fail("Private recovery journal unreadable; Claude termination attempted, restrictions not removed")}
            guard journal!.version==1 else{try? effects.terminateClaude();throw fail("Unsupported transaction journal version; Claude termination attempted")}
            session=SafetySession(recovering:journal!.policy);status.phase="stopping";status.lastRisk="守护进程重启，恢复上一事务"
            // The new process has no durable evidence that old independent worker groups exited.
            restartWorkersUnproven = journal!.boot==effects.boot()
            if restartWorkersUnproven {
                try? effects.terminateClaude();status.verified=false;status.phase="recoveryBlocked"
                status.message="助手在同一 boot 重启；旧 worker 生命周期无法证明。保留限制和事务，不自动 OFF；请使用独立恢复，必要时重启 Mac。"
                log("recovery blocked: same-boot daemon restart; prior worker ownership unproven")
            } else {
                do{try stop(reason:status.lastRisk)}catch{status.phase="recoveryBlocked";status.message="恢复受阻；防护状态未确认，请勿启动 Claude"}
            }
        } else {
            let own=try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines)
            let artifact="enable-result.txt"
            if !own.isEmpty {
                try? effects.terminateClaude()
                status.phase="recoveryBlocked";status.message="无 journal 的非空 anchor；归属不明，防护状态未确认"
            } else if storage.exists(artifact) {
                // Journal deletion is the OFF commit; output-file deletion is the final housekeeping step.
                // Never release an orphan token. Only clear its marker after proving absence.
                let token=try pf.recoveredToken()
                if try pf.referencePresent(token) {
                    try? effects.terminateClaude()
                    status.phase="recoveryBlocked";status.message="无 journal 的引用事务；不得释放归属不明的 token"
                } else {try storage.remove(artifact)}
            }
        }
        if journal==nil,status.phase=="off" {
            do {if try effects.ipv6?.hasOverride() == true {try effects.terminateClaude();try restoreIPv6()}}
            catch {status.phase="recoveryBlocked";status.message="IPv6 启动恢复受阻：\(error)"}
        }
    }
    private func restoreIPv6() throws {
        do {try effects.ipv6?.restore();status.ipv6Override=try effects.ipv6?.summary() ?? "未临时修改"}
        catch {status.phase="recoveryBlocked";status.message="IPv6 原设置恢复受阻：\(error)";throw error}
    }
    private func changeIPv6(_ operation:GuardOperation,_ requested:Settings?) throws {
        guard journal==nil,status.phase=="off",try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,!storage.exists("enable-result.txt") else{throw fail("IPv6 只能在 OFF 且无防护事务时调整")}
        guard let manager=effects.ipv6 else{throw fail("IPv6 backend unavailable")}
        // Never enable a physical path while Claude/Code is still present, even outside a PF session.
        guard NativeProcesses.claude(try effects.inventory().requireComplete(),uid:installation.uid).isEmpty else{throw fail("请先退出 Claude/Code，再调整 IPv6")}
        ipv6RecoveryCount=0;ipv6RecoveryAttempt=nil
        try activity.begin();try requireActive()
        if operation == .ipv6Restore {try restoreIPv6()}
        else {guard let requested else{throw fail("Missing interface")};try manager.set(operation == .ipv6Off ? .off:.automatic,interface:requested.physical)}
        status.ipv6Override=try manager.summary();status.message="IPv6 设置已提交；是否有实际 IPv6 路径仍以运行态检测为准"
        log("IPv6 temporary operation=\(operation.rawValue) \(status.ipv6Override)")
    }
    private func seconds()->UInt64 {UInt64(effects.clock.sample().uptime)}
    public func heartbeat(){activity.heartbeat()}
    public func heartbeat(clientPID:Int32) throws {activity.heartbeat(client:try effects.uiIdentity(clientPID))}
    public func requestStop(restoreIPv6:Bool=false){activity.requestUserStop(restoreIPv6:restoreIPv6)}
    private func requireActive() throws {try activity.check();guard try effects.uiAlive(activity.clientIdentity()) else{throw fail("Authenticated UI process exited or changed")};guard logHealthy else{throw fail("Cannot persist security event log")}}
    private func cancelled()->Bool {do{try activity.check();return try !effects.uiAlive(activity.clientIdentity())}catch{return true}}
    private func requireEpoch(_ expected:UInt64) throws {guard try inspector.epoch()==expected else{throw fail("Network changed while collecting PF evidence or before launch")}}
    private func recordProbe(_ text:String) throws {log(text);guard logHealthy else{throw fail("Cannot persist probe security event")}}
    private func log(_ text:String){
        let line="\(ISO8601DateFormatter().string(from:Date())) \(text)"
        eventsLog.append(line)
        func oversized() -> Bool {
            guard let data=try? JSONEncoder().encode(eventsLog.joined(separator:"\n")) else{return true}
            return data.count>32768
        }
        while !eventsLog.isEmpty && (eventsLog.count>120 || oversized()) {eventsLog.removeFirst()}
        status.report=eventsLog.joined(separator:"\n");progress.update(message:text,report:status.report)
        do {try storage.appendEvent(Data((line+"\n").utf8))}
        catch {logHealthy=false;status.lastRisk="事件日志写入失败；诊断记录不完整";status.verified=false}
    }
    private func persist() throws {if let journal{try storage.writeJournal(journal)}}
    public func inspect() throws {
        let n=try inspector.node();status.gateway="\(n.server):\(n.port)";status.fingerprint=n.fingerprint
        let inventory=effects.inventory()
        try status.applyPreview(inventory,uid:installation.uid,allowPartial:journal == nil || status.phase=="recoveryBlocked",known:previousHealthy?.claudeProcesses ?? [],corePath:installation.registeredCorePath)
        status.message="配置候选已读取；运行态和出口仍需验证"
    }
    private func snapshot(_ evidence:RuntimeEvidence,policy:GuardPolicy) throws -> LocalSnapshot {
        let view=try pf.view(policy);latestLabels=view.labels;var s=LocalSnapshot(policy:policy,core:evidence.core,connection:evidence.connection)
        s.epoch=evidence.epoch;s.interfaces=evidence.network.interfaces;s.routeFingerprint=evidence.routeFingerprint
        s.configurationFingerprint=evidence.node.fingerprint;s.nodeName=evidence.node.name;s.gateway=evidence.node.server;s.gatewayPort=evidence.node.port;s.protocolName=evidence.node.type
        s.flclashRunning=true;s.coreIdentityVerified=true;s.verifiedTun=evidence.network.tun;s.tunRuntimeVerified=true
        s.pfEnabled=view.enabled;s.mainRulesFingerprint=hash(Data(view.main.utf8));s.pfEnvironmentCompatible=true
        s.processInventoryComplete=true;s.claudeProcesses=evidence.claude;s.stateInventoryComplete=true;s.states=view.states;s.ipv6Routable=evidence.network.ipv6Routable
        if let journal,let token=journal.token {
            if view.canonical != journal.expectedCanonicalRules {
                self.journal!.cleanRuleHistory=false;try persist()
                throw fail("PF rule history integrity lost")
            }
            guard try pf.referencePresent(token),!journal.expectedCanonicalRules.isEmpty else{throw fail("PF rule/reference integrity changed")}
            guard Set(view.states.map(\.id)).isSubset(of:Set(journal.allowedStates)) else{throw fail("New PF state appeared under no-state session")}
            s.ownReference=token;s.rulesFingerprint=policy.rulesFingerprint;s.rulesAreStateless=true;s.anchorReachable=true
        }
        try requireEpoch(evidence.epoch)
        return s
    }
    public func begin(_ settings:Settings,launch:Bool) throws {
        guard journal==nil,status.phase=="off" else{throw fail("Stop or recover the previous session first")}
        self.settings=settings;egressMonitor=nil;status.periodicEgress=nil;status.egressWarning=nil;status.egressRechecking=false;blockedStatistics=nil;status.blockedPackets=nil;status.blockedPacketsAt=nil;status.blockedPacketsIssue=nil;launched=false;heartbeatWasDelayed=false;lastMonitorAt=nil;lastMonitorInterval=nil;status.heartbeatDiagnostic=nil;logHealthy=true;status.verified=false;status.phase="checking"
        do {
            try effects.ipv6?.verifyStable()
            recoveryAttempts=0;lastRecoveryCheck=nil
            try activity.begin();try requireActive()
            status.workerBuildID=try effects.preflightWorker({[self] in try recordProbe($0)},{[self] in cancelled()});try requireActive()
            let e=try inspector.runtime(settings:settings)
            try requireActive()
            guard e.claude.isEmpty else{throw fail("请先退出 Claude 和 Helpers；预检不会强制关闭未受保护的会话")}
            let endpoint=try Endpoint(gateway:e.node.server,port:e.node.port,expectedEgress:settings.expectedEgress,configurationFingerprint:e.node.fingerprint,providerConfirmed:settings.providerConfirmed,confirmedGateway:settings.gateway,confirmedPort:settings.port,confirmedFingerprint:settings.confirmationFingerprint,protocolName:e.node.type)
            let policy=try GuardPolicy(endpoint:endpoint,physical:e.network.physical,tun:e.network.tun)
            let pre=try snapshot(e,policy:policy)
            guard try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("Own anchor is not empty without journal; ownership uncertain")}
            var engine=SafetySession(policy:policy);_=try engine.begin();_=try engine.preflightAccepted(pre);session=engine
            log("preflight accepted session=\(policy.sessionID) gateway=\(e.node.server):\(e.node.port) core=\(e.core.pid) epoch=\(e.epoch)")
            try requireActive()
            let env=try pf.environment();try requireEpoch(pre.epoch);try requireActive()
            let boot=effects.boot();guard UUID(uuidString:boot) != nil else{throw fail("Kernel boot UUID unavailable")}
            journal=Journal(policy:policy,boot:boot,main:env.0,references:try pf.foreignReferences(nil),enabled:env.2,states:pre.states);try persist();try requireActive()
            journal!.expectedCanonicalRules=try pf.prepareRules(policy);journal!.stage="prepared";try persist();try requireActive()
            journal!.stage="loading-rules";try persist();try requireActive()
            try pf.activateRules(policy,expected:journal!.expectedCanonicalRules);try requireActive()
            journal!.stage="enabling";try persist();try requireActive()
            journal!.token=try pf.enable(cancelled:{[self] in cancelled()});journal!.stage="protected";try persist();try requireActive()
            var protectedEvidence=try inspector.runtime(settings:settings)
            var protected=try snapshot(protectedEvidence,policy:policy);var installedAt=seconds()
            _=try session!.protectionInstalled(protected,now:installedAt);status.phase="validating";status.udp="验证中"
            log("PF installed; starting probes session=\(policy.sessionID) epoch=\(protected.epoch)")
            var bundle:ValidationBundle
            var finalEvidence=protectedEvidence,final=protected
            var attempt=1
            while true {
                bundle=try effects.runProbes(policy,protected,installedAt,{[self] in try recordProbe($0)},{[self] in cancelled()})
                try requireActive()
                for result in bundle.negative{log("probe=\(result.kind.rawValue) label=\(result.dedicatedLabel) counter=\(result.counterBefore)->\(result.counterAfter) blocked=true measuredAt=\(result.measuredAt)")}
                for result in bundle.egress{log("echo=\(result.service.rawValue) ipv4=\(result.ipv4) measuredAt=\(result.measuredAt)")}
                // Include app identity verification in the final-snapshot window.
                if launch {try effects.verifyClaude();try requireActive()}
                finalEvidence=try inspector.runtime(settings:settings)
                final=try snapshot(finalEvidence,policy:policy)
                var diagnostic=ValidationDiagnostics(bundle:bundle,final:final,routesBefore:protectedEvidence.routeDetail,routesAfter:finalEvidence.routeDetail)
                diagnostic.attempt=attempt;diagnostic.networkEvents=inspector.networkEventDiagnostics()
                _=try diagnostic.encoded();try storage.writeDiagnostic(diagnostic)
                log("final snapshot session=\(policy.sessionID) attempt=\(attempt) changed=\(diagnostic.changedFields.joined(separator:",")) epoch=\(protected.epoch)->\(final.epoch) localPort=\(protected.connection.localPort)->\(final.connection.localPort) elapsed=\(seconds()-installedAt)s")
                try requireActive();try requireEpoch(final.epoch)
                if attempt==1,diagnostic.changedFields==["epoch"],final.epoch>protected.epoch {
                    try effects.assertQuiescent()
                    let retryAt=seconds()
                    try session!.retryValidation(bundle,new:final,now:retryAt)
                    attempt=2;protected=final;protectedEvidence=finalEvidence;installedAt=retryAt
                    status.message="路由通知发生变化，防护保持开启；正在重新完整验证（第 2/2 轮）"
                    log("startup validation retry 2/2; PF retained; all probes discarded and rerun epoch=\(final.epoch); 路由通知变化，保持防护并重新完整验证（2/2）")
                    continue
                }
                if attempt==2,diagnostic.changedFields==["epoch"] {throw fail("Startup validation retry exhausted: epoch")}
                _=try session!.arm(bundle,final:final,now:seconds())
                break
            }
            // Neither first nor retry probes count as user blocked traffic.
            blockedStatistics=try? BlockedPacketStatistics(policy:policy,text:latestLabels)
            updateBlockStatistics();baseline=final
            baselineRoutes=finalEvidence.routeDetail;previousHealthy=final;previousRoutes=finalEvidence.routeDetail
            previousHealthyAt=ISO8601DateFormatter().string(from:Date())
            journal!.stage="armed";try persist();status.phase="armed";status.verified=true;status.udp="ON（实包及计数已验证）";status.monitor="PF 防护运行；socket 仅诊断，不凭创建连接判泄漏";lastSocketObservation=nil
            status.gateway="\(policy.endpoint.gateway):\(policy.endpoint.port)";status.egress=policy.endpoint.expectedEgress;status.physical=policy.physical.name;status.tun=policy.tun.name
            status.ipv6="无默认路由；未完成 IPv6 实包验证";status.country="地区未核验；仅验证预期 IPv4";status.flclash=true
            log("ARMED session=\(policy.sessionID) gateway=\(status.gateway) egress=\(status.egress) interfaces=\(status.physical),\(status.tun)")
            try requireActive()
            try SafetyGate.validate(bundle,final:final,policy:policy,now:seconds())
            try verifyArmedEpoch(policy:policy,baseline:final,routes:finalEvidence.routeDetail,claudeMustBeAbsent:true)
            guard status.verified else{throw fail("Cannot persist security event log")}
            if launch {
                try requireActive()
                try effects.launchClaude({[self] in cancelled()})
                launched=true
                try requireActive()
                try verifyArmedEpoch(policy:policy,baseline:final,routes:finalEvidence.routeDetail,claudeMustBeAbsent:false)
            }
            status.message=launch ? "Claude 已安全启动（测试版）" : "防护验收通过；未启动 Claude。请完成 OFF 和恢复测试"
            egressMonitor=EgressMonitor(verifiedAt:effects.clock.sample().uptime);activity.allowProtectedGrace()
        }catch {
            let cause=String(describing:error);status.lastRisk=cause;log("start rejected: \(cause)")
            let startupEvents=inspector.networkEventDiagnostics()
            if journal != nil {do{try stop(reason:cause,restoreIPv6:false)}catch{status.phase="recoveryBlocked";status.verified=false}}
            else {activity.finish();status.phase="off";status.message=cause+"；本次未加载本工具 PF 防护"}
            for event in startupEvents {log("startup network-event \(event)")}
            throw error
        }
    }
    /// A completed ARMED proof is retained, never an incomplete startup proof.
    /// Ordinary notifications at the launch boundary use the same full local
    /// revalidation as running sessions; lifecycle/path/PF changes still fail.
    private func verifyArmedEpoch(policy:GuardPolicy,baseline:LocalSnapshot,routes:String,claudeMustBeAbsent:Bool) throws {
        guard try inspector.epoch() != (previousHealthy?.epoch ?? baseline.epoch) else{return}
        guard let settings else{throw fail("Runtime settings unavailable")}
        let evidence=try inspector.runtime(settings:settings)
        let current=try snapshot(evidence,policy:policy)
        guard !claudeMustBeAbsent || current.claudeProcesses.isEmpty else{throw fail("Claude appeared before protected launch")}
        let compared=MonitoringRouteEvidence.revalidated(current,baseline:baseline,currentRoutes:evidence.routeDetail,baselineRoutes:routes,policy:policy)
        try MonitoringGate.validate(compared,baseline:baseline,policy:policy)
        try requireActive();try requireEpoch(current.epoch)
        log("armed launch-boundary route notification revalidated epoch=\(current.epoch)")
        previousHealthy=current;previousRoutes=evidence.routeDetail
        previousHealthyAt=ISO8601DateFormatter().string(from:Date())
    }
    public func tick() {
        if serviceRequestedStop(){return}
        if journal==nil,(try? effects.ipv6?.hasOverride()) == true {
            // The durable IPv6 lease survives a UI crash. Restore after absence, never during protection.
            do {try activity.check();guard try effects.uiAlive(activity.clientIdentity()) else{throw fail("IPv6 UI lease ended")}}
            catch {guard ipv6RecoveryCount<3,ipv6RecoveryAttempt==nil || seconds()-ipv6RecoveryAttempt!>=5 else{return};ipv6RecoveryAttempt=seconds();ipv6RecoveryCount+=1
                do {try effects.terminateClaude();try restoreIPv6();activity.finish();status.phase="off";log("IPv6 lease ended; original settings restored")}
                   catch {status.phase="recoveryBlocked";status.message="IPv6 自动恢复受阻：\(error)"};return}
        }
        if restartWorkersUnproven {
            // A previously queued LaunchServices request may complete after the old helper died.
            // Keep terminating Claude while preserving restrictions; never report protected/armed.
            do{try effects.terminateClaude();status.claude=false}catch{status.lastRisk="重启恢复受阻且无法确认 Claude 退出：\(error)"}
            return
        }
        if status.phase=="recoveryBlocked",journal != nil {
            retryBlockedRecovery();return
        }
        guard journal != nil,status.phase=="armed",let settings,let baseline else{return}
        let now=effects.clock.sample().uptime
        lastMonitorInterval=lastMonitorAt.map{max(0,now-$0)};lastMonitorAt=now
        let policy=journal!.policy
        var stage="liveness",observed:LocalSnapshot?,observedRoutes:String?,acceptedRouteEquivalence=false
        do {
            try requireActive()
            try requireEgressMonitor()
            stage="runtimeCollection"
            let evidence=try inspector.runtime(settings:settings);observedRoutes=evidence.routeDetail
            if !evidence.processObservation.isEmpty {log("process identity recheck: \(evidence.processObservation)")}
            stage="pfSnapshot"
            let current=try snapshot(evidence,policy:policy);observed=current
            stage="livenessAfterSnapshot";try requireActive()
            stage="premisesComparison"
            let compared=MonitoringRouteEvidence.revalidated(current,baseline:baseline,currentRoutes:evidence.routeDetail,baselineRoutes:baselineRoutes,policy:policy)
            acceptedRouteEquivalence=compared.routeFingerprint != current.routeFingerprint
            try MonitoringGate.validate(compared,baseline:baseline,policy:policy)
            if current.epoch != (previousHealthy?.epoch ?? baseline.epoch) {
                log("route notification revalidated epoch=\(previousHealthy?.epoch ?? baseline.epoch)->\(current.epoch); interface lifetimes, protected paths and PF unchanged")
            }
            if acceptedRouteEquivalence,previousHealthy?.routeFingerprint != current.routeFingerprint {
                log("monitor route equivalent session=\(policy.sessionID) target=1.1.1.1 tun=\(policy.tun.name) gateway=\(policy.tun.ipv4) baseline=\(baseline.routeFingerprint) current=\(current.routeFingerprint)")
            }
            status.claude = !current.claudeProcesses.isEmpty
            if launched && !status.claude {try stop(reason:"Claude 已退出",restoreIPv6:false);return}
            // Passive collection is diagnostic, not a leakage verdict. The PF/runtime gate
            // above remains mandatory even when socket descriptors disappear mid-read.
            if lastSocketObservation==nil || seconds()-lastSocketObservation!>=5 {
                var report:SocketObservationReport
                do {report=try effects.observeSockets(policy,current.claudeProcesses)}
                catch {report = .init(sessionID:policy.sessionID);report.issue(String(describing:error))}
                status.monitor=report.complete ? "PF 防护运行；socket 元数据仅诊断（未证明泄漏）" : "PF 防护运行；socket 观测不完整（不等于泄漏）"
                do {try storage.writeSocketDiagnostic(report)}
                catch {status.monitor="PF 防护运行；socket 诊断保存失败（不等于泄漏）"}
                lastSocketObservation=seconds()
            }
            try requireEgressMonitor()
            if let monitor=egressMonitor,effects.clock.sample().uptime>=monitor.nextCheckAt && !healthPending {
                healthPending=true;let id=policy.sessionID
                let group=healthGroup;group.enter()
                DispatchQueue.global().async {[weak self] in
                    defer{group.leave()}
                    guard let self else{return}
                    let started=self.effects.clock.sample().uptime
                    let report:EgressReport
                    do {report=try self.effects.healthProbe({[self] in cancelled()})}
                    catch {
                        let end=self.effects.clock.sample().uptime
                        report = .init(startedAt:started,finishedAt:end,samples:EgressService.allCases.map{
                            .init(service:$0,ip:nil,error:"Health collector failed: \(String(String(describing:error).prefix(256)))",elapsed:end-started,completedAt:end)
                        })
                    }
                    self.queue.async {[weak self] in
                        guard let self,self.journal?.policy.sessionID==id,self.status.phase=="armed" else{return}
                        self.healthPending=false
                        self.acceptEgress(report,policy:policy,baseline:baseline)
                    }
                }
            }
            stage="finalLivenessAndEpoch";try requireActive();try requireEpoch(current.epoch)
            updateBlockStatistics();updateHeartbeatDiagnostic()
            previousHealthy=current;previousRoutes=evidence.routeDetail
            previousHealthyAt=ISO8601DateFormatter().string(from:Date())
        }catch {
            recordMonitoringFailure(policy:policy,baseline:baseline,stage:stage,reason:String(describing:error),current:observed,routes:observedRoutes,acceptedRouteEquivalence:acceptedRouteEquivalence)
        }
    }
    private func requireEgressMonitor() throws {
        let now=effects.clock.sample().uptime
        guard let monitor=egressMonitor,now.isFinite,now>=monitor.lastVerifiedAt else {
            throw fail("Periodic egress monitor or clock unavailable")
        }
    }
    private func acceptEgress(_ report:EgressReport,policy:GuardPolicy,baseline:LocalSnapshot) {
        var observed:LocalSnapshot?,routes:String?
        do {
            try requireActive()
            // An asynchronous echo may finish after a harmless routing notification.
            // Recollect local evidence instead of trusting the old epoch or the echo alone.
            if try inspector.epoch() != (previousHealthy?.epoch ?? baseline.epoch) {
                guard let settings else{throw fail("Runtime settings unavailable")}
                let evidence=try inspector.runtime(settings:settings);routes=evidence.routeDetail
                let current=try snapshot(evidence,policy:policy);observed=current
                let compared=MonitoringRouteEvidence.revalidated(current,baseline:baseline,currentRoutes:evidence.routeDetail,baselineRoutes:baselineRoutes,policy:policy)
                try MonitoringGate.validate(compared,baseline:baseline,policy:policy)
                try requireActive();try requireEpoch(current.epoch)
                log("route notification revalidated before egress result epoch=\(current.epoch); local protection verified")
                previousHealthy=current;previousRoutes=evidence.routeDetail
                previousHealthyAt=ISO8601DateFormatter().string(from:Date())
            }
            guard var monitor=egressMonitor else{throw fail("Periodic egress monitor unavailable")}
            let now=effects.clock.sample().uptime,age=now-monitor.lastVerifiedAt
            let decision=monitor.consume(report,expected:policy.endpoint.expectedEgress,now:now)
            egressMonitor=monitor
            let reason:String
            switch decision {case .verified:reason="verified";case .retry(let value):reason="retry: "+value;case .stop(let value):reason=value}
            var diagnostic=EgressDiagnostic(report:report,queueDelay:max(0,now-report.finishedAt),proofAge:age,failures:monitor.failures,decision:reason)
            // No absolute stop deadline for unavailable echo services in 0.5.15.
            if case .retry=decision {diagnostic.retryAfterSeconds=max(0,monitor.nextCheckAt-now)}
            status.periodicEgress=diagnostic
            let encoded=try JSONEncoder().encode(diagnostic)
            log("periodic-egress "+String(decoding:encoded,as:UTF8.self))
            try requireActive()
            switch decision {
            case .verified:status.egressRechecking=false;status.egressWarning=nil
            case .retry(let reason):
                status.egressRechecking=true
                if monitor.failures>=2,status.egressWarning==nil {
                    status.egressWarning=EgressWarning(reason:reason)
                    log("egress-warning: repeated unavailable/stale samples; Claude retained; PF unchanged; retry in 300s")
                }
            case .stop(let reason):recordMonitoringFailure(policy:policy,baseline:baseline,stage:"periodicEgress",reason:reason,current:nil,routes:nil)
            }
        }catch {recordMonitoringFailure(policy:policy,baseline:baseline,stage:"periodicEgress",reason:String(describing:error),current:observed,routes:routes)}
    }
    private func updateBlockStatistics() {
        do {
            guard blockedStatistics != nil else{throw fail("Block statistics baseline unavailable")}
            status.blockedPackets=try blockedStatistics!.read(latestLabels)
            status.blockedPacketsAt=ISO8601DateFormatter().string(from:Date());status.blockedPacketsIssue=nil
        }catch {status.blockedPackets=nil;status.blockedPacketsIssue=String(describing:error)}
    }
    private func updateHeartbeatDiagnostic() {
        var diagnostic=activity.diagnostic();diagnostic.monitorIntervalSeconds=lastMonitorInterval
        status.heartbeatDiagnostic=diagnostic
        if diagnostic.delayed != heartbeatWasDelayed {
            heartbeatWasDelayed=diagnostic.delayed
            log("heartbeat \(diagnostic.delayed ? "delayed; PF and runtime checks continue":"resumed") age=\(String(format:"%.3f",diagnostic.ageSeconds ?? 0))s maxGap=\(String(format:"%.3f",diagnostic.maxGapSeconds))s monitorInterval=\(String(format:"%.3f",lastMonitorInterval ?? 0))s")
        }
    }
    private func retryBlockedRecovery() {
        guard let j=journal else{return}
        let now=seconds()
        guard lastRecoveryCheck==nil || now-lastRecoveryCheck!>=5 else{return}
        lastRecoveryCheck=now
        // This is an asset check, not a fresh TUN/egress verification or permission to arm.
        status.verified=false
        do {
            let view=try pf.view(j.policy)
            guard j.cleanRuleHistory,view.enabled,!j.expectedCanonicalRules.isEmpty,
                  view.canonical==j.expectedCanonicalRules,view.main==j.initialMain,
                  let token=j.token,try pf.referencePresent(token),
                  try pf.foreignReferences(token)==j.initialReferences,
                  Set(view.states.map(\.id)).isSubset(of:Set(j.allowedStates)) else{throw fail("Recovery PF assets cannot be verified")}
            status.udp="PF 限制规则仍在（恢复复核；非新的实包验证）"
        }catch {status.udp="防护未确认（恢复复核失败）"}
        status.monitor="恢复受阻：仅复核 PF 资产；常规出口监控已停止"
        guard recoveryAttempts<3 else{
            status.message="恢复受阻；3 次自动恢复尝试已用完，请关闭 Claude 后手动关闭安全模式或使用兜底";return
        }
        recoveryAttempts += 1
        do {try stop(reason:"自动恢复重试 \(recoveryAttempts)/3："+status.lastRisk,restoreIPv6:recoveryRestoresIPv6)}
        catch { /* stop preserves assets and reports the precise failing stage. */ }
    }
    private func recordMonitoringFailure(policy:GuardPolicy,baseline:LocalSnapshot,stage:String,reason:String,current:LocalSnapshot?,routes:String?,acceptedRouteEquivalence:Bool=false) {
        if serviceRequestedStop(){return}
        updateHeartbeatDiagnostic()
        // Copy the observation before OFF drops the session; diagnostic-file I/O starts only after the stop/termination attempt.
        var diagnostic=MonitoringDiagnostics(sessionID:policy.sessionID,buildID:BuildIdentity.buildID,stage:stage,reason:reason,
            baseline:baseline,previousHealthy:previousHealthy,current:current,baselineRoutes:baselineRoutes,
            previousRoutes:previousRoutes,currentRoutes:routes,previousHealthyAt:previousHealthyAt,acceptedRouteEquivalence:acceptedRouteEquivalence)
        diagnostic.networkEvents=inspector.networkEventDiagnostics()
        stopForIncident(reason:reason,hadClaude:launched || !(current?.claudeProcesses.isEmpty ?? true))
        diagnostic.recoveryPhase=status.phase
        for event in diagnostic.networkEvents ?? [] {log("network-event "+event)}
        do {
            try storage.writeMonitoringDiagnostic(diagnostic)
            log("monitor diagnostic saved session=\(policy.sessionID) stage=\(stage) currentComplete=\(diagnostic.currentComplete) changed=\(diagnostic.changedFields.joined(separator:",")) recovery=\(status.phase) file=last-monitoring-failure.json")
        }catch {
            log("monitor diagnostic persistence failed session=\(policy.sessionID) stage=\(stage): \(error)")
            status.message+="；监控诊断保存失败，请采集事件日志"
        }
    }
    private func normalStop(restoreIPv6:Bool) throws {
        activity.clearUserStopIntent()
        try stop(reason:restoreIPv6 ? "用户退出并恢复原设置":"用户关闭防护",restoreIPv6:restoreIPv6)
        status.interruption=nil;status.lastRisk=""
    }
    @discardableResult private func serviceRequestedStop()->Bool {
        guard let restore=activity.requestedUserStop() else{return false}
        do{try normalStop(restoreIPv6:restore)}catch{log("用户关闭未完成：\(error)")}
        return true
    }
    private func stopForIncident(reason:String,hadClaude:Bool) {
        if serviceRequestedStop(){return}
        var restoreLease=true
        if (try? requireActive()) != nil {restoreLease=false}
        var event=ProtectionInterruption(reason:reason,requestedClaudeStop:hadClaude)
        do{try stop(reason:reason,restoreIPv6:restoreLease)}catch{status.phase="recoveryBlocked";status.lastRisk=reason;status.verified=false}
        event.exitConfirmed=hadClaude && status.phase=="off"
        status.interruption=event
    }
    public func stop(reason:String,restoreIPv6 restoreLease:Bool=true) throws {
        recoveryRestoresIPv6=restoreLease
        activity.requestStop()
        if restartWorkersUnproven {
            try? effects.terminateClaude();status.verified=false;status.phase="recoveryBlocked"
            throw fail("Same-boot daemon restart: prior worker ownership unproven; keep restrictions and recovery assets")
        }
        guard var j=journal else{
            status.phase="stopping";status.verified=false
            do {
                try effects.assertQuiescent()
                guard try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,
                      !storage.exists("enable-result.txt") else{throw fail("Unowned anchor/reference marker: cannot assert OFF")}
                if restoreLease,(try effects.ipv6?.hasOverride()) == true {try effects.terminateClaude();try restoreIPv6()}
                activity.finish();status.phase="off";status.message=restoreLease ? "OFF；本工具临时设置已核验恢复":"防护已关闭；临时 IPv6 保持当前设置";return
            }catch {
                status.phase="recoveryBlocked";status.verified=false
                status.message="恢复受阻（无 PF 会话）：\(error)；临时设置恢复尚未确认"
                log(status.message);throw error
            }
        }
        status.monitor="停止中：常规出口监控已停止；正在终止 Claude/Code 并核验恢复"
        status.udp="恢复处理中；防护以恢复核验为准"
        var recoveryStage="terminateClaude"
        status.egressWarning=nil;status.egressRechecking=false
        status.phase="stopping";status.lastRisk=reason;status.verified=false;session=SafetySession(recovering:j.policy);log("stop: \(reason)")
        do {
            try effects.terminateClaude()
            recoveryStage="workerQuiescence"
            guard healthGroup.wait(timeout:.now()+12) == .success else{throw fail("Pending health probe did not stop; keep PF active")}
            try effects.assertQuiescent();healthPending=false
            recoveryStage="confirmProcessAbsence"
            let absent=NativeProcesses.claude(try effects.inventory().requireComplete(),uid:installation.uid,known:previousHealthy?.claudeProcesses ?? []).isEmpty
            guard absent else{throw fail("Claude still present")}
            if status.interruption?.requestedClaudeStop==true {status.interruption?.exitConfirmed=true}
            _=try session?.claudeExited(inventoryComplete:true,processes:[])
            recoveryStage="verifyRecoveryAssets"
            let currentBoot=effects.boot()
            if j.boot==currentBoot,j.token==nil,storage.exists("enable-result.txt") {
                do {j.token=try pf.recoveredToken();journal=j;try persist()}
                catch {guard try pf.foreignReferences(nil)==j.initialReferences else{throw fail("PF enable outcome uncertain; token output incomplete")}}
            }
            let ownRules=try pf.canonical()
            let tokenPresent=try j.token.map{try pf.referencePresent($0)} ?? false
            let boot=try RecoverySafety.bootDecision(recorded:j.boot,current:currentBoot,anchorEmpty:ownRules.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,oldTokenPresent:tokenPresent)
            if boot == .clearRebootedSession {
                // Kernel PF state and references cannot survive a kernel reboot. Do not touch current foreign PF.
                try storage.remove("session.json");try storage.remove("enable-result.txt")
                journal=nil;session=nil;baseline=nil;self.settings=nil;launched=false;activity.finish()
                try restoreIPv6();status.phase="off";status.udp="OFF（旧 boot 事务已结束，未释放任何当前 token）";status.claude=false;status.monitor="已停止";status.message="旧事务确认已随内核重启失效";return
            }
            if j.token==nil,j.stage=="enabling",try pf.foreignReferences(nil) != j.initialReferences {throw fail("Enable token uncertain; keep transaction and rules")}
            guard j.cleanRuleHistory else{throw fail("Cannot prove stateless rule history")}
            let view=try pf.view(j.policy)
            guard view.main==j.initialMain,try pf.foreignReferences(j.token)==j.initialReferences,
                  Set(view.states.map(\.id)).isSubset(of:Set(j.allowedStates)) else{throw fail("PF environment/state ownership changed; leave restrictions intact")}
            // If rules differ from owned expected rules (e.g. external tampering), do not erase them blindly.
            guard view.canonical.isEmpty || view.canonical==j.expectedCanonicalRules else{throw fail("Own anchor changed; rule ownership uncertain")}
            recoveryStage="removeOwnRules"
            j.stage="removing-rules";journal=j;try persist();try pf.removeOwnRules()
            let states=try pf.states(j.policy);guard Set(states.map(\.id)).isSubset(of:Set(j.allowedStates)) else{throw fail("Residual no-state session states cannot be excluded")}
            _=try session?.rulesRemoved(rulesAbsent:true,stateInventoryComplete:true,states:states)
            recoveryStage="releaseOwnReference"
            j.stage="releasing-token";journal=j;try persist()
            if let token=j.token,try pf.referencePresent(token){try pf.release(token)}
            let env=try pf.environment();guard env.0==j.initialMain,try pf.foreignReferences(nil)==j.initialReferences,env.2==j.initialEnabled,
                  try pf.canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("OFF restoration evidence incomplete")}
            _=try session?.referenceReleased(ownReferenceAbsent:true,foreignEnvironmentUnchanged:true)
            try storage.remove("session.json");try storage.remove("enable-result.txt")
            journal=nil;session=nil;baseline=nil;settings=nil;launched=false;recoveryStage="restoreIPv6";if restoreLease{try restoreIPv6()};activity.finish();status.phase="off";status.egress="";status.country="未核验";status.physical="";status.tun="";status.udp="OFF（规则、引用和 state 核验通过）";status.monitor="已停止";status.claude=false;status.message=restoreLease ? "防护已关闭，原网络设置已核验恢复":"Claude 已退出，防护已关闭；临时 IPv6 保持当前设置";log("OFF verified")
        }catch{
            status.phase="recoveryBlocked";status.verified=false;lastRecoveryCheck=seconds()
            status.monitor="恢复受阻：常规出口监控已停止；等待有限恢复重试"
            status.udp="防护未确认；等待 PF 资产复核"
            status.message="恢复受阻 [\(recoveryStage)]：\(error)；防护状态未确认"
            log(status.message);throw error
        }
    }
    public func handle(_ request:Request) -> Reply {
        do {
            switch request.operation {
            case .status:
                let inventory=effects.inventory()
                try status.applyPreview(inventory,uid:installation.uid,allowPartial:journal == nil || status.phase=="recoveryBlocked",known:previousHealthy?.claudeProcesses ?? [],corePath:installation.registeredCorePath)
            case .heartbeat:heartbeat()
            case .progress:return .init(ok:true,status:progressStatus())
            case .inspect:try inspect()
            case .selfTest:
                guard journal==nil,status.phase=="off" else{throw fail("Offline self-test requires OFF")}
                try activity.begin();defer{activity.finish()}
                try requireActive()
                status.workerBuildID=try effects.preflightWorker({[self] in try recordProbe($0)},{[self] in cancelled()})
                try requireActive();status.message="离线自检通过；未安装 PF、未测试公网、未启动 Claude"
                log(status.message)
            case .verify,.start:guard let settings=request.settings else{throw fail("Missing settings")};try begin(settings,launch:request.operation == .start)
            case .stop,.shutdown:recoveryAttempts=0;ipv6RecoveryCount=0;try normalStop(restoreIPv6:request.operation == .shutdown)
            case .ipv6Off,.ipv6Automatic,.ipv6Restore:try changeIPv6(request.operation,request.settings)
            case .export:status.report=eventsLog.joined(separator:"\n")
            }
            status.ipv6Override=try effects.ipv6?.summary() ?? "未临时修改"
            status.refreshedAt=ISO8601DateFormatter().string(from:Date())
            return .init(ok:true,status:status)
        }catch{
            let original=String(describing:error)
            if journal != nil,[GuardOperation.status,.inspect].contains(request.operation) {
                // A failed live observation is a safety failure, not a partial idle preview.
                status.verified=false
                stopForIncident(reason:"Active observation failed: \(original)",hadClaude:launched || status.claude)
            }
            return .init(ok:false,status:status,error:original)
        }
    }
}
public func bootID() -> String {
    var buffer=[CChar](repeating:0,count:128);var size=buffer.count
    guard sysctlbyname("kern.bootsessionuuid",&buffer,&size,nil,0)==0 else{return "unknown-boot"}
    let value=String(cString:buffer)
    return UUID(uuidString:value)?.uuidString.lowercased() ?? "unknown-boot"
}
