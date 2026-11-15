import Foundation
import Combine
import AppKit
import GuardRuntime
import GuardCore

@MainActor public final class AppModel:ObservableObject {
    @Published public var entryProbeMessage=""
    @Published public var entryProbeDiagnostics:[EntryProbeDiagnostic]=[]
    @Published public var entryProbeStale=false
    public private(set) var entryProbeContext:Settings?
    @Published public var testingEntry=false
    private var entryCancellation:EntryProbeCancellation?
    @Published public var ipCheck:IPCheck?
    @Published public var testingIP=false
    @Published public var ipStale=false
    @Published public var state=Status() {didSet{
        if !entryProbeMessage.isEmpty && (state.fingerprint != oldValue.fingerprint || state.configurationPath != oldValue.configurationPath || state.entryProbeCoreHash != oldValue.entryProbeCoreHash) {entryProbeStale=true}
        observeInterruption();observeEgressWarning();updateActivityLease()
    }}
    @Published public var registrationAlert=false
    @Published public var pfIssueAlert:String?
    @Published public var interruptionAlert:ProtectionInterruption?
    private var lastPresentedInterruption:String?
    private func observeInterruption() {
        guard let event=state.interruption,event.id != lastPresentedInterruption,
              event.id != preferences?.string(forKey:"acknowledgedInterruption") else{return}
        lastPresentedInterruption=event.id;interruptionAlert=event
    }
    public func acknowledgeInterruption() {
        if let event=interruptionAlert {preferences?.set(event.id,forKey:"acknowledgedInterruption")}
        interruptionAlert=nil
    }
    @Published public var egressWarningAlert:EgressWarning?
    private var lastPresentedEgressWarning:String?
    private func observeEgressWarning() {
        guard state.phase=="armed",let event=state.egressWarning,interruptionAlert==nil else{egressWarningAlert=nil;return}
        guard event.id != lastPresentedEgressWarning,event.id != preferences?.string(forKey:"acknowledgedEgressWarning") else{return}
        lastPresentedEgressWarning=event.id;egressWarningAlert=event
    }
    public func acknowledgeVisibleAlert() {
        if registrationAlert {registrationAlert=false;return}
        if interruptionAlert != nil {acknowledgeInterruption();return}
        if pfIssueAlert != nil {pfIssueAlert=nil;return}
        if let event=egressWarningAlert {preferences?.set(event.id,forKey:"acknowledgedEgressWarning")}
        egressWarningAlert=nil
    }
    public var guidance:Guidance {
        if state.protectionMode == .udpOnly,state.phase=="armed",state.verified,failure.isEmpty {
            return .init("仅 UDP 防护","全机 UDP 限制已开启","不管理 Claude；不限制 TCP，不保证公网出口。关闭后恢复原 UDP 行为。")
        }
        if state.phase=="off",!busy,failure.isEmpty,needsIPv6Off {return Guidance.reason("IPv6 default route detected")}
        if state.phase=="armed",state.egressRechecking==true,failure.isEmpty {
            return .init("网络复核","出口待核验，PF 防护继续运行","未关闭 Claude；每 5 分钟重测。当前出口尚未确认；检测到不同公网 IP 会立即停止。")
        }
        return Guidance.current(state,failure:failure,busy:busy,confirmation:confirmation,ip:ipCheck,stale:ipStale || ipCheck?.expected != settings.expectedEgress)
    }
    @Published public var settings=Settings() {didSet {
        if settings != oldValue {
            confirmation=false;ipStale=true;settingsRevision += 1
            let entryChanged=settings.entryName != oldValue.entryName || settings.entryIPv4 != oldValue.entryIPv4 || settings.physical != oldValue.physical || settings.effectivePathMode != oldValue.effectivePathMode
            entryCancellation?.cancel();if entryChanged && !entryProbeMessage.isEmpty {entryProbeStale=true}
            saveSettings()
        }
    }}
    @Published public var onboardingComplete=false
    @Published public var ipv6Preview:IPv6Preview?
    private var readingIPv6=false
    private var lastIPv6Read=Date.distantPast
    private let enableIPv6Polling:Bool
    private let ipv6Reader:@Sendable ()->IPv6Preview
    public var needsIPv6Off:Bool {ipv6Preview?.isFresh==true && ipv6Preview?.hasDefaultRoute==true}
    public var ipv6ReadinessText:String {
        guard let value=ipv6Preview,value.isFresh else{return "IPv6 待检查"}
        guard let present=value.hasDefaultRoute else{return "IPv6 状态读取失败，请刷新"}
        return present ? "检测到 IPv6 默认路由，请先临时关闭":"无 IPv6 默认路由（非全局禁用）"
    }
    public func saveSettings() {
        var stored=settings;stored.providerConfirmed=false;stored.confirmationFingerprint=""
        if let data=try? JSONEncoder().encode(stored){preferences?.set(data,forKey:"publicSettingsV1")}
    }
    public func completeOnboarding(){saveSettings();onboardingComplete=true;preferences?.set(true,forKey:"publicOnboardingV1")}
    public func refreshIPv6() {
        guard !readingIPv6 else{return};readingIPv6=true;lastIPv6Read=Date()
        let read=ipv6Reader
        Task.detached{[weak self] in
            let result=read()
            await MainActor.run{self?.ipv6Preview=result;self?.readingIPv6=false}
        }
    }
    public var readyToQuit:Bool {state.phase=="off" && state.ipv6Override=="未临时修改" && !busy}
    public var networkPathSummary:String {
        let landing=state.gateway.isEmpty ? "待核对":state.gateway
        if settings.effectivePathMode == .chain {
            let physical=state.phase=="armed" ? (state.physicalGateway ?? "待核验") : (settings.entryIPv4 ?? "待确认")
            return "前置：\(physical) → ISP：\(landing)"
        }
        return "ISP 网关：\(landing)"
    }
    public var menuStatus:String {
        if busy{return "处理中"}
        if state.phase=="armed",state.egressRechecking==true {return "出口待核验"}
        if state.verified && state.phase=="armed" {return state.protectionMode == .udpOnly ? "仅 UDP":"完整防护"}
        switch state.phase {case "off":return "OFF";case "recoveryBlocked":return "恢复受阻";default:return "待核验"}
    }
    @Published public var busy=false
    @Published public var failure=""
    @Published public var confirmation=false
    @Published public var flclashCatalog:FlClashCatalog?
    @Published public var readingFlClash=false
    @Published public var flclashCatalogError=""
    @Published public var currentChainMessage=""
    private let transport:@Sendable (Request)throws->Reply
    private let preferences:UserDefaults?
    private var timer:Timer?
    private var pollingStatus=false
    private var pollingProgress=false
    private let heartbeat:HeartbeatPump
    private var activityToken:ProcessActivityLease?
    @Published public var communicationWarning=""
    private func updateActivityLease() {
        let active=["checking","validating","armed","stopping","recoveryBlocked"].contains(state.phase) || state.ipv6Override != "未临时修改"
        if active && activityToken==nil {
            activityToken=ProcessActivityLease()
        } else if !active {activityToken=nil}
    }
    private var settingsRevision:UInt64=0
    private var revision:UInt64=0
    private var stopping=false
    public init(autoPoll:Bool=true,preferences:UserDefaults? = .standard,ipv6Reader:@escaping @Sendable ()->IPv6Preview = {IPv6Preview.read()},transport:@escaping @Sendable (Request)throws->Reply = {try Wire.client($0)}) {
        self.transport=transport;self.heartbeat=HeartbeatPump(transport:transport);self.preferences=preferences;self.ipv6Reader=ipv6Reader;self.enableIPv6Polling=autoPoll;state.daemonBuildID=""
        if let data=preferences?.data(forKey:"publicSettingsV1"),let saved=try? JSONDecoder().decode(Settings.self,from:data){settings=saved}
        onboardingComplete=preferences?.bool(forKey:"publicOnboardingV1") ?? false
        if autoPoll {
            heartbeat.start()
            let tick=Timer(timeInterval:1,repeats:true){[weak self] _ in Task{@MainActor in self?.poll()}}
            timer=tick;RunLoop.main.add(tick,forMode:.common)
        }
    }
    private func communicationFailed(_ version:UInt64) {
        guard version==revision else{return}
        if stopping {
            // Do not orphan the in-flight OFF completion or leave the stop latch permanently set.
            state.ipcUnavailable();failure="助手通信失败；正在等待关闭结果，必要时使用独立恢复";return
        }
        let active=busy || state.verified
        revision+=1;state.ipcUnavailable();failure="助手通信失败；结果未知，请勿启动 Claude";busy=false
        if active && !stopping{request(.stop)}
    }
    public func poll() {
        if enableIPv6Polling && Date().timeIntervalSince(lastIPv6Read)>=5 {refreshIPv6()}
        let version=revision,call=transport
        // A pulse supports manual refresh/tests; the independent timer is authoritative.
        heartbeat.pulse()
        if busy && !pollingProgress {
            pollingProgress=true
            Task.detached{[weak self] in
                let reply=try? call(.init(.progress))
                await MainActor.run {
                    guard let self else{return};self.pollingProgress=false
                    guard version==self.revision,self.busy,let reply,reply.ok,reply.status.phase=="progressOnly" else{return}
                    self.state.message=reply.status.message;self.state.report=reply.status.report
                }
            }
        }
        if !busy && !pollingStatus {
            pollingStatus=true
            Task.detached{[weak self] in
                do {
                    let reply=try call(.init(.status))
                    await MainActor.run {
                        guard let self else{return};self.pollingStatus=false
                        guard version==self.revision,!self.busy else{return}
                        self.communicationWarning="";self.state=reply.status
                        if !reply.ok{self.state.verified=false;self.failure=reply.error ?? "运行态读取失败"}
                    }
                }catch {
                    await MainActor.run{
                        guard let self else{return};self.pollingStatus=false
                        guard version==self.revision else{return}
                        self.communicationWarning="助手状态暂未返回；当前防护状态未确认，正在重试"
                        // No speculative OFF: an IPC timeout is not proof that PF failed.
                        self.state.verified=false
                    }
                }
            }
        }
    }
    @discardableResult public func request(_ operation:GuardOperation,configurationPath:String?=nil,currentChain:FlClashCurrentChain?=nil)->Task<Void,Never>? {
        if [.stop,.shutdown].contains(operation) {guard !stopping else{return nil};entryCancellation?.cancel();stopping=true}
        else {guard !busy else{return nil}}
        if [.refreshClaudeRegistration,.registerProxyConfiguration].contains(operation) {guard state.phase=="off" else{return nil}}
        // Clear before transport: commit may succeed even if its reply is lost or superseded by OFF.
        if operation == .registerProxyConfiguration {confirmation=false}
        if operation == .udpStart,state.phase != "off" {return nil}
        if [.start,.verify].contains(operation) {
            guard state.phase=="off" else{return nil}
            if needsIPv6Off {failure="IPv6 default route detected";return nil}
        }
        revision+=1;let version=revision,configVersion=settingsRevision
        busy=true;failure="";pfIssueAlert=nil;state.verified=false;ipStale=true
        if [.stop,.shutdown].contains(operation){state.phase="stopping"}
        else if [.udpStart,.start,.verify].contains(operation){state.phase="checking"}
        var saved=settings;saved.providerConfirmed=confirmation;saved.confirmationFingerprint=state.fingerprint
        saveSettings()
        var request=Request(operation,settings:saved);request.configurationPath=configurationPath
        let call=transport
        return Task.detached{[weak self] in
            do {
                let reply=try call(request)
                await MainActor.run {
                    guard let self,version==self.revision else{return}
                    if [.stop,.shutdown].contains(operation),reply.ok {self.acknowledgeInterruption()}
                    self.state=reply.status;self.failure=reply.error ?? "";self.busy=false;self.stopping=false
                    if !reply.ok,[.start,.verify,.inspect].contains(operation),PFDiagnosticHelp(reason:self.failure) != nil,self.interruptionAlert==nil {
                        self.pfIssueAlert=self.failure
                    }
                    if operation == .registerProxyConfiguration {
                        self.confirmation=false
                        if reply.ok {
                            let endpoint=reply.status.gateway.split(separator:":")
                            let unchanged=self.settingsRevision==configVersion
                            if endpoint.count==2,let port=UInt16(endpoint[1]) {self.settings.gateway=String(endpoint[0]);self.settings.port=port}
                            if let hint=currentChain {
                                guard unchanged,reply.status.phase=="off",reply.status.configurationPath==hint.configurationPath,
                                      reply.status.fingerprint==hint.node.fingerprint,
                                      reply.status.chainCandidate?.entries.contains(hint.entry)==true else {
                                    self.failure="FLClash 配置或设置在登记期间改变，未应用前置选择；请重新读取。";return
                                }
                                self.settings.pathMode = .chain;self.settings.entryName=hint.entry.name
                                // Domain entries require an observed physical connection, never DNS substitution.
                                self.settings.entryIPv4=IPv4.isPublic(hint.entry.server) ? hint.entry.server:nil
                                self.currentChainMessage="已读取：\(hint.profileLabel) → \(hint.entry.name)。这是保存的选择；请核对前置连接和端点，再启动验证。"
                            }
                        }
                    }
                    if operation == .start,reply.status.claudeRegistrationRequired==true {self.registrationAlert=true}
                    if operation == .refreshClaudeRegistration {
                        self.registrationAlert = !reply.ok
                        if reply.ok {self.acknowledgeInterruption()}
                    }
                    if operation == .inspect,reply.ok,self.settings.gateway.isEmpty {
                        let endpoint=reply.status.gateway.split(separator:":")
                        if endpoint.count==2,let port=UInt16(endpoint[1]) {self.settings.gateway=String(endpoint[0]);self.settings.port=port}
                    }
                    if self.enableIPv6Polling {self.refreshIPv6()}
                }
            }catch {
                await MainActor.run {
                    guard let self,version==self.revision else{return}
                    self.state.ipcUnavailable();self.failure=String(describing:error);self.busy=false;self.stopping=false
                    if operation == .refreshClaudeRegistration {self.registrationAlert=true}
                    // A lost reply does not prove the daemon stopped. Request cancellation independently.
                    if [.udpStart,.start,.verify].contains(operation){self.request(.stop)}
                }
            }
        }
    }
    public func entryCandidateLabel(_ ip:String)->String {
        let passed=entryProbeDiagnostics.last(where:{$0.candidate==ip})?.outcome=="通过"
        return (!entryProbeStale && settings.entryIPv4==ip && passed ? "已核验入口：":"候选连接：")+ip
    }
    public func cancelEntryProbe(){entryCancellation?.cancel()}
    public func verifyEntryConnection() {
        guard !busy,!testingIP,state.phase=="off",settings.effectivePathMode == .chain,
              let resources=Bundle.main.resourcePath else{return}
        busy=true;testingEntry=true;confirmation=false;failure=""
        entryProbeDiagnostics=[];entryProbeStale=false;entryProbeContext=settings
        entryProbeMessage="正在验证所选节点的协议、物理源地址和活动连接；不会切换代理。"
        let cancellation=EntryProbeCancellation();entryCancellation=cancellation
        revision+=1;let probeRevision=revision
        let saved=settings,configVersion=settingsRevision,call=transport
        Task.detached { [weak self] in
            let receiver=self
            do {
                let before=try call(Request(.inspect,settings:saved))
                guard before.ok,before.status.phase=="off" else{throw fail("请先关闭防护并重新检测配置")}
                let results=try EntryProbe.run(status:before.status,settings:saved,resources:resources,cancellation:cancellation,diagnostic:{ event in
                    Task { @MainActor [weak receiver] in
                        guard let self=receiver,self.revision==probeRevision else{return}
                        self.entryProbeDiagnostics.append(event)
                    }
                })
                let after=try call(Request(.inspect,settings:saved))
                guard !cancellation.cancelled,after.ok,after.status.phase=="off",
                      after.status.fingerprint==before.status.fingerprint,
                      after.status.entryProbeCoreHash==before.status.entryProbeCoreHash,
                      after.status.entryProbeCorePath==before.status.entryProbeCorePath,
                      after.status.configurationPath==before.status.configurationPath,
                      after.status.chainCandidate==before.status.chainCandidate,
                      results.allSatisfy({after.status.entryCandidates?.contains($0.entry)==true}) else{throw fail("前置验证结果已失效，请确认当前连接后重试")}
                await MainActor.run {
                    guard let self else{return}
                    self.testingEntry=false;self.entryCancellation=nil
                    guard self.revision==probeRevision else{return}
                    self.busy=false
                    guard self.settingsRevision==configVersion,self.state.phase=="off" else{self.entryProbeMessage="设置或防护状态改变，结果已丢弃";return}
                    self.state=after.status
                    if results.count==1,let result=results.first {
                        self.settings.entryIPv4=result.entry
                        self.entryProbeStale=false
                        self.entryProbeContext=self.settings
                        self.entryProbeMessage="已匹配连接入口：\(result.entry)；本次前置回显出口：\(result.exit)。入口已填入，仍需确认端点并启动完整防护验证。"
                    } else if results.isEmpty {
                        self.entryProbeMessage="没有候选通过独立协议与连接核验。可能是节点不支持独立连接、证书校验失败或网络超时；不会猜选入口。"
                    } else {
                        self.entryProbeMessage="多个入口通过测试，未自动填写："+results.map{"\($0.entry)（出口 \($0.exit)）"}.joined(separator:"；")
                    }
                }
            } catch {
                await MainActor.run {
                    guard let self else{return}
                    self.testingEntry=false;self.entryCancellation=nil
                    guard self.revision==probeRevision else{return}
                    self.busy=false
                    self.entryProbeMessage=String(describing:error)
                }
            }
        }
    }
    @discardableResult public func testIP(fillEgress:Bool=false,fetch:@escaping @Sendable (EgressService)throws->String = {try ProbeExecutor.egress(service:$0,commands:Commands())})->Task<Void,Never>? {
        guard !testingIP,!busy,(!fillEgress || state.phase=="off") else{return nil}
        testingIP=true
        let expected=settings.expectedEgress,phase=state.phase,version=revision,configVersion=settingsRevision
        return Task {
            let result=await IPCheck.run(expected:expected,fetch:fetch)
            ipCheck=result;testingIP=false
            ipStale=(revision != version || state.phase != phase || settingsRevision != configVersion)
            if fillEgress {
                guard !busy,state.phase=="off",!ipStale,let ip=detectedEgress else {
                    failure="出口未填写：检测失败、结果不一致或配置已变化，请重新检测。";return
                }
                settings.expectedEgress=ip
                ipCheck = .init(expected:ip,samples:result.samples,startedAt:result.startedAt)
                ipStale=false;failure=""
            }
        }
    }
    @discardableResult public func readFlClashConfigurations(read:@escaping @Sendable ()throws->FlClashCatalog = {try FlClashCatalog.discover()})->Task<Void,Never>? {
        guard !busy,!readingFlClash,state.phase=="off" else{return nil}
        readingFlClash=true;flclashCatalog=nil;flclashCatalogError=""
        let version=revision
        return Task.detached{[weak self] in
            let result=Result{try read()}
            await MainActor.run {
                guard let self else{return};self.readingFlClash=false
                guard version==self.revision,!self.busy,self.state.phase=="off" else{return}
                switch result {
                case .success(let catalog):self.flclashCatalog=catalog
                case .failure(let error):self.flclashCatalogError=String(describing:error)
                }
            }
        }
    }
    @discardableResult public func readFlClashCurrentChain(read:@escaping @Sendable ()throws->FlClashCurrentChain = {try FlClashCurrentChain.read()})->Task<Void,Never>? {
        guard !busy,!readingFlClash,state.phase=="off" else{return nil}
        readingFlClash=true;currentChainMessage="正在读取 FLClash 当前链路…";confirmation=false
        let version=revision,configVersion=settingsRevision
        return Task { [weak self] in
            let result=await Task.detached {Result{try read()}}.value
            guard let self else{return};self.readingFlClash=false
            guard version==self.revision,configVersion==self.settingsRevision,!self.busy,self.state.phase=="off" else {
                self.currentChainMessage="读取期间状态或设置已变化，结果未应用。";return
            }
            switch result {
            case .success(let hint):
                self.currentChainMessage="已读取保存的选择，正在登记生成配置…"
                await self.request(.registerProxyConfiguration,configurationPath:hint.configurationPath,currentChain:hint)?.value
                if !self.failure.isEmpty {self.currentChainMessage="当前链路未完成读取或登记，请查看错误信息。"}
            case .failure(let error):
                self.currentChainMessage="当前链路未读取；未更改代理。";self.failure=String(describing:error)
            }
        }
    }
    public func chooseProxyConfiguration() {
        guard !busy,state.phase=="off" else{return}
        let panel=NSOpenPanel();panel.canChooseFiles=true;panel.canChooseDirectories=false;panel.allowsMultipleSelection=false
        panel.message="选择单节点 HTTP 或含拓展脚本结果的链式生成配置。不会切换订阅；安全启动还会核验 Core、网关连接、TUN 与出口。"
        if panel.runModal() == .OK,let url=panel.url {request(.registerProxyConfiguration,configurationPath:url.path)}
    }
    public func export() {
        let panel=NSSavePanel();panel.nameFieldStringValue="ClaudeGuard反馈.json";panel.allowedContentTypes=[.json]
        if panel.runModal() == .OK,let url=panel.url {
            do{let enc=JSONEncoder();enc.outputFormatting=[.prettyPrinted,.sortedKeys];var data=try JSONSerialization.jsonObject(with:enc.encode(state)) as! [String:Any];data["uiHeartbeat"]=try JSONSerialization.jsonObject(with:enc.encode(heartbeat.snapshot()));data["communicationWarning"]=communicationWarning;data["operationError"]=failure;data["entryProbeMessage"]=entryProbeMessage;data["entryProbeStale"]=entryProbeStale;data["entryProbeDiagnostics"]=try JSONSerialization.jsonObject(with:enc.encode(entryProbeDiagnostics));if let entryProbeContext {data["entryProbeContext"]=try JSONSerialization.jsonObject(with:enc.encode(entryProbeContext))};if let ipCheck {data["ipTest"]=try JSONSerialization.jsonObject(with:enc.encode(ipCheck));data["ipTestStale"]=ipStale};try JSONSerialization.data(withJSONObject:data,options:[.prettyPrinted,.sortedKeys]).write(to:url,options:.atomic)}catch{failure="报告保存失败"}
        }
    }
}
