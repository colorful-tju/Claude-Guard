import Foundation
import Combine
import AppKit
import GuardRuntime
import GuardCore

@MainActor public final class AppModel:ObservableObject {
    @Published public var ipCheck:IPCheck?
    @Published public var testingIP=false
    @Published public var ipStale=false
    @Published public var state=Status() {didSet{observeInterruption()}}
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
    public var guidance:Guidance {
        if state.phase=="off",!busy,failure.isEmpty,needsIPv6Off {return Guidance.reason("IPv6 default route detected")}
        return Guidance.current(state,failure:failure,busy:busy,confirmation:confirmation,ip:ipCheck,stale:ipStale || ipCheck?.expected != settings.expectedEgress)
    }
    @Published public var settings=Settings() {didSet {
        confirmation=false;ipStale=true;settingsRevision += 1
        saveSettings()
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
    public var menuStatus:String {
        if busy{return "处理中"}
        if state.verified && state.phase=="armed" {return "已防护"}
        switch state.phase {case "off":return "OFF";case "recoveryBlocked":return "恢复受阻";default:return "待核验"}
    }
    @Published public var busy=false
    @Published public var failure=""
    @Published public var confirmation=false
    private let transport:@Sendable (Request)throws->Reply
    private let preferences:UserDefaults?
    private var timer:Timer?
    private var pollingStatus=false
    private var pollingProgress=false
    private var heartbeatPending=false
    private var settingsRevision:UInt64=0
    private var revision:UInt64=0
    private var stopping=false
    public init(autoPoll:Bool=true,preferences:UserDefaults? = .standard,ipv6Reader:@escaping @Sendable ()->IPv6Preview = {IPv6Preview.read()},transport:@escaping @Sendable (Request)throws->Reply = {try Wire.client($0)}) {
        self.transport=transport;self.preferences=preferences;self.ipv6Reader=ipv6Reader;self.enableIPv6Polling=autoPoll;state.daemonBuildID=""
        if let data=preferences?.data(forKey:"publicSettingsV1"),let saved=try? JSONDecoder().decode(Settings.self,from:data){settings=saved}
        onboardingComplete=preferences?.bool(forKey:"publicOnboardingV1") ?? false
        if autoPoll {
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
        // Heartbeat never waits for status on the serialized daemon transaction queue.
        if !heartbeatPending {
            heartbeatPending=true
            Task.detached{[weak self] in
                do {
                    _=try call(.init(.heartbeat))
                    await MainActor.run{self?.heartbeatPending=false}
                }catch {
                    await MainActor.run{guard let self else{return};self.heartbeatPending=false;self.communicationFailed(version)}
                }
            }
        }
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
                        self.state=reply.status
                        if !reply.ok{self.state.verified=false;self.failure=reply.error ?? "运行态读取失败"}
                    }
                }catch {
                    await MainActor.run{guard let self else{return};self.pollingStatus=false;self.communicationFailed(version)}
                }
            }
        }
    }
    @discardableResult public func request(_ operation:GuardOperation)->Task<Void,Never>? {
        if [.stop,.shutdown].contains(operation) {guard !stopping else{return nil};stopping=true}
        else {guard !busy else{return nil}}
        if [.start,.verify].contains(operation) {
            guard state.phase=="off" else{return nil}
            if needsIPv6Off {failure="IPv6 default route detected";return nil}
        }
        revision+=1;let version=revision
        busy=true;failure="";state.verified=false;ipStale=true
        if [.stop,.shutdown].contains(operation){state.phase="stopping"}
        else if [.start,.verify].contains(operation){state.phase="checking"}
        var saved=settings;saved.providerConfirmed=confirmation;saved.confirmationFingerprint=state.fingerprint
        saveSettings()
        let request=Request(operation,settings:saved),call=transport
        return Task.detached{[weak self] in
            do {
                let reply=try call(request)
                await MainActor.run {
                    guard let self,version==self.revision else{return}
                    if [.stop,.shutdown].contains(operation),reply.ok {self.acknowledgeInterruption()}
                    self.state=reply.status;self.failure=reply.error ?? "";self.busy=false;self.stopping=false
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
                    // A lost reply does not prove the daemon stopped. Request cancellation independently.
                    if [.start,.verify].contains(operation){self.request(.stop)}
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
    public func export() {
        let panel=NSSavePanel();panel.nameFieldStringValue="ClaudeGuard反馈.json";panel.allowedContentTypes=[.json]
        if panel.runModal() == .OK,let url=panel.url {
            do{let enc=JSONEncoder();enc.outputFormatting=[.prettyPrinted,.sortedKeys];var data=try JSONSerialization.jsonObject(with:enc.encode(state)) as! [String:Any];if let ipCheck {data["ipTest"]=try JSONSerialization.jsonObject(with:enc.encode(ipCheck));data["ipTestStale"]=ipStale};try JSONSerialization.data(withJSONObject:data,options:[.prettyPrinted,.sortedKeys]).write(to:url,options:.atomic)}catch{failure="报告保存失败"}
        }
    }
}
