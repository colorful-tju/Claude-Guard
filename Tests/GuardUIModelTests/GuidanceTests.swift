import Testing
import GuardRuntime
@testable import GuardUIModel

struct GuidanceTests {
    @Test @MainActor func pfFailureOffersRemedyOncePerOperationNotEveryPoll() async throws {
        let model=AppModel(autoPoll:false,preferences:nil,transport:{request in
            var status=Status();status.phase="off";status.lastRisk="PF Internet Sharing is not empty; observed=host_v4"
            return .init(ok:request.operation != .verify,status:status,error:request.operation == .verify ? status.lastRisk:nil)
        })
        await model.request(.verify)?.value
        #expect(model.pfIssueAlert != nil)
        let help=try #require(PFDiagnosticHelp(reason:model.pfIssueAlert!))
        #expect(help.steps.contains("保存") && help.steps.contains("OFF"))
        #expect(!help.readOnlyCommand.contains("-F") && !help.readOnlyCommand.contains("-d"))
        model.acknowledgeVisibleAlert()
        model.poll();try await Task.sleep(for:.milliseconds(40))
        #expect(model.pfIssueAlert==nil)
        await model.request(.verify)?.value
        #expect(model.pfIssueAlert != nil)
        await model.request(.stop)?.value
        #expect(model.pfIssueAlert==nil)
    }
    @Test func pfReadFailureAndActualSharingConflictHaveDifferentRemedies() throws {
        let unreadable=try #require(PFDiagnosticHelp(reason:"PF display failed or reported an error; required evidence unavailable"))
        let sharing=try #require(PFDiagnosticHelp(reason:"PF Internet Sharing is not empty"))
        #expect(unreadable.title != sharing.title)
        #expect(!unreadable.steps.contains("shutdown") && sharing.steps.contains("虚拟机"))
        #expect(PFDiagnosticHelp(reason:"Expected egress mismatch")==nil)
    }
    @Test func unknownPFAnchorHasActionableGuidanceWithoutClaimingLeak() {
        let guidance=Guidance.reason("Unknown PF root anchor; observed=[com.apple,vendor.test]")
        #expect(guidance.title.contains("PF") && guidance.action.contains("只读"))
        #expect(guidance.action.contains("不") && !guidance.title.contains("泄漏"))
    }
    @Test func internetSharingIsExplainedAsCompatibilityNotIPMismatch() {
        let guidance=Guidance.reason("PF Internet Sharing is not empty; observed=host_v4")
        #expect(guidance.title.contains("共享") && guidance.action.contains("虚拟机"))
        #expect(guidance.action.contains("不") && !guidance.title.contains("泄漏"))
    }
    @Test func unrelatedUnknownRootIsNotBlamedOnEmptySharing() throws {
        let reason="Unknown PF root anchor; observed=com.apple,com.apple.internet-sharing,vendor.test; count=3"
        let help=try #require(PFDiagnosticHelp(reason:reason))
        #expect(!help.steps.contains("Parallels") && help.steps.contains("实际分支"))
        #expect(Guidance.reason(reason).category=="防火墙环境待核对")
        let change="PF Internet Sharing inventory changed during inspection"
        #expect(Guidance.reason(change).category=="环境正在变化")
        #expect(PFDiagnosticHelp(reason:change)?.title.contains("变化")==true)
    }
    @Test @MainActor func daemonReportedOFFIsNotMislabelledAsIPCFailure() async throws {
        let model=AppModel(autoPoll:false,preferences:nil,transport:{ request in
            var status=Status();status.phase="off"
            return .init(ok:request.operation != .status,status:status,error:request.operation == .status ? "Process inventory incomplete":nil)
        })
        model.poll()
        for _ in 0..<200 where model.failure.isEmpty {try await Task.sleep(for:.milliseconds(2))}
        #expect(!model.failure.isEmpty)
        #expect(model.state.phase=="off" && !model.state.verified)
    }
    @Test func knownProblemsHaveActionableChineseAndUnknownIsNotCalledLeak() {
        #expect(Guidance.reason("IPv6 default route detected").category=="需要操作")
        #expect(Guidance.reason("Command deadline-exceeded: guard-probe").title.contains("超时"))
        #expect(Guidance.reason("Expected egress mismatch").category=="网络未通过")
        #expect(Guidance.reason("something unknown").action.contains("不要"))
    }
    @Test @MainActor func eventIsDeduplicatedAndNoPopupForNormalExitOrOldText() {
        let model=AppModel(autoPoll:false,preferences:nil)
        model.state.lastRisk="Claude 已退出"
        #expect(model.interruptionAlert==nil)
        model.state.lastRisk="Protected runtime premises changed"
        #expect(model.interruptionAlert==nil) // no inference from unstructured text
        var event=ProtectionInterruption(reason:"Protected runtime premises changed: routeFingerprint",requestedClaudeStop:true)
        model.state.interruption=event
        #expect(model.interruptionAlert?.exitConfirmed==false)
        model.acknowledgeInterruption();model.state.message="poll refresh"
        #expect(model.interruptionAlert==nil)
        event=ProtectionInterruption(reason:"second incident",requestedClaudeStop:true);event.exitConfirmed=true
        model.state.interruption=event
        #expect(model.interruptionAlert?.exitConfirmed==true)
    }
    @Test @MainActor func egressWarningIsDistinctDeduplicatedAndClearsOnRecovery() {
        let model=AppModel(autoPoll:false,preferences:nil)
        model.state.phase="armed";model.state.verified=true;model.state.egressRechecking=true
        let event=EgressWarning(reason:"services-unavailable")
        model.state.egressWarning=event
        #expect(model.egressWarningAlert?.id==event.id && model.interruptionAlert==nil)
        #expect(model.bannerTone == .waiting && model.menuStatus=="出口待核验")
        #expect(model.guidance.action.contains("5 分钟"))
        model.acknowledgeVisibleAlert();model.state.message="poll"
        #expect(model.egressWarningAlert==nil)
        model.state.egressWarning=nil;model.state.egressRechecking=false
        model.state.egressWarning=EgressWarning(reason:"new outage")
        #expect(model.egressWarningAlert != nil)
        model.state.phase="off"
        #expect(model.egressWarningAlert==nil)
    }
    @Test func recoveryBlockedOutranksOldSuccessAndIPv6OffIsNotAnError() {
        var status=Status();status.phase="recoveryBlocked";status.verified=true
        #expect(Guidance.current(status,failure:"",busy:false,confirmation:true,ip:nil,stale:false).title.contains("恢复受阻"))
        status=Status();status.processInventoryComplete=true;status.fingerprint="x";status.ipv6Override="临时 Off"
        #expect(Guidance.current(status,failure:"",busy:false,confirmation:true,ip:nil,stale:false).category=="待启动")
    }
}

struct ClaudeUpdateGuidanceTests {
    @Test func buildChangeExplainsRegistrationInsteadOfNetworkFailure() {
        let message=Guidance.reason("rejected(\"Claude build changed; reinstall registration\")")
        #expect(message.title.contains("Claude") && message.action.contains("重新登记"))
    }
}

struct ProxyConfigurationGuidanceTests {
    @Test func pointsToConfigurationSelection() {
        let guidance=Guidance.reason("Proxy configuration: 读取到 22 个节点")
        #expect(guidance.title.contains("22") && guidance.action.contains("选择并登记配置"))
    }
}
