import Foundation
import Testing
import GuardRuntime
@testable import GuardUIModel
private final class UITransport:@unchecked Sendable {
    let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0)
    let lock=NSLock();var started=false;var operations:[GuardOperation]=[]
    var failAll=false
    func hasEntered()->Bool{lock.lock();defer{lock.unlock()};return started}
    func snapshot()->[GuardOperation]{lock.lock();defer{lock.unlock()};return operations}
    func call(_ request:Request)throws->Reply {
        lock.lock();operations.append(request.operation);let failNow=failAll;lock.unlock()
        if failNow{throw fail("injected IPC failure")}
        if request.operation == .verify {
            lock.lock();started=true;lock.unlock();entered.signal();guard release.wait(timeout:.now()+2) == .success else{throw fail("fixture deadline")}
            var s=Status();s.phase="armed";s.verified=true;return .init(ok:true,status:s)
        }
        return .init(ok:true,status:Status())
    }
}
struct AppModelTests {
    @Test @MainActor func OFFRemainsAvailableWhileVerifyIsBusyAndLateArmedIsIgnored() async throws {
        let transport=UITransport();let model=AppModel(autoPoll:false,preferences:nil,transport:transport.call)
        let verify=try #require(model.request(.verify))
        for _ in 0..<200 where !transport.hasEntered(){try await Task.sleep(for:.milliseconds(2))}
        #expect(model.busy)
        let stop=try #require(model.request(.stop));await stop.value
        transport.release.signal();await verify.value
        #expect(model.state.phase=="off" && !model.state.verified && !model.busy)
    }
    @Test @MainActor func FailedRPCNeverLeavesOldArmedGreen() async throws {
        let transport=UITransport();transport.failAll=true
        let model=AppModel(autoPoll:false,preferences:nil,transport:transport.call)
        model.state.phase="armed";model.state.verified=true
        let action=try #require(model.request(.inspect));await action.value
        #expect(model.state.phase=="unverified" && !model.state.verified)
        #expect(model.request(.start)==nil)
    }
    @Test @MainActor func FailedStartRequestsIndependentOFFAndCannotClaimSafety() async throws {
        let transport=UITransport();transport.failAll=true
        let model=AppModel(autoPoll:false,preferences:nil,transport:transport.call)
        let action=try #require(model.request(.start));await action.value
        for _ in 0..<200 where model.busy{try await Task.sleep(for:.milliseconds(2))}
        #expect(model.state.phase=="unverified" && !model.state.verified)
        let calls=transport.snapshot()
        #expect(calls==[.start,.stop])
    }
}

private final class SlowStatus:@unchecked Sendable {
    let lock=NSLock(),release=DispatchSemaphore(value:0)
    var beats=0,statusStarted=false
    func snapshot()->(Int,Bool){lock.lock();defer{lock.unlock()};return(beats,statusStarted)}
    func call(_ request:Request)throws->Reply {
        if request.operation == .heartbeat {lock.lock();beats+=1;lock.unlock()}
        if request.operation == .status {
            lock.lock();statusStarted=true;lock.unlock()
            guard release.wait(timeout:.now()+2) == .success else{throw fail("fixture timeout")}
        }
        return .init(ok:true,status:Status())
    }
}
struct UIHeartbeatTests {
    @Test @MainActor func heartbeatContinuesWhileStatusIsWaitingOnTransactionQueue() async throws {
        let transport=SlowStatus(),model=AppModel(autoPoll:false,preferences:nil,transport:transport.call)
        model.poll()
        for _ in 0..<200 {
            if transport.snapshot().0>=1 && transport.snapshot().1{break}
            try await Task.sleep(for:.milliseconds(2))
        }
        // Let heartbeat completion return to MainActor, while status deliberately stays blocked.
        try await Task.sleep(for:.milliseconds(10));model.poll()
        for _ in 0..<200 where transport.snapshot().0<2{try await Task.sleep(for:.milliseconds(2))}
        #expect(transport.snapshot().0>=2)
        transport.release.signal()
    }
}

private final class StopHeartbeatFailure:@unchecked Sendable {
    let lock=NSLock(),release=DispatchSemaphore(value:0)
    var started=false,failed=false
    func snapshot()->(Bool,Bool){lock.lock();defer{lock.unlock()};return(started,failed)}
    func call(_ request:Request)throws->Reply {
        if request.operation == .heartbeat {lock.lock();failed=true;lock.unlock();throw fail("injected heartbeat failure during OFF")}
        if request.operation == .stop {
            lock.lock();started=true;lock.unlock()
            guard release.wait(timeout:.now()+2) == .success else{throw fail("fixture timeout")}
        }
        return .init(ok:true,status:Status())
    }
}
struct UIStopRecoveryTests {
    @Test @MainActor func heartbeatFailureCannotOrphanPendingOFFAndPermanentlyDisableFutureOFF() async throws {
        let transport=StopHeartbeatFailure(),model=AppModel(autoPoll:false,preferences:nil,transport:transport.call)
        let first=try #require(model.request(.stop))
        for _ in 0..<200 where !transport.snapshot().0{try await Task.sleep(for:.milliseconds(2))}
        model.poll()
        for _ in 0..<200 where !transport.snapshot().1{try await Task.sleep(for:.milliseconds(2))}
        try await Task.sleep(for:.milliseconds(5))
        transport.release.signal();await first.value
        #expect(!model.busy && model.state.phase=="off")
        let second=try #require(model.request(.stop))
        transport.release.signal();await second.value
        #expect(!model.busy && model.state.phase=="off")
    }
}

struct UIProgressTests {
    @Test @MainActor func progressDuringBusyCannotSetArmedOrEnableButtons() async throws {
        let model=AppModel(autoPoll:false,preferences:nil,transport:{request in
            var s=Status()
            if request.operation == .progress {s.phase="progressOnly";s.message="offline preflight";s.report="real stage";s.verified=true}
            return .init(ok:true,status:s)
        })
        model.busy=true;model.state.phase="checking";model.poll()
        for _ in 0..<100 where model.state.message != "offline preflight" {try await Task.sleep(for:.milliseconds(5))}
        #expect(model.state.message=="offline preflight" && model.state.report=="real stage")
        #expect(model.busy && !model.state.verified && model.state.phase=="checking")
    }
}
