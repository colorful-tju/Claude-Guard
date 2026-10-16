import Foundation
import GuardRuntime

/// Serial background ownership: neither scheduling nor completion waits for MainActor.
/// A failed attempt is telemetry, not authority to remove PF. The daemon owns the lease.
final class HeartbeatPump:@unchecked Sendable {
    struct Snapshot:Sendable,Codable {var attempts=0;var failures=0;var elapsed:Double=0;var schedulingDelay:Double=0;var error=""}
    private let queue=DispatchQueue(label:"guard.ui-heartbeat",qos:.userInitiated)
    private let lock=NSLock()
    private let call:@Sendable (Request)throws->Reply
    private var timer:DispatchSourceTimer?
    private var result=Snapshot()
    private var lastStart:Double?
    private var queued=false
    init(transport:@escaping @Sendable (Request)throws->Reply){call=transport}
    func start() {
        let timer=DispatchSource.makeTimerSource(queue:queue)
        timer.schedule(deadline:.now(),repeating:1,leeway:.milliseconds(100))
        timer.setEventHandler{[weak self] in self?.send()}
        self.timer=timer;timer.resume()
    }
    deinit {timer?.cancel()}
    func pulse() {
        lock.lock();guard !queued else{lock.unlock();return};queued=true;lock.unlock()
        queue.async{[weak self] in guard let self else{return};self.send();self.lock.lock();self.queued=false;self.lock.unlock()}
    }
    func snapshot()->Snapshot {lock.lock();defer{lock.unlock()};return result}
    private func send() {
        let started=ProcessInfo.processInfo.systemUptime
        let delay=lastStart.map{max(0,started-$0-1)} ?? 0;lastStart=started
        var error=""
        do {let reply=try call(.init(.heartbeat));guard reply.ok else{throw fail("Heartbeat acknowledgement rejected")}}
        catch let caught {error=String(describing:caught)}
        let elapsed=ProcessInfo.processInfo.systemUptime-started
        lock.lock();result.attempts+=1;result.elapsed=elapsed;result.schedulingDelay=delay;result.error=error
        if !error.isEmpty{result.failures+=1};lock.unlock()
    }
}

/// Token lifetime follows the protected session, without preventing system sleep.
final class ProcessActivityLease:@unchecked Sendable {
    private let token=ProcessInfo.processInfo.beginActivity(options:.userInitiatedAllowingIdleSystemSleep,reason:"Claude Guard protection control heartbeat")
    deinit {ProcessInfo.processInfo.endActivity(token)}
}
