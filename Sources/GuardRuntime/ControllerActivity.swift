import Foundation
import Darwin
import GuardCore

public struct GuardClockSample:Sendable {
    public let uptime:TimeInterval
    public let continuous:TimeInterval
    public init(uptime:TimeInterval,continuous:TimeInterval) {self.uptime=uptime;self.continuous=continuous}
}
public protocol GuardClock:Sendable {func sample()->GuardClockSample}
public struct SystemGuardClock:GuardClock {
    public init(){}
    public func sample()->GuardClockSample {
        var base=mach_timebase_info_data_t();mach_timebase_info(&base)
        let factor=Double(base.numer)/Double(base.denom)/1_000_000_000
        return .init(uptime:Double(mach_absolute_time())*factor,continuous:Double(mach_continuous_time())*factor)
    }
}

/// Independent of the serialized transaction queue. Authenticated IPC can cancel a blocked start.
final class ControllerActivity:@unchecked Sendable {
    private let lock=NSLock()
    private let clock:any GuardClock
    private var ping:TimeInterval?
    private var stopped=false
    private var userStop:Bool?
    private var client:ProcessIdentity?
    private var sessionSleepOffset:TimeInterval?
    init(clock:any GuardClock) {self.clock=clock}
    func heartbeat(client:ProcessIdentity?=nil) {let now=clock.sample().uptime;lock.lock();ping=now;if let client{self.client=client};lock.unlock()}
    func clientIdentity()->ProcessIdentity? {lock.lock();defer{lock.unlock()};return client}
    func requestStop() {lock.lock();stopped=true;lock.unlock()}
    func requestUserStop(restoreIPv6:Bool) {lock.lock();stopped=true;userStop=(userStop ?? false) || restoreIPv6;lock.unlock()}
    func requestedUserStop()->Bool? {lock.lock();defer{lock.unlock()};return userStop}
    func clearUserStopIntent() {lock.lock();userStop=nil;lock.unlock()}
    func cancelled()->Bool {lock.lock();defer{lock.unlock()};return stopped}
    func begin() throws {
        try check()
        let sample=clock.sample();lock.lock();sessionSleepOffset=sample.continuous-sample.uptime;lock.unlock()
    }
    func check() throws {
        let sample=clock.sample();lock.lock();let last=ping,cancelled=stopped,offset=sessionSleepOffset;lock.unlock()
        guard !cancelled else{throw fail("Session cancelled by OFF request")}
        guard let last,sample.uptime>=last,sample.uptime-last<6 else{throw fail("UI heartbeat lost")}
        if let offset,abs((sample.continuous-sample.uptime)-offset)>0.25 {throw fail("System sleep/wake detected")}
    }
    func finish() {lock.lock();stopped=false;userStop=nil;sessionSleepOffset=nil;lock.unlock()}
}
