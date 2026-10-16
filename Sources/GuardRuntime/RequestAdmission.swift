import Foundation
/// OFF invalidates starts already waiting on the transaction queue, even after recovery clears cancellation.
public final class RequestAdmission:@unchecked Sendable {
    private let lock=NSLock();private var generation:UInt64=0
    public init(){}
    public func ticket()->UInt64 {lock.lock();defer{lock.unlock()};return generation}
    public func cancelPendingStarts(){lock.lock();generation &+= 1;lock.unlock()}
    public func accepts(_ ticket:UInt64)->Bool {lock.lock();defer{lock.unlock()};return ticket==generation}
}
