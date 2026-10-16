import Foundation

/// Defined outside executable main's implicit MainActor. The dispatch callback is
/// explicitly Sendable, so Swift 6 does not assert MainActor on the daemon queue.
public enum DaemonTimer {
    public static func start(on queue:DispatchQueue,after:TimeInterval=1,
                             repeating:TimeInterval=1,
                             handler:@escaping @Sendable ()->Void) -> DispatchSourceTimer {
        let timer=DispatchSource.makeTimerSource(queue:queue)
        timer.schedule(deadline:.now()+after,repeating:repeating)
        timer.setEventHandler(handler:handler)
        timer.resume()
        return timer
    }
}
