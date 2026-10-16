import Foundation
import GuardCore
import NativeGuard

/// proc_pidinfo + proc_pidfdinfo is not an atomic inventory. Retry the entire
/// read, never merge partial descriptors or reuse an earlier successful sample.
enum SocketInventoryCollector {
    static func collect(pid:Int32,identity:(Int32)throws->ProcessIdentity,
                        read:(Int32)throws->[CSGSocket],wait:(Double)->Void) throws -> [CSGSocket] {
        let original=try identity(pid)
        for attempt in 1...3 {
            guard try identity(pid)==original else{throw fail("Socket owner identity changed: pid=\(pid)")}
            let rows:[CSGSocket]
            do { rows=try read(pid) }
            catch {
                if attempt==3 {throw fail("Socket inventory incomplete: pid=\(pid) attempts=3 last=\(error)")}
                wait(0.025)
                continue
            }
            guard try identity(pid)==original else{throw fail("Socket owner identity changed during read: pid=\(pid)")}
            return rows
        }
        throw fail("Socket inventory unavailable: pid=\(pid)")
    }
}
