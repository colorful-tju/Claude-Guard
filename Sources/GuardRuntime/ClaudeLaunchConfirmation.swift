import Foundation
import GuardCore

/// A successful LaunchServices command alone is insufficient launch evidence.
/// This observes the real main executable; Helpers and Claude Code do not qualify.
enum ClaudeLaunchConfirmation {
    static let mainPath="/Applications/Claude.app/Contents/MacOS/Claude"
    static func observe(uid:UInt32,cancelled:@escaping @Sendable ()->Bool,
                        inventory:()->ProcessInventory={NativeProcesses.inventory()},
                        reread:(Int32)throws->ProcessRecord={try NativeProcesses.record($0)},
                        attempts:Int=20,pause:()->Void={Thread.sleep(forTimeInterval:0.1)}) throws -> ProcessRecord {
        for _ in 0..<attempts {
            guard !cancelled() else{throw fail("Claude launch confirmation cancelled")}
            for row in inventory().records where row.uid==uid && row.path==mainPath {
                if let current=try? reread(row.pid),current.uid==uid,current.path==mainPath,current.identity==row.identity {
                    guard !cancelled() else{throw fail("Claude launch confirmation cancelled")}
                    return current
                }
            }
            pause()
        }
        throw fail("Claude main process not observed after launch")
    }
}
