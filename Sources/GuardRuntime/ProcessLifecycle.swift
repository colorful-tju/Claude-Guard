import Foundation
import Darwin
import GuardCore

/// Retry only failed identities. Never infer disappearance from a libproc error alone.
enum ProcessInventoryCollector {
    static func collect(ids:[Int32],read:(Int32)throws->ProcessRecord,
                        inactive:(Int32,Error)->Bool,wait:(TimeInterval)->Void)->ProcessInventory {
        var rows:[ProcessRecord]=[],pending:[Int32:Error]=[:]
        for pid in Set(ids).sorted() where pid>0 {
            do {rows.append(try read(pid))}
            catch {if !inactive(pid,error){pending[pid]=error}}
        }
        let initial=pending.count
        var rechecked=0
        // A broad permission failure must not create an unbounded per-PID retry delay.
        if pending.count<=64 {
            for _ in 0..<2 where !pending.isEmpty {
                wait(0.01)
                for pid in pending.keys.sorted() {
                    rechecked += 1
                    do {rows.append(try read(pid));pending.removeValue(forKey:pid)}
                    catch {if inactive(pid,error){pending.removeValue(forKey:pid)}else{pending[pid]=error}}
                }
            }
        }
        let issues=pending.keys.sorted().prefix(8).map{"pid=\($0) after bounded identity recheck: \(pending[$0]!)"}
            + (pending.count>8 ? ["Additional unreadable identities: \(pending.count-8)"]:[])
        return .init(records:rows,issues:issues,rechecked:rechecked,recovered:initial-pending.count)
    }
}

/// A partial enumeration must not prevent attempts to stop already identified targets.
/// It also must NEVER authorize PF removal: final complete absence remains mandatory.
enum ClaudeTermination {
    static func run(uid:UInt32,known:[ProcessIdentity],inventory:()->ProcessInventory,
                    read:(Int32)throws->ProcessRecord,inactive:(Int32,Error)->Bool,
                    send:(Int32,Int32)throws->Void,wait:(TimeInterval)->Void) throws {
        var tracked=Dictionary(known.map{($0.pid,$0)},uniquingKeysWith:{$1})
        for signal in [SIGTERM,SIGKILL] {
            let snapshot=inventory()
            for row in NativeProcesses.claude(snapshot.records,uid:uid,known:Array(tracked.values)) {
                tracked[row.pid]=row.identity
            }
            for expected in tracked.values.sorted(by:{$0.pid<$1.pid}) {
                do {
                    let current=try read(expected.pid)
                    // exec may change a tool's path; lifetime+UID must remain the same.
                    guard current.started==expected.startTime,current.uid==uid else{tracked.removeValue(forKey:expected.pid);continue}
                    guard !current.path.hasPrefix(Paths.app+"/Contents/") else{continue}
                    try send(current.pid,signal)
                }catch{
                    if inactive(expected.pid,error){tracked.removeValue(forKey:expected.pid)}
                    // Continue other verified targets. The final inventory proves whether
                    // a failed read/signal resolved, rather than equating it to absence.
                }
            }
            wait(signal==SIGTERM ? 0.5:0.1)
        }
        let final=try inventory().requireComplete()
        let survivors=NativeProcesses.claude(final,uid:uid,known:Array(tracked.values))
        guard survivors.isEmpty else{throw fail("Claude/Code/tools still present; protection retained; pids=\(survivors.prefix(16).map{String($0.pid)}.joined(separator:","))")}
    }
}
