import Foundation
import GuardCore

/// Incomplete inventories are diagnostic data only, never launch/termination evidence.
public struct FailedIdentity: Codable, Sendable {
    public var pid:Int32
    public var stage:String
    public var rc:Int32?
    public var errnoCode:Int32?
}
public struct IncompleteProcessInventory: Error, Sendable, CustomStringConvertible {
    public var failures:[FailedIdentity]
    public var issues:[String]
    public var description:String { "Process inventory incomplete: " + issues.prefix(8).joined(separator:"; ") }
}
public struct ProcessInventory: Sendable {
    public var failures:[FailedIdentity]=[]
    public var records:[ProcessRecord]
    public var issues:[String]
    public var rechecked:Int
    public var recovered:Int
    public var complete:Bool { issues.isEmpty }
    public init(records:[ProcessRecord],issues:[String],rechecked:Int=0,recovered:Int=0,failures:[FailedIdentity]=[]){self.failures=failures;self.records=records;self.issues=issues;self.rechecked=rechecked;self.recovered=recovered}
    public func requireComplete() throws -> [ProcessRecord] {
        guard complete else{throw IncompleteProcessInventory(failures:failures,issues:issues)}
        return records
    }
}
extension Status {
    public mutating func applyPreview(_ inventory:ProcessInventory,uid:UInt32,allowPartial:Bool,known:[ProcessIdentity]=[],corePath:String="/Applications/FlClash.app/Contents/MacOS/FlClashCore") throws {
        if !allowPartial { _ = try inventory.requireComplete() }
        processInventoryComplete=inventory.complete
        processWarning=inventory.issues.prefix(8).joined(separator:"; ")
        flclash=inventory.records.contains{($0.uid==uid || $0.uid==0) && $0.path==corePath}
        let present = !NativeProcesses.claude(inventory.records,uid:uid,known:known).isEmpty
        claudeKnown = present || inventory.complete
        if claudeKnown == true { claude = present }
        // Observed presence is evidence; absence under a partial scan remains unknown.
        // Partial process metadata cannot revoke independently verified PF protection.
    }
}
