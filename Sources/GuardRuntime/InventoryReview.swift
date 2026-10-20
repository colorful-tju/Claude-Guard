import Foundation
import GuardCore

struct InventoryDiagnostic: Codable {
    struct Identity: Codable {
        var pid:Int32;var stage:String;var trackedClaude:Bool
        var rc:Int32?;var errno:Int32?;var name:String?;var startTime:UInt64?;var disposition:String
    }
    var state:String;var elapsed:Double;var observations:Int;var nativeRechecks:Int;var nativeRecovered:Int
    var identities:[Identity];var issues:[String]
    var sessionID:String?;var capturedAt:String?
}

/// Monotonic, shared across tick and asynchronous local revalidation. Never sleeps on the transaction queue.
struct InventoryReview {
    struct Outcome {var expired:Bool;var event:String?}
    private var began:Double?
    private var attempts=0
    private var retries=0
    private var recovered=0
    private var failed:[Int32:FailedIdentity]=[:]
    private var prior:[Int32:ProcessIdentity]=[:]
    mutating func observe(_ inventory:ProcessInventory,now:Double,tracked:[ProcessIdentity])->Outcome {
        guard now.isFinite,now >= (began ?? now) else{return .init(expired:true,event:"invalid monotonic clock")}
        if inventory.complete, began == nil {return .init(expired:false,event:nil)}
        let first=began == nil
        if first {began=now;prior=Dictionary(tracked.map{($0.pid,$0)},uniquingKeysWith:{$1})}
        attempts += 1;retries += inventory.rechecked;recovered += inventory.recovered
        for failure in inventory.failures where failed.count<64 || failed[failure.pid] != nil {failed[failure.pid]=failure}
        let elapsed=now-began!
        let expired=elapsed>=5
        let result=inventory.complete ? (expired ? "expired":"recovered") : (expired ? "expired":"pending")
        // Even a late full scan cannot retroactively prove the five-second observation lease.
        var event:String?
        if first || inventory.complete || expired {
            let identities:[[String:Any]]=failed.keys.sorted().map { pid in
                let failure=failed[pid]!
                let row=inventory.records.first{$0.pid==pid}
                var value:[String:Any]=["pid":pid,"stage":failure.stage,"trackedClaude":prior[pid] != nil]
                if let rc=failure.rc {value["rc"]=rc};if let errno=failure.errnoCode {value["errno"]=errno}
                if let row {
                    value["name"]=row.name;value["startTime"]=row.started
                    value["disposition"]=prior[pid].map{$0.startTime==row.started ? "same-lifetime-readable":"pid-reused"} ?? "readable-no-prior-identity"
                } else {value["disposition"]=inventory.complete ? "absent-in-complete-inventory":"unknown"}
                return value
            }
            let payload:[String:Any]=["state":result,"elapsed":elapsed,"observations":attempts,"nativeRechecks":retries,"nativeRecovered":recovered,"identities":identities,"issues":Array(inventory.issues.prefix(8))]
            event=(try? JSONSerialization.data(withJSONObject:payload,options:[.sortedKeys])).map{String(decoding:$0,as:UTF8.self)} ?? "diagnostic encoding failed"
        }
        if inventory.complete && !expired {self=InventoryReview()}
        return .init(expired:expired,event:event)
    }
}
