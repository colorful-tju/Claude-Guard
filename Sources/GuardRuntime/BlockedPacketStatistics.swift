import Foundation
import GuardCore

/// PF packets, not requests or attribution. Baseline is captured after startup probes.
/// Losing/resetting a baseline never silently rebases the session to zero.
struct BlockedPacketStatistics {
    private var baseline:[String:UInt64]
    private var previous:[String:UInt64]
    private var invalidated=false
    init(policy:GuardPolicy,text:String) throws {
        let labels=policy.rules.split(separator:"\n").filter{$0.hasPrefix("block ")}.compactMap{row -> String? in
            let parts=row.split(separator:"\"");return parts.count==2 ? String(parts[1]):nil
        }
        guard labels.count==5 else{throw fail("Unsupported block statistics labels")}
        baseline=try Dictionary(uniqueKeysWithValues:labels.map{($0,try PFText.counter(text,label:$0))});previous=baseline
    }
    mutating func read(_ text:String) throws -> UInt64 {
        guard !invalidated else{throw fail("Block statistics baseline invalidated")}
        let current=try Dictionary(uniqueKeysWithValues:baseline.keys.map{($0,try PFText.counter(text,label:$0))})
        var total:UInt64=0
        for (label,value) in current {
            guard value>=previous[label]! else{invalidated=true;throw fail("Block statistics counter reset")}
            let sum=total.addingReportingOverflow(value-baseline[label]!)
            guard !sum.overflow else{invalidated=true;throw fail("Block statistics overflow")}
            total=sum.partialValue
        }
        previous=current;return total
    }
}
