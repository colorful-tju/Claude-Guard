import Foundation
import GuardCore

/// Same 10-second command budget as before; independent services run concurrently.
/// A valid conflicting address always fails, even if the other address is expected.
enum PeriodicEgress {
    static func evaluate(_ values:[String?]) throws -> String {
        let valid=values.compactMap{$0}
        guard values.count==2,!valid.isEmpty,valid.allSatisfy({IPv4.isPublic($0)}),Set(valid).count==1 else {
            throw fail("Periodic egress services unavailable or conflicting")
        }
        return valid[0]
    }
    private final class Results:@unchecked Sendable {
        private let lock=NSLock()
        private var values:[String?]=[nil,nil]
        func set(_ value:String?,at index:Int){lock.lock();values[index]=value;lock.unlock()}
        func read()->[String?]{lock.lock();defer{lock.unlock()};return values}
    }
    static func read(cancelled:@escaping @Sendable ()->Bool,
                     fetch:@escaping @Sendable (EgressService)throws->String) throws -> String {
        guard !cancelled() else{throw fail("Periodic egress cancelled")}
        let results=Results(),services=EgressService.allCases
        DispatchQueue.concurrentPerform(iterations:services.count){index in
            guard !cancelled() else{return}
            results.set(try? fetch(services[index]),at:index)
        }
        guard !cancelled() else{throw fail("Periodic egress cancelled")}
        return try evaluate(results.read())
    }
}
