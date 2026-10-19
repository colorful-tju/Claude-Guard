import Foundation
import GuardCore

public struct EgressSample:Codable,Sendable {
    public var service:EgressService
    public var ip:String?
    public var error:String
    public var elapsed:Double
    public var completedAt:Double
}
public struct EgressReport:Codable,Sendable {
    public var startedAt:Double
    public var finishedAt:Double
    public var samples:[EgressSample]
    public var cancelled=false
}
public struct EgressDiagnostic:Codable,Sendable {
    public var report:EgressReport
    public var queueDelay:Double
    public var proofAge:Double
    public var failures:Int
    public var decision:String
    public var retryAfterSeconds:Double? = nil
    public var proofRemainingSeconds:Double? = nil
}

enum EgressDecision:Equatable {case verified,retry(String),stop(String)}
/// Only lack of evidence gets a bounded retry, never contradictory evidence.
struct EgressMonitor {
    private(set) var lastVerifiedAt:Double
    private(set) var failures=0
    private(set) var nextCheckAt:Double
    init(verifiedAt:Double){lastVerifiedAt=verifiedAt;nextCheckAt=verifiedAt+15}
    func expired(at now:Double)->Bool {now<lastVerifiedAt || now-lastVerifiedAt>=45}
    mutating func consume(_ report:EgressReport,expected:String,now:Double)->EgressDecision {
        // Mismatching public IP takes precedence over age: never hide it with a retry.
        if report.samples.contains(where:{$0.ip.map{IPv4.isPublic($0) && $0 != expected} ?? false}) {
            return .stop("Periodic egress mismatch")
        }
        if expired(at:now){return .stop("Periodic egress proof expired")}
        if report.cancelled{return .stop("Periodic egress cancelled")}
        let coherent=report.samples.count==2 && Set(report.samples.map(\.service))==Set(EgressService.allCases)
            && report.startedAt.isFinite && report.finishedAt.isFinite && now.isFinite
            && report.startedAt<=report.finishedAt && report.finishedAt<=now
            && report.samples.allSatisfy{$0.completedAt.isFinite && $0.elapsed.isFinite && $0.elapsed>=0 && $0.completedAt>=report.startedAt && $0.completedAt<=report.finishedAt}
        let matches=report.samples.filter{$0.ip==expected && $0.error.isEmpty}
        var reason="invalid-evidence"
        if coherent {
            if matches.isEmpty {reason="services-unavailable"}
            else if !matches.contains(where:{now-$0.completedAt<=10}) {reason="result-stale"}
            else {
                lastVerifiedAt=matches.map(\.completedAt).max()!;failures=0;nextCheckAt=now+15
                return .verified
            }
        }
        // Spread fast TLS failures; the absolute proof deadline is never extended.
        failures+=1;nextCheckAt=now+(failures==1 ? 6:10)
        return failures>=3 ? .stop("Periodic egress retry limit: "+reason):.retry(reason)
    }
}

enum PeriodicEgress {
    static func evaluate(_ values:[String?]) throws -> String {
        let valid=values.compactMap{$0}
        guard values.count==2,!valid.isEmpty,valid.allSatisfy({IPv4.isPublic($0)}) else{throw fail("Periodic egress services unavailable")}
        guard Set(valid).count==1 else{throw fail("Periodic egress conflicting addresses")}
        return valid[0]
    }
    private final class Results:@unchecked Sendable {
        private let lock=NSLock();private var values:[EgressSample?]=[nil,nil]
        func set(_ value:EgressSample,at index:Int){lock.lock();values[index]=value;lock.unlock()}
        func read()->[EgressSample]{lock.lock();defer{lock.unlock()};return values.compactMap{$0}}
    }
    static func collect(cancelled:@escaping @Sendable ()->Bool,
                        fetch:@escaping @Sendable (EgressService)throws->String)->EgressReport {
        let clock=SystemGuardClock(),started=clock.sample().uptime
        let results=Results(),services=EgressService.allCases
        DispatchQueue.concurrentPerform(iterations:services.count){index in
            let begin=clock.sample().uptime;var ip:String?,error=""
            do {
                guard !cancelled() else{throw fail("Periodic egress cancelled")}
                let value=try fetch(services[index]);guard IPv4.isPublic(value) else{throw fail("Invalid HTTPS echo response")};ip=value
            }catch let caught {
                // Fixed echo URLs, no response body or credentials. Bound and flatten diagnostic text.
                error=String(String(describing:caught).unicodeScalars.filter{!CharacterSet.controlCharacters.contains($0)}.prefix(256))
            }
            let end=clock.sample().uptime
            results.set(.init(service:services[index],ip:ip,error:error,elapsed:end-begin,completedAt:end),at:index)
        }
        return .init(startedAt:started,finishedAt:clock.sample().uptime,samples:results.read(),cancelled:cancelled())
    }
    static func read(cancelled:@escaping @Sendable ()->Bool,fetch:@escaping @Sendable (EgressService)throws->String) throws -> String {
        let report=collect(cancelled:cancelled,fetch:fetch)
        guard !report.cancelled else{throw fail("Periodic egress cancelled")}
        return try evaluate(report.samples.map(\.ip))
    }
}
