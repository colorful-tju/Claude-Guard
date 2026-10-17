import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

struct EgressMonitorTests {
    func report(_ a:String?,_ b:String?,finished:Double=120)->EgressReport {
        .init(startedAt:finished-1,finishedAt:finished,samples:[
            .init(service:.ipify,ip:a,error:a == nil ? "curl exit=28":"",elapsed:1,completedAt:finished),
            .init(service:.webshare,ip:b,error:b == nil ? "curl exit=35":"",elapsed:1,completedAt:finished)])
    }
    @Test func staleCorrectAnswerRetriesWithoutRefreshingProofAge() {
        var monitor=EgressMonitor(verifiedAt:100)
        #expect(monitor.consume(report("1.1.1.1","1.1.1.1",finished:112),expected:"1.1.1.1",now:124) == .retry("result-stale"))
        #expect(monitor.lastVerifiedAt==100 && monitor.failures==1)
        #expect(monitor.consume(report("1.1.1.1",nil,finished:127),expected:"1.1.1.1",now:128) == .verified)
        #expect(monitor.lastVerifiedAt==127 && monitor.failures==0)
    }
    @Test func fourSecondQueueDelayDoesNotInvalidateRecentMatchingSamples() {
        var monitor=EgressMonitor(verifiedAt:100)
        #expect(monitor.consume(report("1.1.1.1","1.1.1.1"),expected:"1.1.1.1",now:124) == .verified)
        #expect(monitor.lastVerifiedAt==120) // Never advance proof time to callback time.
    }
    @Test func mismatchAlwaysStopsEvenWhenOtherServiceMatchesOrResultIsStale() {
        for b in [nil,"1.1.1.1","8.8.8.8"] {
            var monitor=EgressMonitor(verifiedAt:100)
            #expect(monitor.consume(report("8.8.8.8",b),expected:"1.1.1.1",now:124) == .stop("Periodic egress mismatch"))
        }
    }
    @Test func retryBudgetAndAbsoluteProofDeadlineCannotBeExtended() {
        var monitor=EgressMonitor(verifiedAt:100)
        #expect(monitor.consume(report(nil,nil,finished:116),expected:"1.1.1.1",now:116) == .retry("services-unavailable"))
        #expect(monitor.consume(report(nil,nil,finished:128),expected:"1.1.1.1",now:128) == .retry("services-unavailable"))
        #expect(monitor.consume(report(nil,nil,finished:140),expected:"1.1.1.1",now:140) == .stop("Periodic egress retry limit: services-unavailable"))
        var deadline=EgressMonitor(verifiedAt:100)
        #expect(deadline.expired(at:145))
        #expect(deadline.consume(report("1.1.1.1","1.1.1.1",finished:144),expected:"1.1.1.1",now:145) == .stop("Periodic egress proof expired"))
    }
    @Test func incompleteDuplicateCancelledOrFutureEvidenceNeverVerifies() {
        let good=report("1.1.1.1","1.1.1.1")
        var duplicate=good;duplicate.samples[1].service = .ipify
        var missing=good;missing.samples.removeLast()
        var future=good;future.samples[0].completedAt=200
        var cancelled=good;cancelled.cancelled=true
        for report in [duplicate,missing,future,cancelled] {
            var monitor=EgressMonitor(verifiedAt:100)
            #expect(monitor.consume(report,expected:"1.1.1.1",now:121) != .verified)
        }
    }
    @Test func collectorRetainsServiceErrorAndSuccessfulResult() {
        let r=PeriodicEgress.collect(cancelled:{false},fetch:{service in
            if service == .ipify {throw fail("curl exit=28 timeout")};return "1.1.1.1"
        })
        #expect(r.samples.count==2 && r.samples[0].error.contains("exit=28"))
        #expect(r.samples[1].ip=="1.1.1.1" && r.samples[1].error.isEmpty)
        #expect(r.finishedAt>=r.startedAt && r.samples.allSatisfy{$0.elapsed>=0})
    }
}
