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
    @Test func missingResultsRetryEveryFiveMinutesWithoutRefreshingProof() {
        var monitor=EgressMonitor(verifiedAt:100)
        for now:Double in [120,420,720,1020] {
            #expect(monitor.consume(report(nil,nil,finished:now),expected:"1.1.1.1",now:now) == .retry("services-unavailable"))
            #expect(monitor.nextCheckAt==now+300)
            #expect(monitor.lastVerifiedAt==100)
        }
        #expect(monitor.failures==4)
    }
    @Test func successfulRecoveryResetsCadenceAndMismatchStillStops() {
        var monitor=EgressMonitor(verifiedAt:100)
        _=monitor.consume(report(nil,nil,finished:120),expected:"1.1.1.1",now:120)
        #expect(monitor.consume(report("1.1.1.1",nil,finished:421),expected:"1.1.1.1",now:422) == .verified)
        #expect(monitor.failures==0 && monitor.lastVerifiedAt==421 && monitor.nextCheckAt==437)
        #expect(monitor.consume(report("8.8.8.8","1.1.1.1",finished:438),expected:"1.1.1.1",now:438) == .stop("Periodic egress mismatch"))
    }
    @Test func mismatchAfterLongOutageIsNotHiddenAsUnavailable() {
        var monitor=EgressMonitor(verifiedAt:100)
        _=monitor.consume(report(nil,nil,finished:120),expected:"1.1.1.1",now:120)
        #expect(monitor.consume(report(nil,"8.8.8.8",finished:1000),expected:"1.1.1.1",now:1000) == .stop("Periodic egress mismatch"))
    }
    @Test func staleResultNeverPretendsEgressIsFresh() {
        var monitor=EgressMonitor(verifiedAt:100)
        #expect(monitor.consume(report("1.1.1.1",nil,finished:200),expected:"1.1.1.1",now:220) == .retry("result-stale"))
        #expect(monitor.lastVerifiedAt==100 && monitor.nextCheckAt==520)
    }
    @Test func tlsDiagnosticKeepsKnownSignalsButNeverRawSecrets() {
        let raw="curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL connection reset by peer https://user:secret@private.example/token?key=SECRET\nPRIVATE RESPONSE"
        let result=ProbeExecutor.echoFailure(service:.ipify,status:35,stderr:raw)
        #expect(result=="HTTPS echo ipify curl exit=35 detail=connection-reset,ssl-error-syscall")
        #expect(ProbeExecutor.echoFailure(service:.webshare,status:35,stderr:"unknown secret body")=="HTTPS echo webshare curl exit=35 detail=unclassified")
        #expect(ProbeExecutor.echoFailure(service:.ipify,status:35,stderr:"unexpected EOF while reading").contains("unexpected-eof"))
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
