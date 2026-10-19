import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

// These synchronous tests deliberately wait on GCD workers. Run the suite serially
// so test-runner concurrency does not consume the workers needed by its own deadlines.
@Suite(.serialized)
struct ProbeWorkerTests {
    @Test func offlineSelfTestUsesProductionSubprocessAndConcurrentPipeline() throws {
        let result=try ProbeWorker.selfTest()
        #expect(result.buildID==BuildIdentity.buildID && result.protocolVersion==BuildIdentity.protocolVersion)
        #expect(result.subprocess && result.concurrentResults==2 && !result.networkProbes)
    }
    @Test func concurrentEchoFailureCannotReturnPartialEvidence() {
        #expect(throws:(any Error).self){try ProbeWorker.collectEchoes(timeout:1){service in if service == .ipify{throw fail("fake error")};return "192.0.2.1"}}
    }
    @Test func startupFailureIdentifiesBothServiceOutcomesWithoutRawErrorText() {
        do {
            _=try ProbeWorker.collectEchoes(timeout:1){service in
                if service == .ipify {throw fail("secret-token=https://private.example")}
                return "192.0.2.1"
            }
            Issue.record("Expected startup rejection")
        }catch {
            let text=String(describing:error)
            #expect(text.contains("ipify") && text.contains("webshare"))
            #expect(text.contains("unknown-error") && text.contains("ok"))
            #expect(!text.contains("secret-token") && !text.contains("private.example"))
        }
    }
    @Test func startupCurlFailureSurvivesWorkerPayloadAndParentDecode() throws {
        do {
            _=try ProbeWorker.collectEchoes(timeout:1){service in
                if service == .ipify {
                    throw EchoRequestFailure(description:ProbeExecutor.echoFailure(service:service,status:35,stderr:"SSL_ERROR_SYSCALL https://secret.example/token"))
                }
                return "192.0.2.1"
            }
            Issue.record("Partial result must not pass startup")
        }catch let failure as StartupEchoFailure {
            let encoded=String(decoding:try JSONEncoder().encode(failure),as:UTF8.self)
            let summary=try #require(StartupEchoFailure.decodedSummary(encoded))
            #expect(summary.contains("curl exit=35 detail=ssl-error-syscall"))
            #expect(summary.contains("webshare[ok") && !summary.contains("secret.example"))
            #expect(failure.samples.allSatisfy{$0.elapsed>=0})
        }
        #expect(StartupEchoFailure.decodedSummary("not json")==nil)
        #expect(StartupEchoFailure.decodedSummary("{\"ipify\":{\"ipv4\":\"1.1.1.1\"}}")==nil)
    }
    @Test func deadlinePreservesPendingAndCompletedOutcomes() throws {
        do {
            _=try ProbeWorker.collectEchoes(timeout:0.05){service in
                if service == .webshare {Thread.sleep(forTimeInterval:0.2)}
                return "192.0.2.1"
            }
            Issue.record("Deadline must fail")
        }catch let failure as StartupEchoFailure {
            #expect(failure.deadlineExceeded)
            #expect(failure.samples.first(where:{$0.service == .webshare})?.outcome=="pending")
            #expect(failure.samples.count==2)
        }
        let error=CommandFailure(executable:"curl",stage:"deadline-exceeded",elapsed:10,stderrPrefix:"secret")
        #expect(StartupEchoFailure.safeOutcome(error)=="command-deadline-exceeded")
    }
    @Test func stalledEchoCollectionHasItsOwnBound() {
        let start=DispatchTime.now().uptimeNanoseconds
        #expect(throws:(any Error).self){try ProbeWorker.collectEchoes(timeout:0.02){_ in Thread.sleep(forTimeInterval:0.1);return "192.0.2.1"}}
        #expect(Double(DispatchTime.now().uptimeNanoseconds-start)/1e9<0.5)
    }
}

struct WorkerLeafTests {
    @Test func workerLeafChildrenInheritOuterManagedGroupAndOnlyFixedToolsAreAllowed() throws {
        let commands=Commands(workerLeafTools:true)
        #expect(try commands.checked("/usr/bin/printf",["leaf-ok"])=="leaf-ok")
        #expect(throws:(any Error).self){try commands.run("/bin/sh",["-c","exit 0"])}
        try commands.assertQuiescent()
    }
}
