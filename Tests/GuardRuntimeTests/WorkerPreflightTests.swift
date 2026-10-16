import Foundation
import Testing
@testable import GuardRuntime

@Suite struct WorkerPreflightTests {
    @Test func clientDeadlineContainsTheWholeOfflineTransaction() {
        #expect(Wire.responseTimeout(for:.selfTest)>10)
        #expect(Wire.responseTimeout(for:.selfTest)<=20)
        #expect(Wire.responseTimeout(for:.progress)==8)
    }

    @Test func startupBudgetAndDiagnosticsAreSeparateFromNetworkProbeBudget() throws {
        let seen=PreflightCapture()
        let result=try WorkerPreflight.check(run:{path,args,timeout,cancelled in
            seen.budgets.append(timeout)
            if args == ["--self-test"] {
                #expect(timeout>=8 && timeout<=12)
                let test=WorkerSelfTest(buildID:BuildIdentity.buildID,protocolVersion:BuildIdentity.protocolVersion,subprocess:true,concurrentResults:2,networkProbes:false)
                return .init(output:String(decoding:try JSONEncoder().encode(test),as:UTF8.self),error:"worker-enter\nself-test-stage=complete",status:0)
            }
            return .init(output:"curl offline version",error:"",status:0)
        },quiescent:{seen.quiet=true},record:{seen.logs.append($0)},cancelled:{false})
        #expect(result==BuildIdentity.buildID && seen.quiet)
        #expect(seen.logs.joined().contains("self-test-stage=complete"))
    }
    @Test func cancellationAndInvalidEvidenceNeverPass() throws {
        #expect(throws:(any Error).self){try WorkerPreflight.check(run:{_,_,_,_ in Issue.record("must not spawn");throw fail("unexpected")},quiescent:{},record:{_ in},cancelled:{true})}
        #expect(throws:(any Error).self){try WorkerPreflight.check(run:{_,_,_,_ in .init(output:"{}",error:"",status:0)},quiescent:{},record:{_ in},cancelled:{false})}
    }
    @Test func deadlineRetainsStageAndBoundedWorkerDiagnostics() throws {
        let seen=PreflightCapture()
        #expect(throws:(any Error).self){try WorkerPreflight.check(run:{_,_,_,_ in
            throw CommandFailure(executable:"guard-probe",stage:"deadline-exceeded",elapsed:8,stderrPrefix:"self-test-stage=subprocess-start")
        },quiescent:{},record:{seen.logs.append($0)},cancelled:{false})}
        #expect(seen.logs.joined().contains("self-test-stage=subprocess-start"))
        #expect(!seen.logs.joined().contains("preflight-complete"))
    }
}
private final class PreflightCapture:@unchecked Sendable {var logs:[String]=[],budgets:[TimeInterval]=[];var quiet=false}
