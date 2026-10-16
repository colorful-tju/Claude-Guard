import Foundation

/// Offline only; its launch budget is deliberately outside the protected probe freshness window.
public enum WorkerPreflight {
    public static func check(
        run:(String,[String],TimeInterval,@escaping @Sendable ()->Bool)throws->CommandResult,
        quiescent:()throws->Void,
        record:(String)throws->Void,
        cancelled:@escaping @Sendable ()->Bool
    ) throws -> String {
        guard !cancelled() else{throw fail("Offline worker preflight cancelled before launch")}
        try record("preflight-start stage=offline-worker deadline=8s; PF not installed")
        do {
            let result=try run(Paths.root+"/guard-probe",["--self-test"],8,cancelled)
            try record("preflight-worker-finish exit=\(result.status) diagnostics=\(result.error.prefix(2048))")
            guard result.status==0 else{throw fail("Offline worker self-test failed")}
            let test=try JSONDecoder().decode(WorkerSelfTest.self,from:Data(result.output.utf8))
            guard test.buildID==BuildIdentity.buildID,test.protocolVersion==BuildIdentity.protocolVersion,
                  test.subprocess,test.concurrentResults==2,!test.networkProbes else{throw fail("Worker build/self-test mismatch; reinstall matching components")}
            guard !cancelled() else{throw fail("Offline worker preflight cancelled")}
            try record("preflight-start stage=curl-version deadline=2s")
            let curl=try run("/usr/bin/curl",["-q","--version"],2,cancelled)
            guard curl.status==0 else{throw fail("curl offline version check failed")}
            try quiescent()
            try record("preflight-complete build=\(test.buildID); no network probes")
            return test.buildID
        }catch let error as CommandFailure {
            try record("preflight-error \(error) diagnostics=\(error.stderrPrefix.prefix(2048))")
            throw error
        }catch {
            try record("preflight-error validation=\(error)");throw error
        }
    }
}
