import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

struct ProbeWorkerTests {
    @Test func offlineSelfTestUsesProductionSubprocessAndConcurrentPipeline() throws {
        let result=try ProbeWorker.selfTest()
        #expect(result.buildID==BuildIdentity.buildID && result.protocolVersion==BuildIdentity.protocolVersion)
        #expect(result.subprocess && result.concurrentResults==2 && !result.networkProbes)
    }
    @Test func concurrentEchoFailureCannotReturnPartialEvidence() {
        #expect(throws:(any Error).self){try ProbeWorker.collectEchoes(timeout:1){service in if service == .ipify{throw fail("fake error")};return "192.0.2.1"}}
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
