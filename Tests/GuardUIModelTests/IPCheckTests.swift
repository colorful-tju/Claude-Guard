import Testing
import Foundation
@testable import GuardUIModel

@Suite struct IPCheckTests {
    @Test func dualMatchIsNotProtectionProof() async {
        let result=await IPCheck.run(expected:"1.1.1.1",fetch:{_ in "1.1.1.1"})
        #expect(result.matches && result.samples.count==2)
        #expect(result.expected == "1.1.1.1")
    }
    @Test func partialFailureAndDisagreementNeverMatch() async {
        let partial=await IPCheck.run(expected:"1.1.1.1",fetch:{service in
            if service == .ipify {throw NSError(domain:"test",code:1)}
            return "1.1.1.1"
        })
        #expect(!partial.matches && partial.samples.contains{$0.ip.isEmpty})
        let disagree=await IPCheck.run(expected:"1.1.1.1",fetch:{$0 == .ipify ? "1.1.1.1":"8.8.8.8"})
        #expect(!disagree.matches)
    }
}
