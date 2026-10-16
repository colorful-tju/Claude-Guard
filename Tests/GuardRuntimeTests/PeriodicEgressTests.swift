import Testing
@testable import GuardRuntime
struct PeriodicEgressTests {
    @Test func oneUnavailableServiceCanUseTheOtherButConflictsNeverPass() throws {
        #expect(try PeriodicEgress.evaluate([nil,"1.1.1.1"])=="1.1.1.1")
        #expect(try PeriodicEgress.evaluate(["1.1.1.1",nil])=="1.1.1.1")
        reject{_ = try PeriodicEgress.evaluate([nil,nil])}
        reject{_ = try PeriodicEgress.evaluate(["1.1.1.1","8.8.8.8"])}
        reject{_ = try PeriodicEgress.evaluate(["127.0.0.1",nil])}
        // A consistent but wrong egress is returned unchanged for Controller's expected-IP check.
        #expect(try PeriodicEgress.evaluate(["1.1.1.1",nil])=="1.1.1.1")
    }
    @Test func parallelCollectionUsesTheOtherServiceWithoutMaskingMismatch() throws {
        #expect(try PeriodicEgress.read(cancelled:{false},fetch:{service in
            if service == .ipify {throw fail("injected unavailable service")}
            return "1.1.1.1"
        })=="1.1.1.1")
        reject{_ = try PeriodicEgress.read(cancelled:{false},fetch:{$0 == .ipify ? "1.1.1.1":"8.8.8.8"})}
    }
    @Test func cancellationCannotReturnFreshEvidence() {
        reject{_ = try PeriodicEgress.read(cancelled:{true},fetch:{_ in "1.1.1.1"})}
    }
}
