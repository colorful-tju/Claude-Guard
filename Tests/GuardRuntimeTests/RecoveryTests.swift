import Testing
@testable import GuardRuntime
struct RecoveryTests {
    @Test func rebootedJournalNeverReleasesOldOrCollidingToken() throws {
        #expect(try RecoverySafety.bootDecision(recorded:"00000000-0000-0000-0000-000000000001",current:"00000000-0000-0000-0000-000000000001",anchorEmpty:false,oldTokenPresent:true) == .sameBoot)
        #expect(try RecoverySafety.bootDecision(recorded:"00000000-0000-0000-0000-000000000001",current:"00000000-0000-0000-0000-000000000002",anchorEmpty:true,oldTokenPresent:false) == .clearRebootedSession)
        reject{_ = try RecoverySafety.bootDecision(recorded:"00000000-0000-0000-0000-000000000001",current:"00000000-0000-0000-0000-000000000002",anchorEmpty:true,oldTokenPresent:true)}
        reject{_ = try RecoverySafety.bootDecision(recorded:"00000000-0000-0000-0000-000000000001",current:"00000000-0000-0000-0000-000000000002",anchorEmpty:false,oldTokenPresent:false)}
        reject{_ = try RecoverySafety.bootDecision(recorded:"unknown-boot",current:"unknown-boot",anchorEmpty:true,oldTokenPresent:false)}
    }
    @Test func communicationFailureCannotDisplayVerifiedArmed() {
        var s=Status();s.phase="armed";s.verified=true;s.udp="ON";s.ipcUnavailable()
        #expect(!s.verified);#expect(s.phase=="unverified");#expect(s.udp != "ON")
    }
}
