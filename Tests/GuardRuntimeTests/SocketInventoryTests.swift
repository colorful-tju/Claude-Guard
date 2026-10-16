import Testing
import GuardCore
import NativeGuard
@testable import GuardRuntime
struct SocketInventoryTests {
    let process=ProcessIdentity(pid:123,startTime:1,executableIdentity:"core")
    @Test func transientReadRetriesWholeInventory() throws {
        var calls=0,waits=0
        let result=try SocketInventoryCollector.collect(pid:123,identity:{_ in process},read:{_ in
            calls += 1
            if calls<3 {throw fail("descriptor closed")}
            return [CSGSocket()]
        },wait:{_ in waits += 1})
        #expect(result.count==1 && calls==3 && waits==2)
    }
    @Test func persistentFailureIsBoundedAndNeverReturnsPartialEvidence() {
        var calls=0
        reject{_ = try SocketInventoryCollector.collect(pid:123,identity:{_ in process},read:{_ in calls += 1;throw fail("permission denied")},wait:{_ in})}
        #expect(calls==3)
    }
    @Test func changedProcessCannotSupplyReplacementEvidence() {
        var identities=0,reads=0
        reject{_ = try SocketInventoryCollector.collect(pid:123,identity:{_ in
            identities += 1;var p=process;if identities>=3{p.startTime=2};return p
        },read:{_ in reads += 1;return []},wait:{_ in})}
        #expect(reads==1)
    }
}
