import Foundation
import Testing
import GuardCore
@testable import GuardRuntime
struct InventoryReviewTests {
    var failed:ProcessInventory {.init(records:[],issues:["unreadable"],rechecked:2,failures:[.init(pid:42,stage:"bsd",rc:-1,errnoCode:3)])}
    @Test func recoveryRecordsIdentityAndResetsWindow() {
        var review=InventoryReview()
        let tracked=ProcessIdentity(pid:42,startTime:100,executableIdentity:"/bin/test")
        #expect(review.observe(failed,now:10,tracked:[tracked]).event?.contains("pending")==true)
        let row=ProcessRecord(pid:42,ppid:1,uid:501,started:200,path:"/bin/test",name:"test")
        let result=review.observe(.init(records:[row],issues:[]),now:14,tracked:[])
        #expect(!result.expired && result.event?.contains("pid-reused")==true)
        #expect(review.observe(failed,now:100,tracked:[]).expired==false)
    }
    @Test func timeoutAndClockFailuresAreBounded() {
        var review=InventoryReview()
        _=review.observe(failed,now:10,tracked:[])
        #expect(!review.observe(failed,now:14.99,tracked:[]).expired)
        #expect(review.observe(failed,now:15,tracked:[]).expired)
        #expect(review.observe(failed,now:9,tracked:[]).expired)
    }
    @Test func absentRecoveryRequiresCompleteInventory() {
        var review=InventoryReview()
        _=review.observe(failed,now:10,tracked:[])
        let result=review.observe(.init(records:[],issues:[]),now:11,tracked:[])
        #expect(result.event?.contains("absent-in-complete-inventory")==true)
        #expect(result.event?.contains("nativeRechecks")==true)
    }
    @Test func incompleteExceptionIsTypedAndCarriesNativeFields() {
        do {_=try failed.requireComplete();Issue.record("must reject")}
        catch let error as IncompleteProcessInventory {#expect(error.failures.first?.errnoCode==3)}
        catch {Issue.record("wrong error type")}
    }
}
