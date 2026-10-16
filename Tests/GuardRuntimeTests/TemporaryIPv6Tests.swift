import Testing
import Foundation
@testable import GuardRuntime

@Suite struct TemporaryIPv6Tests {
    @Test func restoresOriginalAndRejectsForeignChanges() throws {
        let box=IPv6Fixture()
        let manager=TemporaryIPv6(store:box.store,backend:box.backend)
        try manager.set(.off,interface:"en0")
        #expect(box.saved?.original == box.original)
        #expect(box.current.method == "Off")
        try manager.verifyStable()
        try manager.set(.automatic,interface:"en0")
        #expect(box.saved?.original == box.original)
        try manager.restore()
        #expect(box.current == box.original && box.saved == nil)
        try manager.set(.off,interface:"en0")
        box.current = try .init(serviceID:"wifi",interface:"en0",enabled:true,configuration:["ConfigMethod":"LinkLocal"])
        #expect(throws:(any Error).self){try manager.verifyStable()}
        #expect(throws:(any Error).self){try manager.restore()}
        #expect(box.saved != nil)
    }
    @Test func malformedSavedPlistCannotOverwriteSystemPreferences() throws {
        let box=IPv6Fixture()
        let manager=TemporaryIPv6(store:box.store,backend:box.backend)
        try manager.set(.off,interface:"en0")
        let valid=try JSONEncoder().encode(box.saved!)
        var object=try JSONSerialization.jsonObject(with:valid) as! [String:Any]
        var original=object["original"] as! [String:Any];original["plist"]=Data("invalid".utf8).base64EncodedString();object["original"]=original
        box.saved=try JSONDecoder().decode(IPv6Override.self,from:JSONSerialization.data(withJSONObject:object))
        let before=box.current
        #expect(throws:(any Error).self){try manager.restore()}
        #expect(box.current==before && box.saved != nil)
    }
    @Test func interruptedRestoreAfterUncommittedCompletionRemainsRetryable() throws {
        let box=IPv6Fixture()
        let store=IPv6Store(read:{box.saved},write:{record in
            if record.pending==nil {throw fail("completion save interrupted")};box.saved=record
        },remove:{box.saved=nil})
        #expect(throws:(any Error).self){try TemporaryIPv6(store:store,backend:box.backend).set(.off,interface:"en0")}
        let recovering=TemporaryIPv6(store:box.store,backend:box.backend)
        box.failApply=true
        #expect(throws:(any Error).self){try recovering.restore()}
        box.failApply=false
        // Model daemon restart after the failed restore; use only durable record, not object memory.
        try TemporaryIPv6(store:box.store,backend:box.backend).restore()
        #expect(box.saved==nil && box.current==box.original)
    }
    @Test func recoveryAfterCommitBeforeFinalJournalWrite() throws {
        let box=IPv6Fixture()
        let store=IPv6Store(read:{box.saved},write:{record in
            if record.pending==nil {throw fail("final journal write failed")};box.saved=record
        },remove:{box.saved=nil})
        let first=TemporaryIPv6(store:store,backend:box.backend)
        #expect(throws:(any Error).self){try first.set(.off,interface:"en0")}
        #expect(box.current.enabled==false && box.saved?.pending != nil)
        try TemporaryIPv6(store:box.store,backend:box.backend).restore()
        #expect(box.current==box.original && box.saved==nil)
    }
    @Test func failureToSaveOriginalCannotModifyPreferences() throws {
        let box=IPv6Fixture()
        let store=IPv6Store(read:{nil},write:{_ in throw fail("disk full")},remove:{})
        #expect(throws:(any Error).self){try TemporaryIPv6(store:store,backend:box.backend).set(.off,interface:"en0")}
        #expect(box.current==box.original)
    }
    @Test func intentSurvivesFailedApplyAndDifferentInterfaceRejected() throws {
        let box=IPv6Fixture()
        let live=TemporaryIPv6(store:box.store,backend:box.backend)
        box.failApply=true
        #expect(throws:(any Error).self){try live.set(.off,interface:"en0")}
        #expect(box.saved != nil)
        box.failApply=false
        try live.restore()
        #expect(box.saved == nil)
        try live.set(.off,interface:"en0")
        #expect(throws:(any Error).self){try live.set(.automatic,interface:"en1")}
    }
}
final class IPv6Fixture:@unchecked Sendable {
    let original=try! IPv6Configuration(serviceID:"wifi",interface:"en0",enabled:true,configuration:["ConfigMethod":"Manual","Addresses":["2001:db8::2"],"PrefixLength":[64]])
    var current:IPv6Configuration;var saved:IPv6Override?;var failApply=false
    init(){current=original}
    var store:IPv6Store{.init(read:{self.saved},write:{self.saved=$0},remove:{self.saved=nil})}
    var backend:IPv6Backend{.init(read:{_ in self.current},compareAndApply:{expected,target in
        guard self.current==expected else{throw fail("changed")}
        if self.failApply{throw fail("apply failed")};self.current=target
    })}
}
