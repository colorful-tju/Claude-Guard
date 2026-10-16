import Foundation
import Darwin
import Testing
import GuardCore
@testable import GuardRuntime

@Suite struct ProcessLifecycleTests {
    func row(_ pid:Int32=10,parent:Int32=1,started:UInt64=100,path:String="/Applications/Claude.app/Contents/MacOS/Claude",name:String="Claude",uid:UInt32=501)->ProcessRecord {
        .init(pid:pid,ppid:parent,uid:uid,started:started,path:path,name:name)
    }
    @Test func transientClaudeCodeReadRetriesWithoutLosingIdentity() {
        var reads=0,waits=0
        let code=row(path:"/Users/test/Library/Application Support/Claude/claude-code/2.x/claude.app/Contents/MacOS/claude",name:"claude")
        let result=ProcessInventoryCollector.collect(ids:[10],read:{_ in
            reads += 1;if reads<3{throw fail("libproc ESRCH transient")};return code
        },inactive:{_,_ in false},wait:{_ in waits += 1})
        #expect(result.complete && result.records.first?.identity==code.identity)
        #expect(result.rechecked==2 && result.recovered==1 && waits==2)
    }
    @Test func rawESRCHAndPermissionFailureAreNeverTreatedAsAbsence() {
        for reason in ["ESRCH not corroborated","EPERM"] {
            var reads=0
            let result=ProcessInventoryCollector.collect(ids:[10],read:{_ in reads += 1;throw fail(reason)},inactive:{_,_ in false},wait:{_ in})
            #expect(!result.complete && result.records.isEmpty && reads==3)
            #expect(result.issues.first?.contains(reason)==true)
        }
    }
    @Test func independentlyConfirmedExitCanDisappearDuringRetry() {
        var confirmations=0
        let result=ProcessInventoryCollector.collect(ids:[10],read:{_ in throw fail("exiting")},inactive:{_,_ in confirmations += 1;return confirmations==2},wait:{_ in})
        #expect(result.complete && result.records.isEmpty && result.recovered==1)
    }
    @Test func manyUnreadableProcessesDoNotCreateRetryStorm() {
        var reads=0,waits=0
        let result=ProcessInventoryCollector.collect(ids:Array(1...100),read:{_ in reads += 1;throw fail("permission")},inactive:{_,_ in false},wait:{_ in waits += 1})
        #expect(!result.complete && reads==100 && waits==0 && result.issues.count==9)
    }
    @Test func codeExecAndReparentedToolsStayTrackedButReusedPIDsDoNot() {
        let code=row(10,path:"/Users/test/Library/Application Support/Claude/claude-code/2.x/claude.app/Contents/MacOS/claude",name:"claude")
        let shell=row(11,parent:10,path:"/bin/zsh",name:"zsh")
        let first=NativeProcesses.claude([code,shell],uid:501)
        #expect(first.count==2)
        let tool=row(11,parent:1,path:"/usr/bin/python3",name:"python3")
        #expect(NativeProcesses.claude([tool],uid:501,known:first.map(\.identity)).map(\.pid)==[11])
        #expect(NativeProcesses.claude([row(11,started:200,path:"/usr/bin/python3",name:"python3")],uid:501,known:first.map(\.identity)).isEmpty)
        #expect(NativeProcesses.claude([row(11,path:"/usr/bin/python3",name:"python3",uid:502)],uid:501,known:first.map(\.identity)).isEmpty)
    }
    @Test func partialInventoryStillSignalsVerifiedTargetsButCannotProveOFF() {
        var signals:[Int32]=[]
        reject {
            try ClaudeTermination.run(uid:501,known:[],inventory:{.init(records:[row()],issues:["other pid unreadable"])},read:{_ in row()},inactive:{_,_ in false},send:{pid,_ in signals.append(pid)},wait:{_ in})
        }
        #expect(signals==[10,10])
    }
    @Test func oneUnreadableTargetDoesNotBlockOtherTargetsAndStillRejectsIncompleteExit() {
        let a=row(10),b=row(11)
        var signals:[Int32]=[]
        reject {
            try ClaudeTermination.run(uid:501,known:[a.identity,b.identity],inventory:{.init(records:[a,b],issues:[])},read:{pid in if pid==10{throw fail("unreadable")};return b},inactive:{_,_ in false},send:{pid,_ in signals.append(pid)},wait:{_ in})
        }
        #expect(signals==[11,11])
    }
    @Test func recoveredInventoryAllowsExitProofAfterKnownTargetsAreTerminated() throws {
        let a=row();var stopped=false,signals:[Int32]=[]
        try ClaudeTermination.run(uid:501,known:[a.identity],inventory:{stopped ? .init(records:[],issues:[]):.init(records:[a],issues:["transient"])},read:{_ in if stopped{throw fail("gone")};return a},inactive:{_,_ in stopped},send:{pid,_ in signals.append(pid);stopped=true},wait:{_ in})
        #expect(signals==[10])
    }
    @Test func reusedPIDNeverReceivesSignalFromHistoricalIdentity() throws {
        let old=row(),replacement=row(started:200,path:"/usr/bin/python3",name:"python3")
        var signals=0
        try ClaudeTermination.run(uid:501,known:[old.identity],inventory:{.init(records:[replacement],issues:[])},read:{_ in replacement},inactive:{_,_ in false},send:{_,_ in signals += 1},wait:{_ in})
        #expect(signals==0)
    }
    @Test func signalPermissionFailureLeavesSurvivorsAndRejectsOFF() {
        reject {try ClaudeTermination.run(uid:501,known:[],inventory:{.init(records:[row()],issues:[])},read:{_ in row()},inactive:{_,_ in false},send:{_,_ in throw fail("EPERM")},wait:{_ in})}
    }
}
