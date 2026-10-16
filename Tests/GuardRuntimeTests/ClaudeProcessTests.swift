import Testing
@testable import GuardRuntime

struct ClaudeProcessTests {
    private func row(_ pid:Int32,_ parent:Int32,_ path:String,_ name:String,uid:UInt32=501) -> ProcessRecord {
        .init(pid:pid,ppid:parent,uid:uid,started:100,path:path,name:name)
    }
    @Test func launcherAndItsCLIAreNotClaudeEvenWhenSpawnedByClaude() {
        let rows=[
            row(10,1,"/Applications/Claude.app/Contents/MacOS/Claude","Claude"),
            row(11,10,Paths.app+"/Contents/MacOS/ClaudeSafeLauncher","ClaudeSafeLaunc"),
            row(12,11,Paths.app+"/Contents/Resources/guardctl","guardctl"),
            row(13,11,"/usr/bin/python3","python3")
        ]
        #expect(Set(NativeProcesses.claude(rows,uid:501).map(\.pid)) == [10])
    }
    @Test func unrelatedClaudeNamePrefixesAreNotTerminationTargets() {
        let rows=[
            row(20,1,"/tmp/other","ClaudeGuard"),
            row(21,1,"/tmp/other","Claude Helperish"),
            row(22,1,"/tmp/ClaudeSafeLauncher.app/Contents/MacOS/ClaudeSafeLauncher","ClaudeSafeLaunc"),
            row(23,1,"/usr/bin/python3","python3")
        ]
        #expect(NativeProcesses.claude(rows,uid:501).isEmpty)
    }
    @Test func desktopHelpersAndDescendantsRemainTrackedForTheRegisteredUser() {
        let rows=[
            row(30,1,"/Applications/Claude.app/Contents/MacOS/Claude","Claude"),
            row(31,1,"/Applications/Claude.app/Contents/Frameworks/Claude Helper (GPU).app/Contents/MacOS/Claude Helper (GPU)","Claude Helper (G"),
            row(32,30,"/usr/bin/python3","python3"),
            row(33,32,"/bin/sh","sh"),
            row(34,1,"/Applications/Claude.app/Contents/MacOS/Claude","Claude",uid:502),
            row(35,30,"/bin/sh","sh",uid:0)
        ]
        #expect(Set(NativeProcesses.claude(rows,uid:501).map(\.pid)) == [30,31,32,33])
    }
    @Test func exactDesktopNameFallbackStillFindsRenamedBundle() {
        let rows=[row(40,1,"/Users/example/Apps/Renamed.app/Contents/MacOS/Claude","Claude"),
                  row(41,1,"/Users/example/Apps/Renamed.app/Contents/MacOS/Helper","Claude Helper (R")]
        #expect(Set(NativeProcesses.claude(rows,uid:501).map(\.pid)) == [40,41])
    }
}
