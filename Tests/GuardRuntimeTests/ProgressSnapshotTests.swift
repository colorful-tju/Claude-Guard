import Testing
@testable import GuardRuntime
@Suite struct ProgressSnapshotTests {
    @Test func progressCannotAssertProtectionAndKeepsOnlyBoundedText() {
        let progress=ProgressSnapshot()
        progress.update(message:String(repeating:"x",count:10000),report:String(repeating:"y",count:50000))
        let snapshot=progress.read()
        #expect(snapshot.phase=="progressOnly" && !snapshot.verified)
        #expect(snapshot.message.count==4096 && snapshot.report.count==32768)
    }
}
