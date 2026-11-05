import Foundation
import Testing
import GuardCore
@testable import GuardRuntime
struct ClaudeLaunchConfirmationTests {
    var main:ProcessRecord {.init(pid:42,ppid:1,uid:501,started:100,path:ClaudeLaunchConfirmation.mainPath,name:"Claude")}
    @Test func onlyCurrentStableMainQualifies() throws {
        let row=main
        let result=try ClaudeLaunchConfirmation.observe(uid:501,cancelled:{false},inventory:{.init(records:[row],issues:[])},reread:{_ in row},attempts:1,pause:{})
        #expect(result.identity==row.identity)
        for path in ["/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper","/tmp/Claude","/bin/claude"] {
            let other=ProcessRecord(pid:42,ppid:1,uid:501,started:100,path:path,name:"Claude")
            #expect(throws:(any Error).self){try ClaudeLaunchConfirmation.observe(uid:501,cancelled:{false},inventory:{.init(records:[other],issues:[])},reread:{_ in other},attempts:1,pause:{})}
        }
    }
    @Test func absenceReuseAndCancellationCannotAcknowledgeLaunch() {
        let row=main,reused=ProcessRecord(pid:42,ppid:1,uid:501,started:101,path:ClaudeLaunchConfirmation.mainPath,name:"Claude")
        #expect(throws:(any Error).self){try ClaudeLaunchConfirmation.observe(uid:501,cancelled:{false},inventory:{.init(records:[],issues:[])},attempts:1,pause:{})}
        #expect(throws:(any Error).self){try ClaudeLaunchConfirmation.observe(uid:501,cancelled:{false},inventory:{.init(records:[row],issues:[])},reread:{_ in reused},attempts:1,pause:{})}
        #expect(throws:(any Error).self){try ClaudeLaunchConfirmation.observe(uid:501,cancelled:{true},inventory:{.init(records:[row],issues:[])},reread:{_ in row},attempts:1,pause:{})}
    }
}
