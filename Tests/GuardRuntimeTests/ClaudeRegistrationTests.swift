import Foundation
import Testing
@testable import GuardRuntime
struct ClaudeRegistrationTests {
    @Test func officialCheckAndStableHashRequired() throws {
        var checked=false
        let value=try ClaudeRegistration.validate(readHash:{"hash"},verifyOfficial:{checked=true},checkUnchanged:{})
        #expect(value=="hash" && checked)
        #expect(throws:(any Error).self){try ClaudeRegistration.validate(readHash:{"hash"},verifyOfficial:{throw fail("wrong developer")},checkUnchanged:{})}
        var reads=0
        #expect(throws:(any Error).self){try ClaudeRegistration.validate(readHash:{reads += 1;return reads==1 ? "old":"new"},verifyOfficial:{},checkUnchanged:{})}
        #expect(throws:(any Error).self){try ClaudeRegistration.validate(readHash:{"hash"},verifyOfficial:{},checkUnchanged:{throw fail("app replaced")})}
    }
    @Test func fixedOfficialRequirementCannotComeFromUI() {
        #expect(ClaudeRegistration.appPath=="/Applications/Claude.app")
        #expect(ClaudeRegistration.requirement.contains("anchor apple generic"))
        #expect(ClaudeRegistration.requirement.contains("Q6L2SF6YDW"))
        #expect(ClaudeRegistration.requirement.contains("com.anthropic.claudefordesktop"))
        #expect(Wire.responseTimeout(for:.refreshClaudeRegistration)>20)
    }
}

struct ClaudeSignatureIntegrationTests {
    @Test func localOfficialSignatureReadOnlyWhenExplicitlyRequested() throws {
        guard ProcessInfo.processInfo.environment["CSG_VERIFY_LOCAL_CLAUDE"]=="1" else{return}
        let value=try ClaudeRegistration.verifiedHash(commands:Commands(),cancelled:{false})
        #expect(!value.isEmpty)
        let wrong=try Commands().run("/usr/bin/codesign",["--verify","--strict","-R","="+ClaudeRegistration.requirement,"/bin/echo"],timeout:20)
        #expect(wrong.status != 0)
    }
}
