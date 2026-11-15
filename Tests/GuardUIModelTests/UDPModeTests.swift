import Testing
import Foundation
import GuardRuntime
@testable import GuardUIModel
@Suite @MainActor struct UDPModeTests {
    @Test func activeUDPIsNotBlockedByUnknownClaudeOrIPv6() {
        let m=AppModel(autoPoll:false,preferences:nil)
        m.state.phase="armed";m.state.protectionMode = .udpOnly;m.state.verified=true
        m.state.processInventoryComplete=false;m.state.claudeKnown=false
        #expect(m.bannerTitle=="仅 UDP 防护已开启")
        #expect(m.menuStatus=="仅 UDP")
        #expect(m.guidance.action.contains("不管理 Claude"))
        #expect(m.request(.start)==nil)
        #expect(m.request(.udpStart)==nil)
    }
}
