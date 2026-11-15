import Foundation
import Testing
import GuardCore
import GuardRuntime
@testable import GuardUIModel
@Suite @MainActor struct ChainModeTests {
    @Test func changingRouteOrPinnedEntryRevokesConfirmation() {
        let m=AppModel(autoPoll:false,preferences:nil)
        m.confirmation=true;m.settings.pathMode = .chain
        #expect(!m.confirmation)
        m.confirmation=true;m.settings.entryIPv4="1.2.3.4"
        #expect(!m.confirmation)
        #expect(m.networkPathSummary.contains("前置"))
        m.settings.pathMode = .direct
        #expect(!m.networkPathSummary.contains("前置"))
    }
}
