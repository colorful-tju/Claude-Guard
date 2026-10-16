import Foundation
import Testing
import GuardRuntime
@testable import GuardUIModel
struct PreferencesTests {
    @Test @MainActor func editsPersistWithoutRPCButConsentAndArmedDoNotPersist() {
        let name="guard-test-"+UUID().uuidString
        let defaults=UserDefaults(suiteName:name)!
        defer{defaults.removePersistentDomain(forName:name)}
        let a=AppModel(autoPoll:false,preferences:defaults)
        a.settings.gateway="23.20.10.8";a.settings.port=3128;a.confirmation=true;a.completeOnboarding()
        a.settings.expectedEgress="1.1.1.1"
        #expect(!a.confirmation)
        let b=AppModel(autoPoll:false,preferences:defaults)
        #expect(b.settings.gateway=="23.20.10.8" && b.settings.port==3128 && b.onboardingComplete)
        #expect(!b.confirmation && !b.state.verified && b.state.phase=="off")
    }
    @Test @MainActor func quitRequiresRestoredOFFAndFreshPreviewIsInformationalOnly() async throws {
        let model=AppModel(autoPoll:false,preferences:nil,ipv6Reader:{.init(hasDefaultRoute:true)})
        #expect(model.readyToQuit)
        model.state.ipv6Override="临时 Off";#expect(!model.readyToQuit)
        model.state.ipv6Override="未临时修改";model.state.phase="recoveryBlocked";#expect(!model.readyToQuit)
        model.refreshIPv6()
        for _ in 0..<100 where model.ipv6Preview==nil {try await Task.sleep(for:.milliseconds(2))}
        #expect(model.needsIPv6Off && !model.state.verified)
    }
    @Test @MainActor func onlyFreshPositiveIPv6EvidenceBlocksLaunchAndMenuNeverFakesSafety() {
        let model=AppModel(autoPoll:false,preferences:nil)
        model.ipv6Preview = .init(hasDefaultRoute:true)
        #expect(model.needsIPv6Off && model.request(.start)==nil)
        #expect(model.failure.contains("IPv6"))
        model.ipv6Preview = .init(hasDefaultRoute:false)
        #expect(!model.needsIPv6Off && model.ipv6ReadinessText.contains("非全局禁用"))
        model.ipv6Preview = .init(hasDefaultRoute:true,checkedAt:Date(timeIntervalSinceNow:-30))
        #expect(!model.needsIPv6Off && model.ipv6ReadinessText=="IPv6 待检查")
        model.state.phase="armed";model.state.verified=false
        #expect(model.menuStatus != "已防护")
    }
}
