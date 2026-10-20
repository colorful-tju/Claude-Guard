import Testing
import Foundation
import GuardRuntime
@testable import GuardUIModel

struct PublicEditionTests {
    @Test @MainActor func processReviewIsYellowWithoutClaimingPFStopped() {
        let m=AppModel(autoPoll:false,preferences:nil)
        m.state.phase="armed";m.state.verified=true;m.state.processInventoryComplete=false
        #expect(m.bannerTone == .waiting && m.bannerTitle.contains("进程信息复核"))
        #expect(m.state.verified)
    }

    @Test @MainActor func freshInstallContainsNoPersonalEndpoint() {
        let m=AppModel(autoPoll:false,preferences:nil)
        #expect(m.settings.gateway.isEmpty && m.settings.expectedEgress.isEmpty && m.settings.port==0)
        #expect(m.bannerTone == .waiting)
        m.state.phase="armed";m.state.processInventoryComplete=true;m.state.verified=false
        #expect(m.bannerTone != .protected)
        m.state.verified=true
        #expect(m.bannerTone == .protected)
        m.failure="runtime failure"
        #expect(m.bannerTone == .blocked)
    }
    @Test @MainActor func detectedIPOnlyFillsEgressNeverGatewayOrPort() async {
        let m=AppModel(autoPoll:false,preferences:nil)
        m.ipCheck=await IPCheck.run(expected:"",fetch:{_ in "1.1.1.1"})
        #expect(m.detectedEgress=="1.1.1.1")
        m.useDetectedEgress()
        #expect(m.settings.expectedEgress=="1.1.1.1" && m.settings.gateway.isEmpty && m.settings.port==0)
        #expect(!m.state.verified && !m.confirmation)
        m.ipStale=true
        #expect(m.detectedEgress==nil)
    }
    @Test @MainActor func newPreferenceNamespaceDoesNotImportPrivateDevelopmentSettings() throws {
        let name="guard-test-"+UUID().uuidString
        let defaults=UserDefaults(suiteName:name)!
        defer{defaults.removePersistentDomain(forName:name)}
        var privateSettings=Settings();privateSettings.gateway="1.1.1.1"
        defaults.set(try JSONEncoder().encode(privateSettings),forKey:"settings")
        defaults.set(true,forKey:"onboardingComplete")
        let m=AppModel(autoPoll:false,preferences:defaults)
        #expect(m.settings.gateway.isEmpty && !m.onboardingComplete)
    }
}

struct DetectAndFillTests {
 @Test @MainActor func agreesFillsOnlyEgress() async {
  let m=AppModel(autoPoll:false,preferences:nil)
  await m.testIP(fillEgress:true,fetch:{_ in "1.1.1.1"})?.value
  #expect(m.settings.expectedEgress=="1.1.1.1" && m.settings.gateway.isEmpty && m.settings.port==0)
  #expect(m.ipCheck?.matches==true && !m.ipStale && !m.state.verified && !m.confirmation)
 }
 @Test @MainActor func disagreementDoesNotOverwrite() async {
  let m=AppModel(autoPoll:false,preferences:nil);m.settings.expectedEgress="8.8.8.8"
  await m.testIP(fillEgress:true,fetch:{$0.rawValue=="ipify" ? "1.1.1.1":"9.9.9.9"})?.value
  #expect(m.settings.expectedEgress=="8.8.8.8" && !m.failure.isEmpty)
 }
 @Test @MainActor func editedConfigurationIsNotOverwritten() async {
  let m=AppModel(autoPoll:false,preferences:nil)
  let task=m.testIP(fillEgress:true,fetch:{_ in "1.1.1.1"})
  m.settings.expectedEgress="8.8.8.8"
  await task?.value
  #expect(m.settings.expectedEgress=="8.8.8.8" && m.ipStale)
 }
 @Test @MainActor func armedCannotAutoFill() {
  let m=AppModel(autoPoll:false,preferences:nil);m.state.phase="armed"
  #expect(m.testIP(fillEgress:true)==nil)
 }
}
