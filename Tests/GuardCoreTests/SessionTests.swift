import Foundation
import Testing
@testable import GuardCore

struct SessionTests {
    @Test func orderedStartAndRecovery() throws {
        let p = try fixturePolicy(); let b = fixtureBundle(p)
        var s = SafetySession(policy: p)
        #expect(try s.begin() == .collectPreflight)
        #expect(try s.preflightAccepted(b.baseline) == .installProtection)
        #expect(try s.protectionInstalled(b.baseline, now: 90) == .runProbes)
        #expect(try s.arm(b, final: b.baseline, now: 100) == .launchClaude)
        #expect(s.phase == .armed)
        #expect(s.stop(reason: "UI heartbeat lost") == .terminateClaude)
        #expect(s.phase == .stopping)
        #expect(try s.claudeExited(inventoryComplete: true, processes: []) == .removeOwnRules)
        #expect(try s.rulesRemoved(rulesAbsent: true, stateInventoryComplete: true, states: []) == .releaseOwnReference)
        #expect(try s.referenceReleased(ownReferenceAbsent: true, foreignEnvironmentUnchanged: true) == .none)
        #expect(s.phase == .off)
    }

    @Test func cannotSkipChecksOrReuseSession() throws {
        let p = try fixturePolicy(); let b = fixtureBundle(p); var s = SafetySession(policy: p)
        expectThrows(try s.arm(b, final: b.baseline, now: 100))
        expectThrows(try s.rulesRemoved(rulesAbsent: true, stateInventoryComplete: true, states: []))
        _ = try s.begin(); expectThrows(try s.begin())
        _ = try s.preflightAccepted(b.baseline)
        _ = try s.protectionInstalled(b.baseline, now: 90)
        var changed = b.baseline; changed.epoch += 1
        expectThrows(try s.arm(b, final: changed, now: 100))
        #expect(s.phase == .stopping)
        #expect(s.pendingAction == .terminateClaude)
    }

    @Test func uncertaintyKeepsProtectionAndBlocksRecovery() throws {
        let p = try fixturePolicy(); var s = SafetySession(policy: p)
        _ = try s.begin(); _ = s.stop(reason: "fault")
        expectThrows(try s.claudeExited(inventoryComplete: false, processes: []))
        #expect(s.phase == .recoveryBlocked)
        #expect(s.pendingAction == .terminateClaude)
        _ = try s.claudeExited(inventoryComplete: true, processes: [])
        var own = gatewayState(p); own.originatingSession = p.sessionID
        expectThrows(try s.rulesRemoved(rulesAbsent: true, stateInventoryComplete: true, states: [own]))
        #expect(s.phase == .recoveryBlocked)
        #expect(s.pendingAction == .removeOwnRules)
        _ = try s.rulesRemoved(rulesAbsent: true, stateInventoryComplete: true, states: [])
        expectThrows(try s.referenceReleased(ownReferenceAbsent: false, foreignEnvironmentUnchanged: true))
        #expect(s.phase == .recoveryBlocked)
        #expect(s.pendingAction == .releaseOwnReference)
    }

    @Test func daemonRestartNeverArmsOrLaunches() throws {
        var s = SafetySession(recovering: try fixturePolicy())
        #expect(s.phase == .stopping)
        #expect(s.pendingAction == .terminateClaude)
        expectThrows(try s.begin())
    }
    @Test func noInstallBeforePreflightAndNoBaselineSubstitution() throws {
        let p = try fixturePolicy(); let b = fixtureBundle(p); var s = SafetySession(policy: p)
        _ = try s.begin()
        expectThrows(try s.protectionInstalled(b.baseline, now: 90))
        _ = try s.preflightAccepted(b.baseline)
        var changed = b.baseline; changed.routeFingerprint = "changed"
        expectThrows(try s.protectionInstalled(changed, now: 90))
        #expect(s.pendingAction == .terminateClaude)
    }
    @Test func recoveredSessionCannotBeReusedAfterCleanup() throws {
        var s = SafetySession(recovering: try fixturePolicy())
        _ = try s.claudeExited(inventoryComplete: true, processes: [])
        _ = try s.rulesRemoved(rulesAbsent: true, stateInventoryComplete: true, states: [])
        _ = try s.referenceReleased(ownReferenceAbsent: true, foreignEnvironmentUnchanged: true)
        expectThrows(try s.begin())
    }
}
