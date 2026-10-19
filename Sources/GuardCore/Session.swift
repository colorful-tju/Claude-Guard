import Foundation
public enum SessionPhase: String, Sendable, Codable { case off, checking, validating, armed, stopping, recoveryBlocked }
public enum SessionAction: String, Sendable, Codable { case none, collectPreflight, installProtection, runProbes, launchClaude, terminateClaude, removeOwnRules, releaseOwnReference }
/// Pure transition engine. Effects are commands to a future serialized privileged adapter.
/// No returned phase or command is evidence that the corresponding OS operation happened.
public struct SafetySession: Sendable, Codable {
    public private(set) var phase: SessionPhase = .off
    public private(set) var pendingAction: SessionAction = .none
    public private(set) var lastReason: String?
    private let policy: GuardPolicy
    private var preflightSnapshot: LocalSnapshot?
    private var installedSnapshot: LocalSnapshot?
    private var consumed = false
    private var installedAt: UInt64?
    private var validationRetries = 0
    public init(policy: GuardPolicy) { self.policy = policy }
    public init(recovering policy: GuardPolicy) { self.policy = policy; consumed = true; phase = .stopping; pendingAction = .terminateClaude }
    public mutating func begin() throws -> SessionAction {
        guard phase == .off, !consumed else { throw GuardFailure.invalidTransition("Create a new session before starting again") }
        consumed = true; phase = .checking; pendingAction = .collectPreflight
        return pendingAction
    }
    public mutating func preflightAccepted(_ snapshot: LocalSnapshot) throws -> SessionAction {
        guard phase == .checking, pendingAction == .collectPreflight else {
            throw GuardFailure.invalidTransition("Preflight out of order")
        }
        do { try SafetyGate.validatePreflight(snapshot, policy: policy) }
        catch { _ = stop(reason: String(describing: error)); throw error }
        preflightSnapshot = snapshot; pendingAction = .installProtection
        return pendingAction
    }
    public mutating func protectionInstalled(_ snapshot: LocalSnapshot, now: UInt64) throws -> SessionAction {
        guard phase == .checking, pendingAction == .installProtection else { throw GuardFailure.invalidTransition("Not checking") }
        do {
            try SafetyGate.validateLocal(snapshot, policy: policy)
            guard var before = preflightSnapshot else { throw GuardFailure.rejected("Missing preflight") }
            // Only installation-owned PF facts may change across installation.
            before.pfEnabled = snapshot.pfEnabled; before.ownReference = snapshot.ownReference
            before.rulesFingerprint = snapshot.rulesFingerprint; before.rulesAreStateless = snapshot.rulesAreStateless
            before.anchorReachable = snapshot.anchorReachable
            // PF is already installed and no probes have run yet. A routing-only
            // epoch advance may establish the first protected probe baseline.
            if before.differingFields(from:snapshot)==["epoch"],snapshot.epoch>before.epoch {before.epoch=snapshot.epoch}
            guard before == snapshot else { throw GuardFailure.rejected("Premises changed during PF installation") }
        }
        catch { _ = stop(reason: String(describing: error)); throw error }
        installedAt = now; installedSnapshot = snapshot; phase = .validating; pendingAction = .runProbes
        return pendingAction
    }
    /// Rebase only after validating the completed old probes against their own
    /// baseline. No result is relabelled: callers must run ALL probes again.
    public mutating func retryValidation(_ bundle:ValidationBundle,new snapshot:LocalSnapshot,now:UInt64) throws {
        guard phase == .validating,validationRetries==0,
              bundle.baseline==installedSnapshot,bundle.startedAt==installedAt else {
            throw GuardFailure.rejected("Startup validation retry unavailable")
        }
        try SafetyGate.validate(bundle,final:bundle.baseline,policy:policy,now:now)
        try SafetyGate.validateLocal(snapshot,policy:policy)
        guard bundle.baseline.differingFields(from:snapshot)==["epoch"],snapshot.epoch>bundle.baseline.epoch else {
            throw GuardFailure.rejected("Startup retry requires routing-only epoch change")
        }
        validationRetries=1;installedSnapshot=snapshot;installedAt=now
        pendingAction = .runProbes
    }
    public mutating func arm(_ bundle: ValidationBundle, final: LocalSnapshot, now: UInt64) throws -> SessionAction {
        guard phase == .validating else { throw GuardFailure.invalidTransition("Not validating") }
        do {
            guard bundle.baseline == installedSnapshot, bundle.startedAt == installedAt else { throw GuardFailure.rejected("Probe baseline replaced") }
            try SafetyGate.validate(bundle, final: final, policy: policy, now: now)
        } catch { _ = stop(reason: String(describing: error)); throw error }
        phase = .armed; pendingAction = .launchClaude
        return pendingAction
    }
    public mutating func stop(reason: String) -> SessionAction {
        lastReason = reason
        if phase == .off { return .none }
        phase = .stopping; pendingAction = .terminateClaude
        return pendingAction
    }
    public mutating func claudeExited(inventoryComplete: Bool, processes: [ProcessIdentity]) throws -> SessionAction {
        try requireRecovery(.terminateClaude)
        guard inventoryComplete, processes.isEmpty else { try blocked("Cannot confirm Claude and Helpers exited") }
        phase = .stopping; pendingAction = .removeOwnRules; return pendingAction
    }
    public mutating func rulesRemoved(rulesAbsent: Bool, stateInventoryComplete: Bool, states: [ExistingState]) throws -> SessionAction {
        try requireRecovery(.removeOwnRules)
        guard rulesAbsent, stateInventoryComplete else { try blocked("Rule/state inventory incomplete") }
        do { try StateClassifier.validate(states, policy: policy) }
        catch { try blocked("Cannot prove absence of residual session states") }
        phase = .stopping; pendingAction = .releaseOwnReference; return pendingAction
    }
    public mutating func referenceReleased(ownReferenceAbsent: Bool, foreignEnvironmentUnchanged: Bool) throws -> SessionAction {
        try requireRecovery(.releaseOwnReference)
        guard ownReferenceAbsent, foreignEnvironmentUnchanged else { try blocked("PF restoration not verified") }
        phase = .off; pendingAction = .none; installedSnapshot = nil; return pendingAction
    }
    private func requireRecovery(_ action: SessionAction) throws {
        guard (phase == .stopping || phase == .recoveryBlocked), pendingAction == action else {
            throw GuardFailure.invalidTransition("Recovery acknowledgement out of order")
        }
    }
    private mutating func blocked(_ reason: String) throws -> Never {
        phase = .recoveryBlocked; lastReason = reason
        throw GuardFailure.rejected(reason)
    }
}
