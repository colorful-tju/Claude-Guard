import Foundation

public struct ProcessIdentity: Equatable, Hashable, Sendable, Codable {
    public var pid: Int32
    public var startTime: UInt64
    public var executableIdentity: String
    public init(pid: Int32, startTime: UInt64, executableIdentity: String) {
        self.pid = pid; self.startTime = startTime; self.executableIdentity = executableIdentity
    }
}

public struct CoreConnection: Equatable, Sendable, Codable {
    public var owner: ProcessIdentity
    public var gateway: String
    public var port: UInt16
    public var localAddress: String
    public var localPort: UInt16
    public var established: Bool
    public init(owner: ProcessIdentity, gateway: String, port: UInt16, localAddress: String,
                localPort: UInt16, established: Bool) {
        self.owner = owner; self.gateway = gateway; self.port = port
        self.localAddress = localAddress; self.localPort = localPort; self.established = established
    }
}

/// Normalized state, produced by a version-checked collector in a later phase.
/// A nil interface means floating/unknown, NOT permission to guess an interface.
public struct ExistingState: Equatable, Sendable, Codable {
    public var id: String
    public var boundInterface: String?
    public var family: AddressFamily
    public var transport: Transport
    public var localAddress: String
    public var remoteAddress: String
    public var localPort: UInt16
    public var remotePort: UInt16
    public var originatingSession: UUID?
    public var parserRecognized: Bool

    public init(id: String, boundInterface: String?, family: AddressFamily = .ipv4,
                transport: Transport = .tcp, localAddress: String, remoteAddress: String,
                localPort: UInt16, remotePort: UInt16, originatingSession: UUID? = nil,
                parserRecognized: Bool = true) {
        self.id = id; self.boundInterface = boundInterface; self.family = family; self.transport = transport
        self.localAddress = localAddress; self.remoteAddress = remoteAddress
        self.localPort = localPort; self.remotePort = remotePort
        self.originatingSession = originatingSession; self.parserRecognized = parserRecognized
    }
}

public enum StateClassifier {
    public static func validate(_ states: [ExistingState], policy: GuardPolicy) throws {
        var ids = Set<String>()
        for state in states {
            guard state.parserRecognized, !state.id.isEmpty, ids.insert(state.id).inserted,
                  state.originatingSession == nil, let interface = state.boundInterface else {
                throw GuardFailure.rejected("Unknown, floating, duplicate or session-created PF state")
            }
            // Only the narrowly provable existing gateway path is retained in MVP.
            guard interface == policy.physical.name, state.family == .ipv4,
                  state.transport == .tcp, state.localAddress == policy.physical.ipv4,
                  state.remoteAddress == policy.endpoint.gateway,
                  state.remotePort == policy.endpoint.port, state.localPort > 0 else {
                throw GuardFailure.rejected("Existing PF state is outside the verified gateway path")
            }
        }
    }
}

public struct LocalSnapshot: Equatable, Sendable, Codable {
    public func differingFields(from other:LocalSnapshot) -> [String] {
        var fields:[String]=[]
        func check<T:Equatable>(_ name:String,_ left:T,_ right:T){if left != right{fields.append(name)}}
        check("epoch",epoch,other.epoch);check("interfaces",interfaces,other.interfaces)
        check("routeFingerprint",routeFingerprint,other.routeFingerprint)
        check("configurationFingerprint",configurationFingerprint,other.configurationFingerprint)
        check("nodeName",nodeName,other.nodeName);check("gateway",gateway,other.gateway)
        check("gatewayPort",gatewayPort,other.gatewayPort);check("protocolName",protocolName,other.protocolName)
        check("flclashRunning",flclashRunning,other.flclashRunning)
        check("coreIdentityVerified",coreIdentityVerified,other.coreIdentityVerified);check("core",core,other.core)
        check("connection",connection,other.connection);check("verifiedTun",verifiedTun,other.verifiedTun)
        check("tunRuntimeVerified",tunRuntimeVerified,other.tunRuntimeVerified);check("pfEnabled",pfEnabled,other.pfEnabled)
        check("ownReference",ownReference,other.ownReference);check("rulesFingerprint",rulesFingerprint,other.rulesFingerprint)
        check("mainRulesFingerprint",mainRulesFingerprint,other.mainRulesFingerprint)
        check("pfEnvironmentCompatible",pfEnvironmentCompatible,other.pfEnvironmentCompatible)
        check("rulesAreStateless",rulesAreStateless,other.rulesAreStateless);check("anchorReachable",anchorReachable,other.anchorReachable)
        check("claudeProcesses",claudeProcesses,other.claudeProcesses)
        check("processInventoryComplete",processInventoryComplete,other.processInventoryComplete)
        check("states",states,other.states);check("stateInventoryComplete",stateInventoryComplete,other.stateInventoryComplete)
        check("ipv6Routable",ipv6Routable,other.ipv6Routable)
        return fields
    }
    public var epoch: UInt64
    public var interfaces: [InterfaceIdentity]
    public var routeFingerprint: String
    public var configurationFingerprint: String
    public var nodeName: String
    public var gateway: String
    public var gatewayPort: UInt16
    public var protocolName: String
    public var flclashRunning: Bool
    public var coreIdentityVerified: Bool
    public var core: ProcessIdentity
    public var connection: CoreConnection
    public var verifiedTun: InterfaceIdentity
    public var tunRuntimeVerified: Bool
    public var pfEnabled: Bool
    public var ownReference: String
    public var rulesFingerprint: String
    public var mainRulesFingerprint: String
    public var pfEnvironmentCompatible: Bool
    public var rulesAreStateless: Bool
    public var anchorReachable: Bool
    public var claudeProcesses: [ProcessIdentity]
    public var processInventoryComplete: Bool
    public var states: [ExistingState]
    public var stateInventoryComplete: Bool
    public var ipv6Routable: Bool

    public init(policy: GuardPolicy, core: ProcessIdentity, connection: CoreConnection) {
        // Unverified defaults are deliberate. The collector must provide every positive fact.
        epoch = 0; interfaces = []; routeFingerprint = ""; configurationFingerprint = ""
        nodeName = ""; gateway = ""; gatewayPort = 0; protocolName = ""
        flclashRunning = false; coreIdentityVerified = false; self.core = core; self.connection = connection
        verifiedTun = policy.tun; tunRuntimeVerified = false; pfEnabled = false; ownReference = ""
        rulesFingerprint = ""; mainRulesFingerprint = ""; pfEnvironmentCompatible = false
        rulesAreStateless = false; anchorReachable = false; claudeProcesses = []
        processInventoryComplete = false; states = []; stateInventoryComplete = false; ipv6Routable = false
    }
}

public enum ProbeKind: String, CaseIterable, Sendable, Codable { case boundTCP, boundUDP, boundSTUN, boundIPv6 }

public struct NegativeProbe: Sendable, Codable {
    public var kind: ProbeKind
    public var sessionID: UUID
    public var epoch: UInt64
    public var ruleFingerprint: String
    public var dedicatedLabel: String
    public var tupleMatched: Bool
    public var failed: Bool
    public var counterBefore: UInt64
    public var counterAfter: UInt64
    public var measuredAt: UInt64
    public init(kind: ProbeKind, sessionID: UUID, epoch: UInt64, ruleFingerprint: String,
                dedicatedLabel: String, tupleMatched: Bool, failed: Bool,
                counterBefore: UInt64, counterAfter: UInt64, measuredAt: UInt64) {
        self.kind = kind; self.sessionID = sessionID; self.epoch = epoch; self.ruleFingerprint = ruleFingerprint
        self.dedicatedLabel = dedicatedLabel; self.tupleMatched = tupleMatched; self.failed = failed
        self.counterBefore = counterBefore; self.counterAfter = counterAfter; self.measuredAt = measuredAt
    }
}

public enum EgressService: String, CaseIterable, Sendable, Codable { case ipify, webshare }
public struct EgressObservation: Sendable, Codable {
    public var sessionID: UUID
    public var epoch: UInt64
    public var ruleFingerprint: String
    public var service: EgressService
    public var ipv4: String
    public var bypassesSystemProxy: Bool
    public var tlsVerified: Bool
    public var measuredAt: UInt64
    public init(sessionID: UUID, epoch: UInt64, ruleFingerprint: String, service: EgressService, ipv4: String, bypassesSystemProxy: Bool, tlsVerified: Bool, measuredAt: UInt64) {
        self.sessionID = sessionID; self.epoch = epoch; self.ruleFingerprint = ruleFingerprint
        self.service = service; self.ipv4 = ipv4; self.bypassesSystemProxy = bypassesSystemProxy
        self.tlsVerified = tlsVerified; self.measuredAt = measuredAt
    }
}

public struct ValidationBundle: Sendable, Codable {
    public var startedAt: UInt64
    public var sessionID: UUID
    public var baseline: LocalSnapshot
    public var egress: [EgressObservation]
    public var negative: [NegativeProbe]
    public init(sessionID: UUID, startedAt: UInt64, baseline: LocalSnapshot, egress: [EgressObservation], negative: [NegativeProbe]) {
        self.startedAt = startedAt; self.sessionID = sessionID; self.baseline = baseline; self.egress = egress; self.negative = negative
    }
}

public enum SafetyGate {
    public static func validatePreflight(_ s: LocalSnapshot, policy p: GuardPolicy) throws {
        guard s.interfaces.contains(p.physical), s.interfaces.contains(p.tun),
              Set(s.interfaces.map(\.name)).count == s.interfaces.count,
              Set(s.interfaces.map(\.index)).count == s.interfaces.count,
              !s.routeFingerprint.isEmpty,
              s.configurationFingerprint == p.endpoint.configurationFingerprint,
              !s.nodeName.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty, s.gateway == p.endpoint.gateway,
              s.gatewayPort == p.endpoint.port, s.protocolName == "http",
              s.flclashRunning, s.coreIdentityVerified, s.core.pid > 0,
              s.core.startTime > 0, !s.core.executableIdentity.isEmpty,
              s.connection.owner == s.core, s.connection.established,
              s.connection.gateway == p.endpoint.gateway, s.connection.port == p.endpoint.port,
              s.connection.localAddress == p.physical.ipv4, s.connection.localPort > 0,
              s.verifiedTun == p.tun, s.tunRuntimeVerified,
              s.processInventoryComplete, s.claudeProcesses.isEmpty, s.stateInventoryComplete else {
            throw GuardFailure.rejected("Incomplete runtime node, process, interface or TUN evidence")
        }
        guard !s.mainRulesFingerprint.isEmpty, s.pfEnvironmentCompatible else {
            throw GuardFailure.rejected("Incompatible PF preflight")
        }
        try StateClassifier.validate(s.states, policy: p)
    }
    public static func validateLocal(_ s: LocalSnapshot, policy p: GuardPolicy) throws {
        try validatePreflight(s, policy: p)
        guard s.pfEnabled, !s.ownReference.isEmpty, s.rulesFingerprint == p.rulesFingerprint,
              !s.mainRulesFingerprint.isEmpty, s.pfEnvironmentCompatible,
              s.rulesAreStateless, s.anchorReachable else {
            throw GuardFailure.rejected("PF protection is not verified")
        }
        try StateClassifier.validate(s.states, policy: p)
    }
    public static func validate(_ bundle: ValidationBundle, final: LocalSnapshot, policy: GuardPolicy, now: UInt64) throws {
        try validateLocal(bundle.baseline, policy: policy)
        try validateLocal(final, policy: policy)
        guard bundle.sessionID == policy.sessionID, bundle.baseline == final else {
            let changed=bundle.baseline.differingFields(from:final)
            throw GuardFailure.rejected("Final premises changed during validation: \(changed.isEmpty ? "sessionID":changed.joined(separator:","))")
        }
        func fresh(_ time: UInt64) -> Bool { time >= bundle.startedAt && time <= now && now - time <= 15 }
        guard bundle.egress.count == 2, Set(bundle.egress.map(\.service)).count == 2,
              bundle.egress.allSatisfy({ $0.sessionID == policy.sessionID && $0.epoch == final.epoch &&
                  $0.ruleFingerprint == policy.rulesFingerprint && $0.ipv4 == policy.endpoint.expectedEgress &&
                  $0.bypassesSystemProxy && $0.tlsVerified && fresh($0.measuredAt) }) else {
            throw GuardFailure.rejected("Two fresh independent HTTPS exit observations required")
        }
        var required: Set<ProbeKind> = [.boundTCP, .boundUDP, .boundSTUN]
        if final.ipv6Routable { required.insert(.boundIPv6) }
        guard Set(bundle.negative.map(\.kind)) == required, bundle.negative.count == required.count,
              Set(bundle.negative.map(\.dedicatedLabel)).count == required.count,
              bundle.negative.allSatisfy({ probe in
                  probe.sessionID == policy.sessionID && probe.epoch == final.epoch &&
                  probe.ruleFingerprint == policy.rulesFingerprint && probe.dedicatedLabel == policy.probeLabel(probe.kind) &&
                  probe.tupleMatched && probe.failed && probe.counterAfter > probe.counterBefore &&
                  fresh(probe.measuredAt)
              }) else {
            throw GuardFailure.rejected("Missing fresh failed probes with dedicated block counter evidence")
        }
    }
}

public enum MonitoringGate {
    public static func validate(_ current:LocalSnapshot,baseline:LocalSnapshot,policy:GuardPolicy) throws {
        // Runtime monitoring permits Claude to exist; this copy asserts only the network premises.
        var network=current;network.claudeProcesses=[]
        try SafetyGate.validateLocal(network,policy:policy)
        guard Set(current.states.map(\.id)).isSubset(of:Set(baseline.states.map(\.id))) else{throw GuardFailure.rejected("New state appeared during stateless monitoring")}
        let fields=changedPremises(current,baseline:baseline)
        guard fields.isEmpty else{throw GuardFailure.rejected("Protected runtime premises changed: "+fields.joined(separator:","))}
    }
    /// Exactly the existing monitoring allowances; raw differences are recorded separately for diagnosis.
    public static func changedPremises(_ current:LocalSnapshot,baseline:LocalSnapshot)->[String] {
        var expected=baseline;expected.claudeProcesses=current.claudeProcesses;expected.states=current.states
        // A fresh established socket owned by the SAME verified Core and endpoint is expected HTTP behavior.
        // Startup's final snapshot comparison remains exact and does not permit this renewal.
        expected.connection.localPort=current.connection.localPort
        var fields=expected.differingFields(from:current)
        if !Set(current.states.map(\.id)).isSubset(of:Set(baseline.states.map(\.id))) {fields.append("states")}
        return fields
    }
}
