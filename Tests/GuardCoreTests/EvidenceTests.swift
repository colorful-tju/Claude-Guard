import Foundation
import Testing
@testable import GuardCore

func fixtureSnapshot(_ p: GuardPolicy) -> LocalSnapshot {
    let core = ProcessIdentity(pid: 2345, startTime: 100, executableIdentity: "verified-core-cdhash")
    let connection = CoreConnection(owner: core, gateway: p.endpoint.gateway, port: p.endpoint.port,
                                    localAddress: p.physical.ipv4, localPort: 50000, established: true)
    var s = LocalSnapshot(policy: p, core: core, connection: connection)
    s.epoch = 7; s.interfaces = [p.physical, p.tun]; s.routeFingerprint = "routes-1"
    s.configurationFingerprint = p.endpoint.configurationFingerprint; s.nodeName = "Webshare-Canada"
    s.gateway = p.endpoint.gateway; s.gatewayPort = p.endpoint.port; s.protocolName = "http"
    s.flclashRunning = true; s.coreIdentityVerified = true; s.tunRuntimeVerified = true
    s.pfEnabled = true; s.ownReference = "owned-reference-1"; s.rulesFingerprint = p.rulesFingerprint
    s.mainRulesFingerprint = "main-rules-1"; s.pfEnvironmentCompatible = true
    s.rulesAreStateless = true; s.anchorReachable = true; s.processInventoryComplete = true
    s.stateInventoryComplete = true
    return s
}

func fixtureBundle(_ p: GuardPolicy) -> ValidationBundle {
    let s = fixtureSnapshot(p)
    return ValidationBundle(sessionID: p.sessionID, startedAt: 90, baseline: s,
        egress: EgressService.allCases.map {
            EgressObservation(sessionID: p.sessionID, epoch: s.epoch, ruleFingerprint: p.rulesFingerprint, service: $0, ipv4: p.endpoint.expectedEgress, bypassesSystemProxy: true,
                              tlsVerified: true, measuredAt: 95)
        }, negative: [ProbeKind.boundTCP, .boundUDP, .boundSTUN].map {
            NegativeProbe(kind: $0, sessionID: p.sessionID, epoch: s.epoch, ruleFingerprint: p.rulesFingerprint,
                          dedicatedLabel: p.probeLabel($0), tupleMatched: true, failed: true,
                          counterBefore: 10, counterAfter: 11, measuredAt: 96)
        })
}

func gatewayState(_ p: GuardPolicy) -> ExistingState {
    .init(id: "state-1", boundInterface: p.physical.name, localAddress: p.physical.ipv4,
          remoteAddress: p.endpoint.gateway, localPort: 50000, remotePort: p.endpoint.port)
}

struct EvidenceTests {
    @Test func validationDiagnosticsRedactReferencesAndBoundStoredData() throws {
        let p=try fixturePolicy();var b=fixtureBundle(p),f=b.baseline
        b.baseline.ownReference="secret-reference-before";f.ownReference="secret-reference-after";f.connection.localPort += 1
        let report=ValidationDiagnostics(bundle:b,final:f,routesBefore:"before routes",routesAfter:"after routes")
        let data=try report.encoded(),text=String(decoding:data,as:UTF8.self)
        #expect(!text.contains("secret-reference-before"));#expect(!text.contains("secret-reference-after"))
        #expect(Set(report.changedFields)==["ownReference","connection"])
        #expect(report.negative.count==3);#expect(report.egress.count==2)
        #expect(b.baseline.ownReference=="secret-reference-before")
        let huge=ValidationDiagnostics(bundle:b,final:f,routesBefore:String(repeating:"r",count:65536),routesAfter:"")
        expectThrows(try huge.encoded())
    }
    @Test func everySnapshotFieldIsNamedWhenItChanges() throws {
        let b=fixtureSnapshot(try fixturePolicy())
        let mutations:[(String,(inout LocalSnapshot)->Void)]=[
            ("epoch",{$0.epoch += 1}),("interfaces",{$0.interfaces.removeLast()}),
            ("routeFingerprint",{$0.routeFingerprint += "x"}),("configurationFingerprint",{$0.configurationFingerprint += "x"}),
            ("nodeName",{$0.nodeName += "x"}),("gateway",{$0.gateway="1.1.1.1"}),("gatewayPort",{$0.gatewayPort += 1}),
            ("protocolName",{$0.protocolName="other"}),("flclashRunning",{$0.flclashRunning.toggle()}),
            ("coreIdentityVerified",{$0.coreIdentityVerified.toggle()}),("core",{$0.core.pid += 1}),
            ("connection",{$0.connection.localPort += 1}),("verifiedTun",{$0.verifiedTun.index += 1}),
            ("tunRuntimeVerified",{$0.tunRuntimeVerified.toggle()}),("pfEnabled",{$0.pfEnabled.toggle()}),
            ("ownReference",{$0.ownReference += "x"}),("rulesFingerprint",{$0.rulesFingerprint += "x"}),
            ("mainRulesFingerprint",{$0.mainRulesFingerprint += "x"}),("pfEnvironmentCompatible",{$0.pfEnvironmentCompatible.toggle()}),
            ("rulesAreStateless",{$0.rulesAreStateless.toggle()}),("anchorReachable",{$0.anchorReachable.toggle()}),
            ("claudeProcesses",{$0.claudeProcesses=[.init(pid:1,startTime:1,executableIdentity:"Claude")]}),
            ("processInventoryComplete",{$0.processInventoryComplete.toggle()}),
            ("states",{$0.states=[gatewayState(try! fixturePolicy())]}),
            ("stateInventoryComplete",{$0.stateInventoryComplete.toggle()}),("ipv6Routable",{$0.ipv6Routable.toggle()})]
        let keys=try JSONSerialization.jsonObject(with:JSONEncoder().encode(b)) as! [String:Any]
        #expect(Set(mutations.map(\.0))==Set(keys.keys))
        #expect(b.differingFields(from:b).isEmpty)
        for (name,change) in mutations {var changed=b;change(&changed);#expect(b.differingFields(from:changed)==[name])}
    }
    @Test func finalGateNamesDifferencesAndStillRejectsThem() throws {
        let p=try fixturePolicy(),b=fixtureBundle(p);var final=b.baseline
        final.epoch += 1;final.connection.localPort += 1;final.routeFingerprint += "x"
        do {try SafetyGate.validate(b,final:final,policy:p,now:100);Issue.record("Changed startup premises must be rejected")}
        catch {let text=String(describing:error);for name in ["epoch","connection","routeFingerprint"]{#expect(text.contains(name))}}
    }
    @Test func authorizedExistingGatewayStateDoesNotRequireEmptyTable() throws {
        let p = try fixturePolicy()
        try StateClassifier.validate([gatewayState(p)], policy: p)
        var b = fixtureBundle(p); b.baseline.states = [gatewayState(p)]
        try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100)
    }

    @Test func rejectsOldDirectFloatingUnknownAndOwnStates() throws {
        let p = try fixturePolicy()
        var forbidden = gatewayState(p); forbidden.remoteAddress = "1.1.1.1"
        var floating = gatewayState(p); floating.boundInterface = nil
        var unknown = gatewayState(p); unknown.parserRecognized = false
        var own = gatewayState(p); own.originatingSession = p.sessionID
        var udp = gatewayState(p); udp.transport = .udp
        var spoofed = gatewayState(p); spoofed.localAddress = "172.21.191.85"
        for state in [forbidden, floating, unknown, own, udp, spoofed] {
            expectThrows(try StateClassifier.validate([state], policy: p))
        }
    }

    @Test func matchingNameWithoutRuntimeProofIsRejected() throws {
        let p = try fixturePolicy()
        let changes: [(inout LocalSnapshot) -> Void] = [
            { $0.connection.gateway = "9.9.9.9" }, { $0.connection.port = 80 },
            { $0.connection.owner.pid = 999 }, { $0.connection.established = false },
            { $0.connection.localAddress = "127.0.0.1" }, { $0.coreIdentityVerified = false },
            { $0.tunRuntimeVerified = false }, { $0.flclashRunning = false },
            { $0.protocolName = "hysteria2" }, { $0.nodeName = "" },
            { $0.processInventoryComplete = false }, { $0.stateInventoryComplete = false },
            { $0.claudeProcesses = [.init(pid: 123, startTime: 1, executableIdentity: "Claude")] },
            { $0.configurationFingerprint = "other-config" }, { $0.gatewayPort = 80 }
        ]
        for change in changes {
            var b = fixtureBundle(p); change(&b.baseline)
            expectThrows(try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100))
        }
    }

    @Test func readableRulesWithoutEnforcementAreRejected() throws {
        let p = try fixturePolicy()
        for change: (inout LocalSnapshot) -> Void in [
            { $0.anchorReachable = false }, { $0.rulesAreStateless = false },
            { $0.pfEnabled = false }, { $0.ownReference = "" },
            { $0.pfEnvironmentCompatible = false }, { $0.rulesFingerprint = "not-loaded" }
        ] {
            var b = fixtureBundle(p); change(&b.baseline)
            expectThrows(try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100))
        }
    }

    @Test func negativeProbeNeedsFailureAndDedicatedCounterIncrement() throws {
        let p = try fixturePolicy()
        let changes: [(inout NegativeProbe) -> Void] = [
            { $0.failed = false }, { $0.counterAfter = 10 }, { $0.counterAfter = 0 },
            { $0.tupleMatched = false }, { $0.dedicatedLabel = "" },
            { $0.epoch = 6 }, { $0.sessionID = UUID() }, { $0.ruleFingerprint = "old" },
            { $0.measuredAt = 10 }, { $0.measuredAt = 101 }
        ]
        for change in changes {
            var b = fixtureBundle(p); change(&b.negative[0])
            expectThrows(try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100))
        }
        var missing = fixtureBundle(p); missing.negative.removeLast()
        expectThrows(try SafetyGate.validate(missing, final: missing.baseline, policy: p, now: 100))
        var duplicate = fixtureBundle(p); duplicate.negative[1].dedicatedLabel = duplicate.negative[0].dedicatedLabel
        expectThrows(try SafetyGate.validate(duplicate, final: duplicate.baseline, policy: p, now: 100))
    }

    @Test func requiresTwoIndependentFreshVerifiedEgressResults() throws {
        let p = try fixturePolicy()
        for change: (inout EgressObservation) -> Void in [
            { $0.ipv4 = "202.113.13.3" }, { $0.bypassesSystemProxy = false },
            { $0.tlsVerified = false }, { $0.service = .webshare },
            { $0.measuredAt = 1 }, { $0.measuredAt = 101 }
        ] {
            var b = fixtureBundle(p); change(&b.egress[0])
            expectThrows(try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100))
        }
    }

    @Test func anyCriticalFinalSnapshotChangeInvalidatesProbes() throws {
        let p = try fixturePolicy(); let b = fixtureBundle(p)
        let changes: [(inout LocalSnapshot) -> Void] = [
            { $0.epoch += 1 }, { $0.interfaces[0].index += 1 }, { $0.interfaces[0].generation += 1 },
            { $0.interfaces[0].ipv4 = "172.21.191.85" }, { $0.verifiedTun.generation += 1 },
            { $0.routeFingerprint = "routes-2" }, { $0.mainRulesFingerprint = "main-2" },
            { $0.ownReference = "another-reference" }, { $0.connection.localPort += 1 },
            { $0.core.startTime += 1 }, { $0.states = [gatewayState(p)] },
            { $0.interfaces.append(.init(name: "en9", index: 40, generation: 3, ipv4: "10.0.0.3")) },
            { $0.claudeProcesses = [.init(pid: 999, startTime: 101, executableIdentity: "Claude")] }
        ]
        for change in changes {
            var final = b.baseline; change(&final)
            expectThrows(try SafetyGate.validate(b, final: final, policy: p, now: 100))
        }
    }

    @Test func ipv6RouteRequiresActualProbe() throws {
        let p = try fixturePolicy(); var b = fixtureBundle(p); b.baseline.ipv6Routable = true
        expectThrows(try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100))
        var v6 = b.negative[0]; v6.kind = .boundIPv6; v6.dedicatedLabel = p.probeLabel(.boundIPv6)
        b.negative.append(v6)
        try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100)
    }
    @Test func rejectReplayedEgressContextAndPreinstallationSamples() throws {
        let p = try fixturePolicy()
        for change: (inout EgressObservation) -> Void in [
            { $0.sessionID = UUID() }, { $0.epoch = 6 },
            { $0.ruleFingerprint = "previous-rules" }, { $0.measuredAt = 89 }
        ] {
            var b = fixtureBundle(p); change(&b.egress[0])
            expectThrows(try SafetyGate.validate(b, final: b.baseline, policy: p, now: 100))
        }
    }
    @Test func monitoringAllowsOnlyProvenGatewaySocketRenewal() throws {
        let p=try fixturePolicy();let baseline=fixtureSnapshot(p);var current=baseline
        current.connection.localPort += 1
        current.claudeProcesses=[.init(pid:123,startTime:200,executableIdentity:"Claude")]
        try MonitoringGate.validate(current,baseline:baseline,policy:p)
        current.connection.gateway="1.1.1.1"
        expectThrows(try MonitoringGate.validate(current,baseline:baseline,policy:p))
        current=baseline;current.epoch += 1
        expectThrows(try MonitoringGate.validate(current,baseline:baseline,policy:p))
        current=baseline;current.states=[gatewayState(p)]
        expectThrows(try MonitoringGate.validate(current,baseline:baseline,policy:p))
    }
}

struct MonitoringDifferenceTests {
    @Test func monitoringFailureNamesEveryChangedPremiseWithoutRelaxingTheGate() throws {
        let p=try fixturePolicy(),baseline=fixtureSnapshot(p);var current=baseline
        current.epoch+=1;current.routeFingerprint="changed route";current.mainRulesFingerprint="changed main"
        current.connection.localPort+=1 // Already permitted while monitoring, never reported as the cause.
        do{try MonitoringGate.validate(current,baseline:baseline,policy:p);Issue.record("Changed premises must be rejected")}
        catch {
            let text=String(describing:error)
            for field in ["epoch","routeFingerprint","mainRulesFingerprint"]{#expect(text.contains(field))}
        }
    }
}

struct MonitoringReportTests {
    @Test func reportsRawRenewalWithoutCallingItAnUnsafeChangeAndRedactsAllReferences() throws {
        let p=try fixturePolicy();var baseline=fixtureSnapshot(p),current=baseline
        baseline.ownReference="PRIVATE_BASELINE_REFERENCE";current.ownReference="PRIVATE_BASELINE_REFERENCE"
        current.connection.localPort+=1
        let report=MonitoringDiagnostics(sessionID:p.sessionID,buildID:"test",stage:"premisesComparison",reason:"test",
            baseline:baseline,previousHealthy:baseline,current:current,baselineRoutes:"before",previousRoutes:"previous",currentRoutes:"after",previousHealthyAt:"then")
        let text=String(decoding:try report.encoded(),as:UTF8.self)
        #expect(report.changedFields.isEmpty)
        #expect(report.rawChangedFields==["connection"])
        #expect(report.changedSincePrevious==["connection"])
        #expect(!text.contains("PRIVATE_BASELINE_REFERENCE"))
        #expect(baseline.ownReference=="PRIVATE_BASELINE_REFERENCE")
        try MonitoringGate.validate(current,baseline:baseline,policy:p)
    }
    @Test func oversizedMonitoringReportCannotBePersistedSilently() throws {
        let p=try fixturePolicy(),baseline=fixtureSnapshot(p)
        let report=MonitoringDiagnostics(sessionID:p.sessionID,buildID:"test",stage:"runtimeCollection",reason:"test",
            baseline:baseline,previousHealthy:nil,current:nil,baselineRoutes:String(repeating:"r",count:100000),previousRoutes:nil,currentRoutes:nil,previousHealthyAt:nil)
        expectThrows(try report.encoded())
        #expect(!report.currentComplete && report.current==nil)
    }
}
