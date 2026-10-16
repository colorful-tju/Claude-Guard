import Foundation
import GuardCore

// Entirely synthetic. This executable has no collector, socket, process launcher or PF backend.
do {
    let endpoint = try Endpoint(gateway: "23.20.10.8", port: 5376, expectedEgress: "1.1.1.1",
        configurationFingerprint: "synthetic-config", providerConfirmed: true,
        confirmedGateway: "23.20.10.8", confirmedPort: 5376, confirmedFingerprint: "synthetic-config",
        protocolName: "http")
    let policy = try GuardPolicy(endpoint: endpoint,
        physical: .init(name: "en0", index: 6, generation: 1, ipv4: "172.21.191.84"),
        tun: .init(name: "utun4", index: 20, generation: 2, ipv4: "198.18.0.1"))
    print("OFFLINE SIMULATION ONLY — 未保护本机，未检测真实网络，未启动 Claude")
    if CommandLine.arguments.contains("--print-rules") {
        print("# 未验证的 PF 候选文本；不要直接加载到运行系统")
        print(policy.rules)
    }
    let core = ProcessIdentity(pid: 2345, startTime: 100, executableIdentity: "synthetic-cdhash")
    let connection = CoreConnection(owner: core, gateway: endpoint.gateway, port: endpoint.port,
        localAddress: policy.physical.ipv4, localPort: 50000, established: true)
    var s = LocalSnapshot(policy: policy, core: core, connection: connection)
    s.epoch = 1; s.interfaces = [policy.physical, policy.tun]; s.routeFingerprint = "synthetic-routes"
    s.configurationFingerprint = endpoint.configurationFingerprint; s.nodeName = "Webshare-Canada"
    s.gateway = endpoint.gateway; s.gatewayPort = endpoint.port; s.protocolName = "http"
    s.flclashRunning = true; s.coreIdentityVerified = true; s.tunRuntimeVerified = true
    s.pfEnabled = true; s.ownReference = "synthetic-token"; s.rulesFingerprint = policy.rulesFingerprint
    s.mainRulesFingerprint = "synthetic-main"; s.pfEnvironmentCompatible = true
    s.rulesAreStateless = true; s.anchorReachable = true; s.processInventoryComplete = true; s.stateInventoryComplete = true
    let bundle = ValidationBundle(sessionID: policy.sessionID, startedAt: 90, baseline: s,
        egress: EgressService.allCases.map {
            EgressObservation(sessionID: policy.sessionID, epoch: s.epoch, ruleFingerprint: policy.rulesFingerprint, service: $0, ipv4: endpoint.expectedEgress, bypassesSystemProxy: true, tlsVerified: true, measuredAt: 95)
        }, negative: [ProbeKind.boundTCP, .boundUDP, .boundSTUN].map {
            NegativeProbe(kind: $0, sessionID: policy.sessionID, epoch: s.epoch, ruleFingerprint: policy.rulesFingerprint,
                dedicatedLabel: policy.probeLabel($0), tupleMatched: true, failed: true,
                counterBefore: 0, counterAfter: 1, measuredAt: 96)
        })
    var session = SafetySession(policy: policy)
    _ = try session.begin(); _ = try session.preflightAccepted(s); _ = try session.protectionInstalled(s, now: 90)
    _ = try session.arm(bundle, final: s, now: 100)
    print("模拟：完整证据 → \(session.phase.rawValue.uppercased())（仅模拟）")
    var changed = s; changed.epoch += 1
    do {
        try SafetyGate.validate(bundle, final: changed, policy: policy, now: 100)
        throw GuardFailure.rejected("Simulation failed: changed snapshot unexpectedly accepted")
    } catch let error as GuardFailure {
        guard case .rejected(let reason) = error, reason.hasPrefix("Final premises changed during validation:") else { throw error }
        print("模拟：最终网络代次改变 → 拒绝启动")
    }
    _ = session.stop(reason: "synthetic heartbeat failure")
    _ = try session.claudeExited(inventoryComplete: true, processes: [])
    _ = try session.rulesRemoved(rulesAbsent: true, stateInventoryComplete: true, states: [])
    _ = try session.referenceReleased(ownReferenceAbsent: true, foreignEnvironmentUnchanged: true)
    print("模拟：确认 Claude 退出 → 清自身规则及 state 检查 → 释放引用 → \(session.phase.rawValue.uppercased())")
    print("IPv6：模拟无路由；未执行实包验证。")
} catch {
    fputs("Offline simulation failed: \(error)\n", stderr)
    exit(1)
}
