import Foundation
import Darwin
import GuardCore
import NativeGuard
import Security
public struct RuntimeEvidence:Sendable {
    public var chainBoundary:ChainBoundary? = nil
    public var node:NodeConfiguration;public var core:ProcessIdentity;public var connection:CoreConnection;public var network:NetworkView
    public var inventory:ProcessInventory = .init(records:[],issues:[])
    public var processObservation:String=""
    public var routeFingerprint:String;public var routeDetail:String;public var epoch:UInt64;public var claude:[ProcessIdentity]
}
public final class Inspector: @unchecked Sendable {
    private var nodeCache=VerifiedNodeCache()
    private(set) var trackedClaude:[ProcessIdentity]=[]
    // Accessed on the existing serialized controller transaction path. Keep late
    // termination discoveries across failed recovery attempts and reparenting.
    func retainTerminationTargets(_ targets:[ProcessIdentity]) {
        var byPID=Dictionary(trackedClaude.map{($0.pid,$0)},uniquingKeysWith:{$1})
        for target in targets {byPID[target.pid]=target}
        trackedClaude=byPID.values.sorted{$0.pid<$1.pid}
    }
    public private(set) var installation:Installation;public let commands:Commands;public let events:NetworkEvents
    public init(_ installation:Installation,commands:Commands,events:NetworkEvents){self.installation=installation;self.commands=commands;self.events=events}
    public func node() throws -> NodeConfiguration {
        let file=installation.registeredConfigPath
        return try nodeCache.read(readBytes:{try ProxyConfiguration.bytes(path:file,uid:self.installation.uid)},parse:{ bytes in
            return try ProxyConfiguration.parse(bytes,commands:self.commands)
        })
    }
    public func configuration(path:String) throws -> NodeConfiguration {try ProxyConfiguration.candidate(path:path,uid:installation.uid,commands:commands)}
    public func adoptConfiguration(path:String) {installation.proxyConfigPath=path;nodeCache=VerifiedNodeCache()}
    public func runtime(settings:Settings) throws -> RuntimeEvidence {try collect(settings:settings,monitoring:false)}
    public func monitoringRuntime(settings:Settings) throws -> RuntimeEvidence {try collect(settings:settings,monitoring:true)}
    private func collect(settings:Settings,monitoring:Bool) throws -> RuntimeEvidence {
        let before=try events.epoch();let node=try node()
        let path=try ProxyPath.resolve(node:node,settings:settings)
        let inventory=NativeProcesses.inventory()
        let processes=monitoring ? inventory.records : try inventory.requireComplete()
        let observedClaude=NativeProcesses.claude(processes,uid:installation.uid,known:trackedClaude).map(\.identity)
        // Never discard descendants solely because a partial scan could not read them.
        if inventory.complete {trackedClaude=observedClaude}
        else {trackedClaude=Array(Set(trackedClaude+observedClaude))}
        let cores=processes.filter{$0.path==installation.registeredCorePath && ($0.uid==0 || $0.uid==installation.uid)}
        guard cores.count==1,let core=cores.first else{throw fail("Unique registered proxy Core not found; prepare the registered proxy manually")}
        try verifyProcess(core,expectedHash:installation.coreHash)
        let sockets=try NativeProcesses.sockets(core.pid)
        var tuns=Set<String>();var connections:[CoreConnection]=[]
        var identity=core.identity;identity.executableIdentity=installation.coreHash
        for var socket in sockets {
            let tun=NativeProcesses.text(&socket.tun);if !tun.isEmpty{tuns.insert(tun)}
            if socket.kind==2,socket.state==4 {
                let remote=NativeProcesses.text(&socket.remote);let local=NativeProcesses.text(&socket.local)
                if remote==path.gateway && socket.remote_port==path.port {
                    connections.append(.init(owner:identity,gateway:remote,port:socket.remote_port,localAddress:local,localPort:socket.local_port,established:true))
                }
            }
        }
        guard tuns.count==1,let tun=tuns.first else{throw fail("Cannot attribute exactly one TUN to verified Core control socket")}
        let network=try Networks.read(physicalName:settings.physical,tunName:tun,epoch:try events.interfaceGeneration(),commands:commands)
        // Read-only eligibility gate: Controller has not created a journal or
        // loaded/enabled PF when its initial runtime collection reaches here.
        try MVPNetworkRequirements.validate(ipv6Routable:network.ipv6Routable)
        let ordinaryRoute=try RouteEvidence.read(["-n","get",path.gateway],commands:commands)
        let physicalRoute=try GatewayRoute.read(physical:network.physical.name,gateway:path.gateway,commands:commands)
        let connection:CoreConnection
        do {connection=try GatewayRoute.select(route:physicalRoute,physical:network.physical,owner:identity,
                                               gateway:path.gateway,port:path.port,connections:connections)}
        catch is GatewaySocketUnavailable where monitoring && path.chain != nil {
            // No invented ESTABLISHED evidence: startup remains strict. During an
            // armed chain session PF is checked independently on every tick.
            connection = .init(owner:identity,gateway:path.gateway,port:path.port,localAddress:network.physical.ipv4,localPort:0,established:false)
        }
        let end=try NativeProcesses.record(core.pid)
        guard end.started==core.started,end.path==core.path else{throw fail("Runtime changed while collecting evidence: core identity")}
        let after=try events.epoch()
        guard after==before else{throw fail("Runtime changed while collecting evidence: epoch \(before)->\(after), interfaceGeneration=\(network.physical.generation)->\(try events.interfaceGeneration())")}
        let detail=network.detail+"\nordinary-gateway-route\n"+(try RouteEvidence.canonical(ordinaryRoute))+"\nphysical-scoped-gateway-route\n"+(try RouteEvidence.canonical(physicalRoute))
        return .init(chainBoundary:path.chain,node:node,core:identity,connection:connection,network:network,inventory:inventory,processObservation:inventory.rechecked>0 ? "rechecked=\(inventory.rechecked) recovered=\(inventory.recovered)":"",routeFingerprint:hash(Data(detail.utf8)),routeDetail:detail,epoch:before,claude:trackedClaude)
    }
    /// Suggestions only; confirmation plus a fresh startup socket is still required.
    public func physicalEntryCandidates(settings:Settings) throws -> [String] {
        let n=try node()
        guard let chain=n.chain,let name=settings.entryName,let entry=chain.entries.first(where:{$0.name==name}) else{return []}
        let records=try NativeProcesses.inventory().requireComplete()
        let cores=records.filter{$0.path==installation.registeredCorePath && ($0.uid==0 || $0.uid==installation.uid)}
        guard cores.count==1,let core=cores.first else{throw fail("Unique registered proxy Core not found")}
        try verifyProcess(core,expectedHash:installation.coreHash)
        let physical=try UDPProtection.physical(settings.physical)
        var ips=Set<String>()
        for var socket in try NativeProcesses.sockets(core.pid) where socket.kind==2 && socket.state==4 && socket.remote_port==entry.port {
            let remote=NativeProcesses.text(&socket.remote),local=NativeProcesses.text(&socket.local)
            if local==physical.ipv4 && IPv4.isPublic(remote) && (IPv4.octets(entry.server)==nil || remote==entry.server) {ips.insert(remote)}
        }
        let after=try NativeProcesses.record(core.pid)
        guard after.started==core.started,after.path==core.path else{throw fail("Core changed during entry suggestions")}
        return Array(ips.sorted().prefix(32))
    }
    func verifyProcess(_ r:ProcessRecord,expectedHash:String) throws {
        var guest:SecCode?
        guard SecCodeCopyGuestWithAttributes(nil,[kSecGuestAttributePid as String:r.pid] as CFDictionary,[],&guest)==errSecSuccess,let guest,
              SecCodeCheckValidity(guest,SecCSFlags(rawValue:kSecCSStrictValidate),nil)==errSecSuccess else{throw fail("Running proxy Core signature invalid")}
        var staticCode:SecStaticCode?;guard SecCodeCopyStaticCode(guest,[],&staticCode)==errSecSuccess,let staticCode else{throw fail("Core static code unavailable")}
        var info:CFDictionary?;guard SecCodeCopySigningInformation(staticCode,[],&info)==errSecSuccess,
              let dict=info as? [String:Any],let bytes=dict[kSecCodeInfoUnique as String] as? Data,
              bytes.map({String(format:"%02x",$0)}).joined()==expectedHash else{throw fail("Proxy Core build identity changed; reinstall registration")}
        let after=try NativeProcesses.record(r.pid);guard after.started==r.started,after.path==r.path else{throw fail("Process changed during identity check")}
    }
}
