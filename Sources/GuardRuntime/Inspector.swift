import Foundation
import Darwin
import GuardCore
import NativeGuard
import Security
public struct RuntimeEvidence:Sendable {
    public var node:NodeConfiguration;public var core:ProcessIdentity;public var connection:CoreConnection;public var network:NetworkView
    public var processObservation:String=""
    public var routeFingerprint:String;public var routeDetail:String;public var epoch:UInt64;public var claude:[ProcessIdentity]
}
public final class Inspector: @unchecked Sendable {
    private(set) var trackedClaude:[ProcessIdentity]=[]
    public let installation:Installation;public let commands:Commands;public let events:NetworkEvents
    public init(_ installation:Installation,commands:Commands,events:NetworkEvents){self.installation=installation;self.commands=commands;self.events=events}
    public func node() throws -> NodeConfiguration {
        let file=installation.registeredConfigPath
        var st=stat();guard lstat(file,&st)==0,(st.st_mode&S_IFMT)==S_IFREG,st.st_uid==installation.uid else{throw fail("Registered proxy config is missing or not owned by expected user")}
        let result=try commands.checked("/usr/bin/ruby",[Paths.root+"/read-node.rb",file])
        return try NodeConfiguration.parse(Data(result.utf8))
    }
    public func runtime(settings:Settings) throws -> RuntimeEvidence {
        let before=try events.epoch();let node=try node()
        guard settings.providerConfirmed,node.server==settings.gateway,node.port==settings.port,
              node.fingerprint==settings.confirmationFingerprint else{throw fail("Provider endpoint confirmation does not match current config fingerprint")}
        let inventory=NativeProcesses.inventory();let processes=try inventory.requireComplete()
        trackedClaude=NativeProcesses.claude(processes,uid:installation.uid,known:trackedClaude).map(\.identity)
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
                if remote==settings.gateway && socket.remote_port==settings.port {
                    connections.append(.init(owner:identity,gateway:remote,port:socket.remote_port,localAddress:local,localPort:socket.local_port,established:true))
                }
            }
        }
        guard tuns.count==1,let tun=tuns.first else{throw fail("Cannot attribute exactly one TUN to verified Core control socket")}
        let network=try Networks.read(physicalName:settings.physical,tunName:tun,epoch:before,commands:commands)
        // Read-only eligibility gate: Controller has not created a journal or
        // loaded/enabled PF when its initial runtime collection reaches here.
        try MVPNetworkRequirements.validate(ipv6Routable:network.ipv6Routable)
        let ordinaryRoute=try RouteEvidence.read(["-n","get",settings.gateway],commands:commands)
        let physicalRoute=try GatewayRoute.read(physical:network.physical.name,gateway:settings.gateway,commands:commands)
        let connection=try GatewayRoute.select(route:physicalRoute,physical:network.physical,owner:identity,
                                               gateway:settings.gateway,port:settings.port,connections:connections)
        let end=try NativeProcesses.record(core.pid)
        guard end.started==core.started,end.path==core.path,try events.epoch()==before else{throw fail("Runtime changed while collecting evidence")}
        let detail=network.detail+"\nordinary-gateway-route\n"+(try RouteEvidence.canonical(ordinaryRoute))+"\nphysical-scoped-gateway-route\n"+(try RouteEvidence.canonical(physicalRoute))
        return .init(node:node,core:identity,connection:connection,network:network,processObservation:inventory.rechecked>0 ? "rechecked=\(inventory.rechecked) recovered=\(inventory.recovered)":"",routeFingerprint:hash(Data(detail.utf8)),routeDetail:detail,epoch:before,claude:trackedClaude)
    }
    private func verifyProcess(_ r:ProcessRecord,expectedHash:String) throws {
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
