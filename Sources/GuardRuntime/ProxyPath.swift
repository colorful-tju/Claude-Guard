import Foundation
import GuardCore
public struct ChainEntry:Codable,Sendable,Equatable {
    public var name:String;public var type:String;public var server:String;public var port:UInt16
    public init(name:String,type:String,server:String,port:UInt16){self.name=name;self.type=type;self.server=server;self.port=port}
}
public struct ChainConfiguration:Codable,Sendable,Equatable {
    public var dialer:String;public var entries:[ChainEntry]
    public init(dialer:String,entries:[ChainEntry]){self.dialer=dialer;self.entries=entries}
}
public struct ProxyPath:Sendable {
    public let gateway:String;public let port:UInt16;public let protocolName:String;public let chain:ChainBoundary?
    public static func resolve(node:NodeConfiguration,settings:Settings) throws -> Self {
        guard settings.providerConfirmed,node.server==settings.gateway,node.port==settings.port,
              node.fingerprint==settings.confirmationFingerprint else{throw fail("Provider endpoint confirmation does not match current config fingerprint")}
        if settings.effectivePathMode == .direct {
            guard node.chain==nil else{throw fail("Chain configuration requires chain mode; physical entry is not the ISP landing")}
            return .init(gateway:node.server,port:node.port,protocolName:node.type,chain:nil)
        }
        guard let config=node.chain,let name=settings.entryName,let ip=settings.entryIPv4,
              IPv4.isPublic(ip),config.entries.filter({$0.name==name}).count==1,
              let entry=config.entries.first(where:{$0.name==name}),entry.port>0 else {
            throw fail("Chain entry missing: select a TCP entry and confirm its current public IPv4")
        }
        // A domain stays a domain in the proxy config. The operator explicitly pins
        // one currently connected address for PF; no DNS lookup or rewrite occurs.
        if IPv4.octets(entry.server) != nil,entry.server != ip {throw fail("Chain numeric entry differs from confirmed physical IPv4")}
        let boundary=ChainBoundary(landingGateway:node.server,landingPort:node.port,entryName:name,entryProtocol:entry.type,entryHost:entry.server)
        try boundary.validate()
        return .init(gateway:ip,port:entry.port,protocolName:entry.type,chain:boundary)
    }
}
