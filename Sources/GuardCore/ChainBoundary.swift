import Foundation

public enum ProxyPathMode:String,Codable,Sendable {case direct,chain}
/// Operator-selected first hop; not a claim of per-request inner-chain observation.
public struct ChainBoundary:Equatable,Codable,Sendable {
    public let landingGateway:String
    public let landingPort:UInt16
    public let entryName:String
    public let entryProtocol:String
    public let entryHost:String
    public init(landingGateway:String,landingPort:UInt16,entryName:String,entryProtocol:String,entryHost:String) {
        self.landingGateway=landingGateway;self.landingPort=landingPort;self.entryName=entryName;self.entryProtocol=entryProtocol;self.entryHost=entryHost
    }
    public func validate() throws {
        guard IPv4.isPublic(landingGateway),landingPort>0,!entryName.isEmpty,!entryHost.isEmpty,
              ["vless","vmess","trojan","ss","http","socks5"].contains(entryProtocol) else {
            throw GuardFailure.unsupported("Chain requires a fixed TCP entry and numeric HTTP landing")
        }
    }
}
