import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

struct ChainPathTests {
    let fixture: [String:Any] = ["mode":"rule","proxies":[
        ["name":"Entry","type":"vless","server":"entry.example","port":443,"uuid":"PRIVATE"],
        ["name":"ISP","type":"http","server":"8.8.4.4","port":5230,"password":"PRIVATE","dialer-proxy":"Front"]],
        "proxy-groups":[["name":"Front","type":"select","proxies":["Entry"]]],"rules":["MATCH,ISP"]]
    func read(_ value:[String:Any]) throws -> NodeConfiguration {
        let script=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/read-node.rb").path
        return try ProxyConfiguration.parse(JSONSerialization.data(withJSONObject:value),commands:Commands(),script:script)
    }
    @Test func candidateSeparatesLandingAndPhysicalEntry() throws {
        let n=try read(fixture)
        #expect(n.server=="8.8.4.4" && n.chain?.entries.first?.name=="Entry")
        var s=Settings();s.gateway=n.server;s.port=n.port;s.confirmationFingerprint=n.fingerprint;s.providerConfirmed=true
        s.pathMode = .chain;s.entryName="Entry";s.entryIPv4="1.2.3.4"
        let p=try ProxyPath.resolve(node:n,settings:s)
        #expect(p.gateway=="1.2.3.4" && p.port==443 && p.chain?.landingGateway=="8.8.4.4")
        #expect(!String(data:try JSONEncoder().encode(n),encoding:.utf8)!.contains("PRIVATE"))
        s.pathMode = .direct
        #expect(throws:(any Error).self){try ProxyPath.resolve(node:n,settings:s)}
    }
    @Test func numericEntryMustMatchAndUnsupportedEntryCannotBeChosen() throws {
        var f=fixture;var nodes=f["proxies"] as! [[String:Any]];nodes[0]["server"]="9.9.9.9";f["proxies"]=nodes
        let n=try read(f);var s=Settings();s.gateway=n.server;s.port=n.port;s.confirmationFingerprint=n.fingerprint;s.providerConfirmed=true;s.pathMode = .chain;s.entryName="Entry";s.entryIPv4="1.2.3.4"
        #expect(throws:(any Error).self){try ProxyPath.resolve(node:n,settings:s)}
        s.entryIPv4="9.9.9.9";#expect(try ProxyPath.resolve(node:n,settings:s).gateway=="9.9.9.9")
        nodes[0]["type"]="hysteria2";f["proxies"]=nodes
        #expect(throws:(any Error).self){try read(f)}
    }
    @Test func legacySettingsDecodeAsDirect() throws {
        let raw=Data(#"{"gateway":"1.2.3.4","port":80,"expectedEgress":"8.8.8.8","physical":"en0","providerConfirmed":false,"confirmationFingerprint":""}"#.utf8)
        #expect(try JSONDecoder().decode(Settings.self,from:raw).effectivePathMode == .direct)
    }
}
