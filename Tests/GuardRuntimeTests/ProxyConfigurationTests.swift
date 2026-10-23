import Foundation
import Testing
import Darwin
@testable import GuardRuntime
struct ProxyConfigurationTests {
    @Test func reportsOldSubscriptionCountWithoutRawData() {
        do {
            _=try ProxyConfiguration.decode(.init(output:"{\"errorCode\":\"node-count\",\"nodeCount\":22}",error:"SECRET",status:1))
            Issue.record("must fail")
        }catch {
            #expect(String(describing:error).contains("22") && !String(describing:error).contains("SECRET"))
        }
        #expect(throws:(any Error).self){try ProxyConfiguration.decode(.init(output:"PRIVATE YAML",error:"SECRET",status:1))}
    }
    @Test func blankRelativeAndControlCharacterPathsRejected() {
        for path in ["","node.yaml","/tmp/line\nnext","/tmp/\0"] {
            #expect(throws:(any Error).self){try ProxyConfiguration.validatePath(path)}
        }
        #expect(Wire.responseTimeout(for:.registerProxyConfiguration)>=32)
    }
    @Test func realParserRejectsFriendConfigAndAcceptsCurrentCandidate() throws {
        let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
        defer{try? FileManager.default.removeItem(at:directory)}
        let file=directory.appendingPathComponent("candidate.yaml")
        let script=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/read-node.rb").path
        let old:[String:Any]=["mode":"rule","proxies":Array(repeating:["type":"trojan","password":"SECRET"],count:22)]
        try JSONSerialization.data(withJSONObject:old).write(to:file)
        do {_=try ProxyConfiguration.candidate(path:file.path,uid:getuid(),commands:Commands(),script:script);Issue.record("old config accepted")}
        catch {#expect(String(describing:error).contains("22") && !String(describing:error).contains("SECRET"))}
        let current:[String:Any]=["mode":"rule","proxies":[["name":"当前 HTTP","type":"http","server":"1.2.3.4","port":8080,"password":"SECRET"]]]
        let bytes=try JSONSerialization.data(withJSONObject:current);try bytes.write(to:file)
        let node=try ProxyConfiguration.candidate(path:file.path,uid:getuid(),commands:Commands(),script:script)
        #expect(node.fingerprint==hash(bytes) && node.server=="1.2.3.4")
    }

}
