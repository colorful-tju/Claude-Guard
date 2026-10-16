import Foundation
import Testing
@testable import GuardRuntime

struct ProxyRegistrationTests {
    @Test func registeredPathsRoundTripWithoutDependingOnGUIIdentity() throws {
        var original=Installation(uid:501,home:"/Users/example",clients:["ui"],coreHash:"core-build",flclashHash:"",claudeHash:"claude")
        original.proxyCorePath="/Applications/Example.app/Contents/MacOS/core"
        original.proxyConfigPath="/Users/example/runtime.yaml"
        let loaded=try JSONDecoder().decode(Installation.self,from:JSONEncoder().encode(original))
        #expect(loaded.registeredCorePath==original.proxyCorePath)
        #expect(loaded.registeredConfigPath==original.proxyConfigPath)
        #expect(loaded.coreHash=="core-build")
    }
    @Test func legacyRecoveryRegistrationRemainsDecodable() throws {
        let json=Data(#"{"uid":501,"home":"/Users/example","clients":[],"coreHash":"core","flclashHash":"gui","claudeHash":"claude"}"#.utf8)
        let old=try JSONDecoder().decode(Installation.self,from:json)
        #expect(old.proxyCorePath==nil && old.registeredCorePath.hasSuffix("FlClashCore"))
    }
    @Test func nodeNameIsNotBrandGateButNumericHTTPStillRequired() throws {
        let valid=Data(#"{"name":"My HTTP proxy","type":"http","server":"1.1.1.1","port":3128,"numeric":true,"fingerprint":"hash","tunDevice":""}"#.utf8)
        #expect(try NodeConfiguration.parse(valid).name=="My HTTP proxy")
        let text=String(decoding:valid,as:UTF8.self)
        for bad in [text.replacingOccurrences(of:"My HTTP proxy",with:" "),text.replacingOccurrences(of:"http",with:"socks5"),text.replacingOccurrences(of:"1.1.1.1",with:"proxy.example.com")] {
            reject{_ = try NodeConfiguration.parse(Data(bad.utf8))}
        }
    }
}
