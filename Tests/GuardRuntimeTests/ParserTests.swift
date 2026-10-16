import Foundation
import Testing
import GuardCore
@testable import GuardRuntime
func reject(_ block: () throws -> Void) { do { try block(); Issue.record("Expected rejection") } catch {} }
struct ParserTests {
    @Test func enableTokenMustBeUnambiguous() throws {
        #expect(try PFText.token("pf enabled\nToken : 12345\n") == "12345")
        reject { _ = try PFText.token("Token : 1\nToken : 2") }
        reject { _ = try PFText.token("pf enabled") }
    }
    @Test func countersCannotUseEvaluationOrOtherLabel() throws {
        #expect(try PFText.counter("one 90 3 100 0 0 3 100\ntwo 5 0 0 0 0 0 0\n", label: "one") == 3)
        reject { _ = try PFText.counter("one 2 1", label: "one") }
        reject { _ = try PFText.counter("one 90 3 100 0 0 3 100\none 9 1 1 0 0 1 1", label: "one") }
    }
    @Test func rejectBypassingPFEnvironment() throws {
        try PFText.environment(main: "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", siblings: "", skipped: "lo0 (skip)\nen0\n")
        reject { try PFText.environment(main: "pass out quick all\nanchor \"com.apple/*\" all", siblings: "", skipped: "") }
        reject { try PFText.environment(main: "anchor \"com.apple/*\" all", siblings: "unexpected", skipped: "") }
        reject { try PFText.environment(main: "anchor \"com.apple/*\" all", siblings: "", skipped: "en7 (skip)") }
    }
    @Test func unknownStateFormatNeverLooksEmpty() throws {
        let e = try Endpoint(gateway:"23.20.10.8",port:5376,expectedEgress:"1.1.1.1",configurationFingerprint:"x",providerConfirmed:true,confirmedGateway:"23.20.10.8",confirmedPort:5376,confirmedFingerprint:"x",protocolName:"http")
        let p = try GuardPolicy(endpoint:e,physical:.init(name:"en0",index:6,generation:1,ipv4:"172.21.191.84"),tun:.init(name:"utun4",index:20,generation:1,ipv4:"198.18.0.1"))
        #expect(try PFText.states("", policy:p).isEmpty)
        reject { _ = try PFText.states("all tcp 1.1.1.1:443 <- 172.21.191.84:50000 ESTABLISHED:ESTABLISHED", policy:p) }
        reject { _ = try PFText.states("unknown text", policy:p) }
    }
    @Test func nodeSummaryRejectsExtraTunnelAndDomain() throws {
        let valid = Data("{\"name\":\"Webshare-Canada\",\"type\":\"http\",\"server\":\"1.1.1.1\",\"port\":5376,\"fingerprint\":\"abc\",\"numeric\":true,\"tunDevice\":\"FlClash\"}".utf8)
        #expect(try NodeConfiguration.parse(valid).port == 5376)
        reject { _ = try NodeConfiguration.parse(Data("{}".utf8)) }
        reject { _ = try NodeConfiguration.parse(Data(String(decoding:valid,as:UTF8.self).replacingOccurrences(of:"http",with:"hysteria2").utf8)) }
        reject { _ = try NodeConfiguration.parse(Data(String(decoding:valid,as:UTF8.self).replacingOccurrences(of:"1.1.1.1",with:"proxy.webshare.io").utf8)) }
    }
}
