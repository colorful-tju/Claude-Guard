import Testing
@testable import GuardCore

struct EndpointTests {
    func make(_ gateway: String = "1.1.1.1", port: UInt16 = 5376,
              egress: String = "1.1.1.1", confirmed: Bool = true,
              confirmedGateway: String? = nil, fingerprint: String = "config-v1",
              confirmedFingerprint: String = "config-v1", proto: String = "http") throws -> Endpoint {
        try Endpoint(gateway: gateway, port: port, expectedEgress: egress,
                     configurationFingerprint: fingerprint, providerConfirmed: confirmed,
                     confirmedGateway: confirmedGateway ?? gateway, confirmedPort: 5376,
                     confirmedFingerprint: confirmedFingerprint, protocolName: proto)
    }

    @Test func testGatewayAndEgressAreIndependent() throws {
        let endpoint = try make("23.20.10.8")
        #expect(endpoint.gateway == "23.20.10.8")
        #expect(endpoint.expectedEgress == "1.1.1.1")
    }

    @Test func testDomainNeverBecomesAnEndpoint() {
        expectThrows(try make("p.webshare.io"))
    }

    @Test func testRejectsAmbiguousOrNonPublicIPv4() {
        for address in ["", "01.1.1.1", "1.2.3", "1.2.3.256", "1.2.3.4\n", "127.0.0.1",
                        "172.21.191.84", "198.18.0.1", "0.0.0.0", "224.0.0.1", "::1", "1.2.3.4/32", "100.64.0.1"] {
            expectThrows(try make(address), address)
        }
    }

    @Test func testRequiresProviderConfirmationForExactEndpointAndConfiguration() {
        expectThrows(try make(confirmed: false))
        expectThrows(try make(confirmedGateway: "9.9.9.9"))
        expectThrows(try make(port: 80))
        expectThrows(try make(confirmedFingerprint: "old-config"))
        expectThrows(try make(fingerprint: "", confirmedFingerprint: ""))
    }

    @Test func testRejectsUnknownProtocolsPortZeroAndInvalidEgress() {
        for proto in ["socks5", "hysteria2", "http\npass out all", "https", ""] {
            expectThrows(try make(proto: proto))
        }
        expectThrows(try make(port: 0))
        expectThrows(try make(egress: "127.0.0.1"))
    }
}

func expectThrows<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", sourceLocation: SourceLocation = #_sourceLocation) {
    do {
        _ = try expression()
        Issue.record("Expected rejection: \(message)", sourceLocation: sourceLocation)
    } catch {}
}
