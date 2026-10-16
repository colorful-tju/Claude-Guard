import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

struct GatewayRouteTests {
    private let physical=InterfaceIdentity(name:"en0",index:6,generation:1,ipv4:"172.21.191.84")
    private let owner=ProcessIdentity(pid:52941,startTime:100,executableIdentity:"verified-core")
    private let route="route to: 1.1.1.1\n gateway: 172.21.128.1\n interface: en0\n"
    private func connection() -> CoreConnection {
        .init(owner:owner,gateway:"1.1.1.1",port:5376,localAddress:"172.21.191.84",localPort:54449,established:true)
    }
    @Test func capturedPhysicalConnectionIsAcceptedWithScopedRoute() throws {
        let selected=try GatewayRoute.select(route:route,physical:physical,owner:owner,gateway:"1.1.1.1",port:5376,connections:[connection()])
        #expect(selected.localAddress == "172.21.191.84")
        #expect(selected.gateway == "1.1.1.1")
    }
    @Test func scopeDoesNotSubstituteForRealEstablishedCoreConnection() {
        reject{_ = try GatewayRoute.select(route:route,physical:physical,owner:owner,gateway:"1.1.1.1",port:5376,connections:[])}
        for field in 0..<8 {
            var c=connection()
            switch field {
            case 0:c.localAddress="198.18.0.1"
            case 1:c.owner.pid=99
            case 2:c.gateway="8.8.8.8"
            case 3:c.port=80
            case 4:c.established=false
            case 5:c.localPort=0
            case 6:c.owner.startTime=999
            default:c.owner.executableIdentity="different-core-build"
            }
            reject{_ = try GatewayRoute.select(route:route,physical:physical,owner:owner,gateway:"1.1.1.1",port:5376,connections:[c])}
        }
    }
    @Test func wrongUnknownOrAmbiguousRouteCannotAuthorizePhysicalPath() {
        for bad in ["",route.replacingOccurrences(of:"interface: en0",with:"interface: utun4"),route+"interface: en0\n",route.replacingOccurrences(of:"1.1.1.1",with:"8.8.8.8")] {
            reject{_ = try GatewayRoute.select(route:bad,physical:physical,owner:owner,gateway:"1.1.1.1",port:5376,connections:[connection()])}
        }
    }
    // Read-only native test, like the existing libproc/socket boundary tests.
    // Requires this Mac's active en0 IPv4 route; never switches or sends network traffic.
    private static var hasTunAndPhysicalRoute:Bool {
        let c=Commands()
        // Independent environment checks: no result from the function under test
        // participates in deciding whether to execute this native characterization.
        guard let ordinary=try? c.checked("/sbin/route",["-n","get","1.1.1.1"]),
              let physical=try? c.checked("/sbin/route",["-n","get","-ifscope","en0","1.1.1.1"]) else{return false}
        return ordinary.components(separatedBy:.newlines).contains{$0.trimmingCharacters(in:.whitespaces).hasPrefix("interface: utun")} &&
               physical.components(separatedBy:.newlines).contains{$0.trimmingCharacters(in:.whitespaces)=="interface: en0"}
    }
    @Test(.enabled(if:hasTunAndPhysicalRoute,"Requires an already active TUN and en0; never changes network modes"))
    func nativeRouteQueryUsesPhysicalScopeWhenOrdinaryRouteIsTun() throws {
        let commands=Commands()
        let ordinary=try commands.checked("/sbin/route",["-n","get","1.1.1.1"])
        #expect(ordinary.components(separatedBy:.newlines).contains{$0.trimmingCharacters(in:.whitespaces).hasPrefix("interface: utun")})
        let scoped=try GatewayRoute.read(physical:"en0",gateway:"1.1.1.1",commands:commands)
        #expect(scoped.components(separatedBy:.newlines).contains{$0.trimmingCharacters(in:.whitespaces)=="interface: en0"})
    }
}
