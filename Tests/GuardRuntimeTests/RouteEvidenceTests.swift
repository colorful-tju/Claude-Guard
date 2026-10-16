import Testing
@testable import GuardRuntime

struct RouteEvidenceTests {
    @Test func onlyExactUnallowlistedAuxiliaryNamesCanAvoidEpochInvalidation() {
        #expect(NetworkEvents.isAuxiliaryInterface("awdl0"))
        #expect(NetworkEvents.isAuxiliaryInterface("llw0"))
        for name in ["en0","utun4","lo0","awdl1","llw1","unknown",""] {#expect(!NetworkEvents.isAuxiliaryInterface(name))}
    }

    @Test func exitZeroWithStderrIsNotSuccessfulRouteEvidence() {
        for r in [CommandResult(output:"",error:"route: writing to routing socket: not in table",status:0),
                  .init(output:"",error:"Operation not permitted",status:0),
                  .init(output:"route to: 1.1.1.1",error:"",status:1)] {
            reject {_ = try RouteEvidence.canonical(r)}
        }
    }
    private let route="""
       route to: 1.1.1.1
    destination: default
           mask: default
        gateway: 172.21.128.1
      interface: en0
          flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
     recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
           0         0         0        20         5         0      1500       120
    """
    @Test func unconfiguredRTTAndExpirationDoNotChangeRouteIdentity() throws {
        let later=route.replacingOccurrences(of:"20         5",with:"99        16").replacingOccurrences(of:"1500       120",with:"1500       103")
        #expect(try RouteEvidence.canonical(route)==RouteEvidence.canonical(later))
    }
    @Test func unlockedSlowStartIsNotAStartupPremiseButLocksStillAre() throws {
        let changed=route.replacingOccurrences(of:"0         0         0        20",with:"0         0      1680        20")
        #expect(try RouteEvidence.canonical(route)==RouteEvidence.canonical(changed))
        let locked=changed.replacingOccurrences(of:"1680",with:"1680L")
        #expect(try RouteEvidence.canonical(locked) != RouteEvidence.canonical(route))
        #expect(try RouteEvidence.canonical(locked) != RouteEvidence.canonical(locked.replacingOccurrences(of:"1680L",with:"1681L")))
    }
    @Test func structuralAndConfiguredMetricChangesRemainVisible() throws {
        let original=try RouteEvidence.canonical(route)
        for changed in [route.replacingOccurrences(of:"gateway: 172.21.128.1",with:"gateway: 172.21.128.2"),
                        route.replacingOccurrences(of:"interface: en0",with:"interface: en1"),
                        route.replacingOccurrences(of:"route to: 1.1.1.1",with:"route to: 88.88.88.89"),
                        route.replacingOccurrences(of:"destination: default",with:"destination: 1.1.1.1"),
                        route.replacingOccurrences(of:"mask: default",with:"mask: 255.255.255.0"),
                        route.replacingOccurrences(of:"UP,GATEWAY",with:"UP,REJECT,GATEWAY"),
                        route.replacingOccurrences(of:"1500",with:"1400"),
                        route.replacingOccurrences(of:"0         0         0        20",with:"1         0         0        20"),
                        route.replacingOccurrences(of:"0         0         0        20",with:"0         1         0        20"),
                        route.replacingOccurrences(of:"5         0      1500",with:"5         1      1500")] {
            #expect(try original != RouteEvidence.canonical(changed))
        }
        let locked=route.replacingOccurrences(of:"20         5",with:"20L         5")
        #expect(try RouteEvidence.canonical(locked) != RouteEvidence.canonical(locked.replacingOccurrences(of:"20L",with:"21L")))
        #expect(try original != RouteEvidence.canonical(locked))
        let host=route.replacingOccurrences(of:"       mask: default\n",with:"")
        #expect(try original != RouteEvidence.canonical(host))
    }
    @Test func unknownAmbiguousAndMalformedRouteOutputIsRejected() {
        for bad in ["",route+"\n gateway: 172.21.128.1",route+"\n unknown: ignored",
                    route+"\n0 0 0 1 1 0 1500 90",route.replacingOccurrences(of:"1500       120",with:"1500"),
                    route.replacingOccurrences(of:"1500",with:"1500LL"),
                    route.replacingOccurrences(of:"1500",with:"18446744073709551616"),
                    route.replacingOccurrences(of:"1500",with:"-1"),
                    route.replacingOccurrences(of:"interface: en0",with:""),
                    route.replacingOccurrences(of:"recvpipe",with:"othermetric")] {
            reject {_ = try RouteEvidence.canonical(bad)}
        }
    }
}
