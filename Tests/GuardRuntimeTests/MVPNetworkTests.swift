import Testing
@testable import GuardRuntime
struct MVPNetworkTests {
    @Test func macOSNoRouteDiagnosticCanHaveZeroExitStatus() throws {
        // Read-only /sbin/route get on absent scoped IPv6 defaults on this Mac:
        // exit 0, empty stdout, exact ENOENT diagnostic on stderr.
        for status:Int32 in [0,1] {
            for diagnostic in ["route: writing to routing socket: not in table",
                               "route: writing to routing socket: No such process"] {
                #expect(try !Networks.ipv6DefaultPresence(.init(output:"",error:diagnostic+"\n",status:status)))
            }
        }
    }
    @Test func noRouteTextMustNotAuthorizeAmbiguousOrFailedQueries() throws {
        let missing="route: writing to routing socket: not in table\n"
        let present="   route to: ::\ndestination: ::\n       mask: default\n  interface: en0\n"
        for unknown in [CommandResult(output:"",error:"Operation not permitted",status:0),
                        .init(output:"",error:missing,status:2),
                        .init(output:present,error:missing,status:0),
                        .init(output:"unexpected output",error:missing,status:0),
                        .init(output:"",error:missing+"additional error\n",status:0),
                        .init(output:"",error:missing+missing,status:0),
                        .init(output:"",error:"",status:0)] {
            reject {_ = try Networks.ipv6DefaultPresence(unknown)}
        }
    }
    @Test func unavailableRouteEvidenceReportsExitAndDiagnostic() {
        do {
            _ = try Networks.ipv6DefaultPresence(.init(output:"",error:"Operation not permitted",status:0))
            Issue.record("Permission failure must not be accepted")
        } catch {
            let message=String(describing:error)
            #expect(message.contains("exit=0"))
            #expect(message.contains("stdout="))
            #expect(message.contains("stderr="))
            #expect(message.contains("Operation not permitted"))
        }
    }
    @Test func ipv6DefaultRouteIsRejectedByReadOnlyMVPPreflight() throws {
        try MVPNetworkRequirements.validate(ipv6Routable:false)
        reject {try MVPNetworkRequirements.validate(ipv6Routable:true)}
    }
    @Test func ipv6RouteErrorsCannotMasqueradeAsConfirmedAbsence() throws {
        let present="   route to: ::\ndestination: ::\n       mask: default\n  interface: en0\n"
        #expect(try Networks.ipv6DefaultPresence(.init(output:present,error:"",status:0)))
        #expect(try !Networks.ipv6DefaultPresence(.init(output:"",error:"route: writing to routing socket: not in table\n",status:1)))
        for unknown in [CommandResult(output:"",error:"Operation not permitted",status:1),
                        .init(output:"",error:"",status:1),.init(output:"",error:"",status:0),
                        .init(output:"interface: en0\n",error:"",status:0),
                        .init(output:present,error:"warning",status:0)] {
            reject {_ = try Networks.ipv6DefaultPresence(unknown)}
        }
    }
}
