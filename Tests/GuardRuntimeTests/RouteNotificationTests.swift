import Testing
@testable import GuardRuntime

struct RouteNotificationTests {
    @Test func routingEventsDoNotPretendInterfacesWereRecreated() {
        var gate=RouteNotificationGate(initial:[12:"same"])
        for type:UInt32 in [1,2,3] {
            let invalidates=gate.invalidates(type:type,index:0,signature:"route");#expect(invalidates)
            #expect(gate.identityGeneration==1)
        }
        let duplicate=gate.invalidates(type:14,index:12,signature:"same");#expect(!duplicate)
        #expect(gate.identityGeneration==1)
        for type:UInt32 in [6,12,13,18,255] {
            let before=gate.identityGeneration
            let invalidates=gate.invalidates(type:type,index:12,signature:"changed");#expect(invalidates)
            #expect(gate.identityGeneration==before+1)
        }
    }

    @Test func repeatedInformationDoesNotInvalidateInterfaceIdentity() {
        var gate=RouteNotificationGate(initial:[12:"same",19:"tun"])
        let result1 = !gate.invalidates(type:14,index:12,signature:"same"); #expect(result1)
        let result2 = !gate.invalidates(type:14,index:19,signature:"tun"); #expect(result2)
        let result3=gate.invalidates(type:14,index:12,signature:"down"); #expect(result3)
        // A down/up transition cannot be erased by a matching final snapshot.
        let result4=gate.invalidates(type:14,index:12,signature:"same"); #expect(result4)
    }
    @Test func unknownOrAddressAndRouteChangesRemainConservative() {
        var gate=RouteNotificationGate(initial:[12:"same"])
        let result5=gate.invalidates(type:14,index:20,signature:"new"); #expect(result5)
        let result6=gate.invalidates(type:14,index:12,signature:""); #expect(result6)
        for type in [1,2,3,6,12,13,18,255] {
            let result7=gate.invalidates(type:UInt32(type),index:12,signature:"same"); #expect(result7)
        }
    }
}
