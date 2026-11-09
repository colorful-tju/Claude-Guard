import Foundation
import GuardCore

// Only absence is retryable. A present but inconsistent connection remains fatal.
public struct GatewaySocketUnavailable:Error,CustomStringConvertible {
    public let physicalAddress:String
    public init(physicalAddress:String){self.physicalAddress=physicalAddress}
    public var description:String {"No verified Core ESTABLISHED gateway TCP socket uses physical address \(physicalAddress) (no established candidate observed)"}
}

public enum GatewayRoute {
    public static func read(physical:String,gateway:String,commands:Commands) throws -> String {
        // This reads an available scoped path, not the socket's binding option.
        // Verified Core metadata and later PF/probe checks are separate ARMED gates.
        try RouteEvidence.read(["-n","get","-ifscope",physical,gateway],commands:commands)
    }
    public static func select(route:String,physical:InterfaceIdentity,owner:ProcessIdentity,
                              gateway:String,port:UInt16,connections:[CoreConnection]) throws -> CoreConnection {
        func value(_ key:String) throws -> String {
            let prefix=key+":"
            let rows=route.components(separatedBy:.newlines).map{$0.trimmingCharacters(in:.whitespaces)}.filter{$0.hasPrefix(prefix)}
            guard rows.count==1 else{throw fail("Scoped gateway route missing or ambiguous: \(key)")}
            let result=String(rows[0].dropFirst(prefix.count)).trimmingCharacters(in:.whitespaces)
            guard !result.isEmpty else{throw fail("Scoped gateway route field empty: \(key)")}
            return result
        }
        guard try value("route to")==gateway else{throw fail("Scoped gateway route destination mismatch")}
        guard try value("interface")==physical.name else{throw fail("Scoped gateway route is not on verified physical interface \(physical.name)")}
        let candidates=connections.filter{
            $0.owner==owner && $0.established && $0.gateway==gateway && $0.port==port &&
            $0.localAddress==physical.ipv4 && $0.localPort>0
        }
        if connections.isEmpty {throw GatewaySocketUnavailable(physicalAddress:physical.ipv4)}
        guard let selected=candidates.sorted(by:{$0.localPort<$1.localPort}).first else{
            throw fail("No verified Core ESTABLISHED gateway TCP socket uses physical address \(physical.ipv4)")
        }
        return selected
    }
}
