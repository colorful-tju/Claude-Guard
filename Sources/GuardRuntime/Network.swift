import Foundation
import Darwin
import GuardCore
import NativeGuard
public enum MVPNetworkRequirements {
    public static func validate(ipv6Routable:Bool) throws {
        guard !ipv6Routable else{throw GuardFailure.unsupported("IPv6 default route detected; this MVP does not support real IPv6 path validation")}
    }
}
public struct NetworkView: Sendable {
    public var interfaces:[InterfaceIdentity];public var detail:String;public var physical:InterfaceIdentity;public var tun:InterfaceIdentity
    public var ipv6Routable:Bool
}
public final class NetworkEvents: @unchecked Sendable {
    private let lock=NSLock();private var generation:UInt64=1;private var failed=false
    private let routeQueue=DispatchQueue(label:"guard.route-events")
    private var source:DispatchSourceRead?;private var fd:Int32 = -1
    public init() throws {
        fd=csg_route_open();guard fd>=0 else{throw fail("Route-event monitor unavailable")}
        let s=DispatchSource.makeReadSource(fileDescriptor:fd,queue:routeQueue);source=s
        s.setEventHandler {[weak self] in self?.drain()}
        s.resume()
    }
    private func drain(){
        while true {let r=csg_route_read(fd);if r==0{break};if r==2{continue};lock.lock();generation += 1;if r<0{failed=true};lock.unlock();if r<0{break}}
    }
    public func epoch() throws -> UInt64 {routeQueue.sync{drain()};lock.lock();defer{lock.unlock()};guard !failed else{throw fail("Route events lost")};return generation}
    deinit {source?.cancel();if fd>=0{close(fd)}}
}
public enum Networks {
    public static func ipv6DefaultPresence(_ result:CommandResult) throws -> Bool {
        let out=result.output.trimmingCharacters(in:.whitespacesAndNewlines)
        let error=result.error.trimmingCharacters(in:.whitespacesAndNewlines)
        // macOS route may exit 0 even when RTM_GET reports ENOENT on stderr.
        // Absence requires the exact diagnostic AND empty stdout, not exit alone.
        if [Int32(0),1].contains(result.status),out.isEmpty,["route: writing to routing socket: not in table","route: writing to routing socket: No such process"].contains(error){return false}
        guard result.status==0,error.isEmpty else{throw fail("IPv6 default-route evidence unavailable (exit=\(result.status), stdout=\(String(reflecting:String(out.prefix(200)))), stderr=\(String(reflecting:String(error.prefix(200)))))")}
        let lines=out.components(separatedBy:.newlines).map{$0.trimmingCharacters(in:.whitespaces)}
        let route=lines.filter{$0.hasPrefix("route to:")},destination=lines.filter{$0.hasPrefix("destination:")}
        let interfaces=lines.filter{$0.hasPrefix("interface:")}
        guard route==["route to: ::"],destination==["destination: ::"],lines.filter({$0=="mask: default"}).count==1,
              interfaces.count==1,let name=interfaces[0].split(whereSeparator:{$0.isWhitespace}).last,
              !name.isEmpty,name.utf8.allSatisfy({(65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)}) else{throw fail("Unknown IPv6 default-route output")}
        return true
    }
    public static func read(physicalName:String,tunName:String,epoch:UInt64,commands:Commands) throws -> NetworkView {
        var head:UnsafeMutablePointer<ifaddrs>?;guard getifaddrs(&head)==0,let start=head else{throw fail("Interface inventory unavailable")};defer{freeifaddrs(head)}
        var rows:[String:(UInt32,[String],UInt32)] = [:];var p:UnsafeMutablePointer<ifaddrs>?=start
        while let item=p {defer{p=item.pointee.ifa_next};let name=String(cString:item.pointee.ifa_name);let idx=if_nametoindex(name)
            var row=rows[name] ?? (idx,[],item.pointee.ifa_flags)
            if let addr=item.pointee.ifa_addr {
                var host=[CChar](repeating:0,count:1025)
                if [AF_INET,AF_INET6].contains(Int32(addr.pointee.sa_family)),getnameinfo(addr,socklen_t(addr.pointee.sa_len),&host,socklen_t(host.count),nil,0,NI_NUMERICHOST)==0 {row.1.append(String(cString:host))}
            }
            rows[name]=row
        }
        let identities=rows.keys.sorted().map{InterfaceIdentity(name:$0,index:rows[$0]!.0,generation:epoch,ipv4:rows[$0]!.1.filter{IPv4.octets($0) != nil}.sorted().first ?? "0.0.0.0")}
        guard let physical=identities.first(where:{$0.name==physicalName}),let tun=identities.first(where:{$0.name==tunName}),
              physical.ipv4 != "0.0.0.0",tun.ipv4 != "0.0.0.0",
              (rows[physicalName]!.2 & UInt32(IFF_UP)) != 0,(rows[tunName]!.2 & UInt32(IFF_UP)) != 0 else{throw fail("Verified physical/TUN interface is not up with IPv4")}
        let gatewayRoute=try RouteEvidence.read(["-n","get","1.1.1.1"],commands:commands)
        guard gatewayRoute.components(separatedBy:.newlines).contains(where:{$0.trimmingCharacters(in:.whitespaces)=="interface: \(tunName)"}) else{throw fail("Public IPv4 route is not on the Core-owned TUN")}
        let v6=try commands.run("/sbin/route",["-n","get","-inet6","default"])
        let ipv6Present=try ipv6DefaultPresence(v6)
        let detail=rows.keys.sorted().map{"\($0):\(rows[$0]!.0):\(rows[$0]!.2):\(rows[$0]!.1.sorted().joined(separator:","))"}.joined(separator:"\n")+"\n"+(try RouteEvidence.canonical(gatewayRoute))+"\n"+(ipv6Present ? v6.output : "confirmed-no-ipv6-default")
        return .init(interfaces:identities,detail:detail,physical:physical,tun:tun,ipv6Routable:ipv6Present)
    }
}
