import Foundation
import Darwin
import GuardCore
import NativeGuard

/// Only an exact Core-owned interface can receive the DNS-only exception.
/// Nothing here changes routes, DNS settings or the proxy configuration.
struct UDPDNSTUN:Equatable {
    let name:String
    let index:UInt32
    let address:String
    let core:ProcessIdentity
}

extension Inspector {
    func udpDNSTUN() throws -> UDPDNSTUN? {
        let cores=NativeProcesses.inventory().records.filter {
            $0.path==installation.registeredCorePath && ($0.uid==0 || $0.uid==installation.uid)
        }
        if cores.isEmpty {return nil}
        guard cores.count==1,let core=cores.first else{throw fail("UDP DNS: registered Core identity ambiguous")}
        try verifyProcess(core,expectedHash:installation.coreHash)
        var tuns=Set<String>()
        for var socket in try NativeProcesses.sockets(core.pid) {
            let name=NativeProcesses.text(&socket.tun)
            if !name.isEmpty {tuns.insert(name)}
        }
        if tuns.isEmpty {return nil}
        guard tuns.count==1,let name=tuns.first else{throw fail("UDP DNS: cannot attribute a unique TUN")}
        _=try UDPOnlyPolicy(physical:"en0",dnsTUN:name)
        var head:UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head)==0 else{throw fail("UDP DNS: interface read failed")}
        defer{freeifaddrs(head)}
        var p=head,addresses=Set<String>()
        while let item=p {
            defer{p=item.pointee.ifa_next}
            guard String(cString:item.pointee.ifa_name)==name,item.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  let addr=item.pointee.ifa_addr,Int32(addr.pointee.sa_family)==AF_INET else{continue}
            var host=[CChar](repeating:0,count:1025)
            guard getnameinfo(addr,socklen_t(addr.pointee.sa_len),&host,socklen_t(host.count),nil,0,NI_NUMERICHOST)==0 else{throw fail("UDP DNS: address read failed")}
            addresses.insert(String(cString:host))
        }
        let index=if_nametoindex(name),after=try NativeProcesses.record(core.pid)
        guard index>0,addresses.count==1,let address=addresses.first,
              after.identity==core.identity else{throw fail("UDP DNS: Core/TUN changed during collection")}
        var identity=core.identity;identity.executableIdentity=installation.coreHash
        return .init(name:name,index:index,address:address,core:identity)
    }
}
