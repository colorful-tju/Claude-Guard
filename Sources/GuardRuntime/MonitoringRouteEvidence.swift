import Foundation
import Darwin
import GuardCore

/// Runtime-only equivalence. Startup continues to compare the untouched full route fingerprint.
/// Never updates the ARMED baseline, PF policy or interface allowlist.
enum MonitoringRouteEvidence {
    static func comparison(_ current:LocalSnapshot,baseline:LocalSnapshot,currentRoutes:String,
                           baselineRoutes:String,policy:GuardPolicy) -> LocalSnapshot {
        guard current.routeFingerprint != baseline.routeFingerprint,
              current.routeFingerprint==hash(Data(currentRoutes.utf8)),
              baseline.routeFingerprint==hash(Data(baselineRoutes.utf8)),
              current.verifiedTun==policy.tun,baseline.verifiedTun==policy.tun,
              current.tunRuntimeVerified,baseline.tunRuntimeVerified,
              let before=split(baselineRoutes),let after=split(currentRoutes),
              equivalentInventory(before.prefix,after.prefix),equivalentGatewaySections(before.suffix,after.suffix),
              equivalent(before.route,after.route,tun:policy.tun) else{return current}
        var compared=current;compared.routeFingerprint=baseline.routeFingerprint
        return compared
    }
    /// Only an ARMED session may revalidate a routing-table notification. Keep
    /// the immutable baseline, interface lifetimes, PF rules and all other gates.
    static func revalidated(_ current:LocalSnapshot,baseline:LocalSnapshot,currentRoutes:String,
                            baselineRoutes:String,policy:GuardPolicy) -> LocalSnapshot {
        let compared=comparison(current,baseline:baseline,currentRoutes:currentRoutes,baselineRoutes:baselineRoutes,policy:policy)
        guard current.epoch != baseline.epoch,
              current.routeFingerprint==hash(Data(currentRoutes.utf8)),
              baseline.routeFingerprint==hash(Data(baselineRoutes.utf8)) else{return compared}
        var candidate=compared;candidate.epoch=baseline.epoch
        do {try MonitoringGate.validate(candidate,baseline:baseline,policy:policy);return candidate}
        catch {return compared}
    }
    // Runtime-only: preserve names, indices, flags, all other interfaces and
    // every non-link-local address. This does not authorize auxiliary traffic.
    private static func equivalentInventory(_ a:String,_ b:String)->Bool {
        func normalized(_ text:String)->String {
            text.components(separatedBy:"\n").map { line in
                let fields=line.split(separator:":",maxSplits:3,omittingEmptySubsequences:false)
                guard fields.count==4,NetworkEvents.isAuxiliaryInterface(String(fields[0])) else{return line}
                let name=String(fields[0])
                let addresses=fields[3].split(separator:",",omittingEmptySubsequences:false).filter { entry in
                    let parts=entry.split(separator:"%",omittingEmptySubsequences:false)
                    guard parts.count==2,parts[1]==name else{return true}
                    var address=in6_addr()
                    guard String(parts[0]).withCString({inet_pton(AF_INET6,$0,&address)})==1 else{return true}
                    return withUnsafeBytes(of:address){!($0[0]==0xfe && ($0[1]&0xc0)==0x80)}
                }
                return fields.prefix(3).joined(separator:":")+":"+addresses.joined(separator:",")
            }.joined(separator:"\n")
        }
        return normalized(a)==normalized(b)
    }
    private struct Detail {let prefix:String;let route:String;let suffix:String}
    private static func split(_ detail:String) -> Detail? {
        // Networks.read emits one public route after interface inventory. Require the
        // exact no-IPv6 delimiter, preserving ALL other routes and inventory byte-for-byte.
        let end="\nconfirmed-no-ipv6-default\nordinary-gateway-route\n"
        let parts=detail.components(separatedBy:end)
        guard parts.count==2,!parts[1].isEmpty,
              parts[1].components(separatedBy:"\nphysical-scoped-gateway-route\n").count==2,
              let start=parts[0].range(of:"\ndestination="),start.lowerBound>parts[0].startIndex else{return nil}
        return Detail(prefix:String(parts[0][..<start.lowerBound]),
                      route:String(parts[0][parts[0].index(after:start.lowerBound)...]),suffix:end+parts[1])
    }
    private static let routeKeys=["destination","flags","gateway","interface","mask","route to"]
    private static let metrics=["recvpipe","sendpipe","ssthresh","rtt,msec","rttvar","hopcount","mtu","expire"]
    private static func fields(_ text:String) -> [String:String]? {
        var values:[String:String]=[:]
        for line in text.components(separatedBy:"\n") {
            let pair=line.components(separatedBy:"=")
            guard pair.count==2,!pair[1].isEmpty,values[pair[0]]==nil,
                  (routeKeys+metrics).contains(pair[0]) else{return nil}
            values[pair[0]]=pair[1]
        }
        let required=Set(routeKeys.filter{$0 != "mask"}+metrics)
        guard required.isSubset(of:Set(values.keys)) else{return nil}
        let ordered=routeKeys.filter{values[$0] != nil}+metrics
        guard ordered.map({"\($0)=\(values[$0]!)"}).joined(separator:"\n")==text else{return nil}
        for key in metrics {
            let value=values[key]!
            if ["ssthresh","rtt,msec","rttvar","expire"].contains(key),value=="dynamic" {continue}
            let number=value.hasSuffix("L") ? String(value.dropLast()):value
            guard let parsed=Int64(number),parsed>=0,String(parsed)==number else{return nil}
        }
        return values
    }
    // TCP updates unlocked slow-start cache values without changing the route.
    // Preserve locked values, all route/path fields, and all other metrics.
    private static func runtimeFields(_ text:String)->[String:String]? {
        guard var values=fields(text) else{return nil}
        if let value=values["ssthresh"],!value.hasSuffix("L") {values["ssthresh"]="dynamic"}
        return values
    }
    private static func equivalentGatewaySections(_ a:String,_ b:String)->Bool {
        let marker="\nconfirmed-no-ipv6-default\nordinary-gateway-route\n"
        guard a.hasPrefix(marker),b.hasPrefix(marker) else{return false}
        let left=String(a.dropFirst(marker.count)).components(separatedBy:"\nphysical-scoped-gateway-route\n")
        let right=String(b.dropFirst(marker.count)).components(separatedBy:"\nphysical-scoped-gateway-route\n")
        guard left.count==2,right.count==2 else{return false}
        return zip(left,right).allSatisfy { x,y in
            guard let p=runtimeFields(x),let q=runtimeFields(y) else{return false}
            return p==q
        }
    }
    private static func equivalent(_ left:String,_ right:String,tun:InterfaceIdentity) -> Bool {
        guard var a=runtimeFields(left),var b=runtimeFields(right),
              a["route to"]=="1.1.1.1",b["route to"]=="1.1.1.1",
              a["interface"]==tun.name,b["interface"]==tun.name,
              a["gateway"]==tun.ipv4,b["gateway"]==tun.ipv4 else{return false}
        if a==b {return true}
        let parentFlags="<UP,GATEWAY,DONE,STATIC,PRCLONING>"
        let cloneFlags="<UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF>"
        func parent(_ fields:[String:String])->Bool {
            guard fields["flags"]==parentFlags,let destination=fields["destination"],let mask=fields["mask"],
                  let d=address(destination),let m=address(mask),let target=address("1.1.1.1"),
                  m != 0,m != UInt32.max else{return false}
            let inverse = ~m
            return inverse & (inverse &+ 1)==0 && d & m==d && target & m==d
        }
        func clone(_ fields:[String:String])->Bool {
            fields["flags"]==cloneFlags && fields["destination"]=="1.1.1.1" && fields["mask"]==nil
        }
        guard (parent(a) && clone(b)) || (clone(a) && parent(b)) else{return false}
        for key in ["destination","mask","flags"] {a.removeValue(forKey:key);b.removeValue(forKey:key)}
        return a==b
    }
    private static func address(_ text:String)->UInt32? {
        guard let octets=IPv4.octets(text) else{return nil}
        return octets.reduce(UInt32(0)){($0<<8)|UInt32($1)}
    }
}
