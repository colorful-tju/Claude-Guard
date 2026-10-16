import Foundation

/// Strict identity of the route, excluding only unlocked TCP slow-start/RTT/rttvar/expiry statistics.
public enum RouteEvidence {
    public static func canonical(_ output:String) throws -> String {
        let columns=["recvpipe","sendpipe","ssthresh","rtt,msec","rttvar","hopcount","mtu","expire"]
        let required:Set<String>=["route to","destination","gateway","interface","flags"]
        let allowed=required.union(["mask"])
        var fields:[String:String]=[:],metrics:[String]=[];var header=false,finished=false
        for line in output.components(separatedBy:.newlines) {
            let text=line.trimmingCharacters(in:.whitespaces)
            if text.isEmpty {continue}
            guard !finished else{throw fail("Unexpected extra route output")}
            let tokens=text.split(whereSeparator:{$0.isWhitespace}).map(String.init)
            if tokens==columns {
                guard !header else{throw fail("Duplicate route metric header")}
                header=true;continue
            }
            if header {
                guard tokens.count==columns.count else{throw fail("Malformed route metric row")}
                for (index,token) in tokens.enumerated() {
                    let locked=token.hasSuffix("L"),number=locked ? String(token.dropLast()):token
                    guard let value=Int64(number),index==7 || value>=0,
                          number.utf8.allSatisfy({(48...57).contains($0) || (index==7 && $0==45)}) else{throw fail("Unknown route metric or lock format")}
                    // Preserve every lock and all configured/path metrics. Locked RTT is a premise.
                    let volatile=[2,3,4,7].contains(index) && !locked
                    metrics.append("\(columns[index])=\(volatile ? "dynamic":String(value))\(locked ? "L":"")")
                }
                finished=true;continue
            }
            guard let colon=text.firstIndex(of:":") else{throw fail("Unknown route field")}
            let key=String(text[..<colon]),value=String(text[text.index(after:colon)...]).trimmingCharacters(in:.whitespaces)
            guard allowed.contains(key),fields[key]==nil,!value.isEmpty else{throw fail("Unknown, duplicate or empty route field")}
            fields[key]=value
        }
        guard finished,required.isSubset(of:Set(fields.keys)) else{throw fail("Incomplete route identity")}
        return fields.keys.sorted().map{"\($0)=\(fields[$0]!)"}.joined(separator:"\n")+"\n"+metrics.joined(separator:"\n")
    }
    public static func canonical(_ result:CommandResult) throws -> String {
        guard result.status==0,result.error.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("IPv4 route evidence unavailable (exit=\(result.status), stderr=\(String(reflecting:String(result.error.prefix(200)))))")}
        return try canonical(result.output)
    }
    public static func read(_ arguments:[String],commands:Commands) throws -> String {
        let result=try commands.run("/sbin/route",arguments)
        _=try canonical(result)
        return result.output
    }
}
