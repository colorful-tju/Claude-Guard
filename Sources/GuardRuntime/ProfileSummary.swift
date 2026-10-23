import Foundation

/// Display metadata only, never node registration or runtime evidence.
public struct ProfileSummary:Decodable,Sendable {
    public let nodeCount:Int?
    public let httpCount:Int?
    public let providerCount:Int?
    public let errorCode:String?
    public init(nodeCount:Int?=nil,httpCount:Int?=nil,providerCount:Int?=nil,errorCode:String?="unavailable") {
        self.nodeCount=nodeCount;self.httpCount=httpCount;self.providerCount=providerCount;self.errorCode=errorCode
    }
    public static func read(paths:[String],uid:UInt32,script:String,commands:Commands=Commands())->[ProfileSummary] {
        let unknown=Array(repeating:ProfileSummary(),count:paths.count)
        guard !paths.isEmpty,paths.count<=501 else{return unknown}
        // One bounded worker for the entire picker, never one process per file.
        // The same descriptor/owner/type checks as registration protect file reads.
        var budget=8_000_000
        let rows:[String?]=paths.map{path in
            guard budget>0,let bytes=try? ProxyConfiguration.bytes(path:path,uid:uid) else{return nil}
            guard bytes.count<=budget else{budget=0;return nil}
            budget-=bytes.count
            return String(data:bytes,encoding:.utf8)
        }
        do {
            let input=try JSONEncoder().encode(rows)
            let result=try commands.run("/usr/bin/ruby",[script],timeout:5,input:input)
            guard result.status==0 else{return unknown}
            let values=try JSONDecoder().decode([ProfileSummary].self,from:Data(result.output.utf8))
            guard values.count==paths.count else{return unknown}
            return values.map{value in
                guard value.errorCode==nil,let total=value.nodeCount,let http=value.httpCount,let providers=value.providerCount,
                      (0...100_000).contains(total),(0...total).contains(http),(0...100_000).contains(providers) else{return ProfileSummary()}
                return value
            }
        }catch{return unknown}
    }
}
