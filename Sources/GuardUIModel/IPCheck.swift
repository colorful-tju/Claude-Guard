import Foundation
import GuardRuntime
import GuardCore

public struct IPSample:Codable,Sendable,Identifiable {
    public var id:String{service}
    public let service:String,ip:String,error:String,measuredAt:Date
}
public struct IPCheck:Codable,Sendable {
    public let expected:String,samples:[IPSample],startedAt:Date
    public var matches:Bool {samples.count==2 && IPv4.isPublic(expected) && samples.allSatisfy{$0.error.isEmpty && $0.ip==expected}}
    /// Informational IPv4 evidence only. Never changes the PF session or its verification bit.
    public static func run(expected:String,fetch:@escaping @Sendable (EgressService)throws->String = {try ProbeExecutor.egress(service:$0,commands:Commands())}) async -> IPCheck {
        let started=Date()
        let values=await withTaskGroup(of:IPSample.self){group in
            for service in EgressService.allCases {
                group.addTask {
                    do {let ip=try fetch(service);guard IPv4.isPublic(ip) else{throw fail("Invalid IPv4 response")}
                        return IPSample(service:service.rawValue,ip:ip,error:"",measuredAt:Date())
                    }catch{return IPSample(service:service.rawValue,ip:"",error:"HTTPS IPv4 检测失败或超时",measuredAt:Date())}
                }
            }
            var rows:[IPSample]=[];for await value in group{rows.append(value)}
            return rows.sorted{$0.service<$1.service}
        }
        return .init(expected:expected,samples:values,startedAt:started)
    }
}
