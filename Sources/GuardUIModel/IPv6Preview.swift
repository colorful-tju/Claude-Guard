import Foundation
import GuardRuntime

public struct IPv6Preview:Sendable {
    public var hasDefaultRoute:Bool?
    public var checkedAt:Date
    public var detail:String
    public init(hasDefaultRoute:Bool?,checkedAt:Date=Date(),detail:String=""){self.hasDefaultRoute=hasDefaultRoute;self.checkedAt=checkedAt;self.detail=detail}
    public var isFresh:Bool {Date().timeIntervalSince(checkedAt)<12}
    public static func read()->IPv6Preview {
        do {
            let result=try Commands().run("/sbin/route",["-n","get","-inet6","default"],timeout:2)
            return .init(hasDefaultRoute:try Networks.ipv6DefaultPresence(result))
        }catch{return .init(hasDefaultRoute:nil,detail:String(describing:error))}
    }
}
