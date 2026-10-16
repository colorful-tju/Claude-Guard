import Foundation
import GuardCore
public enum BootRecovery:Equatable,Sendable {case sameBoot,clearRebootedSession}
public enum RecoverySafety {
    public static func bootDecision(recorded:String,current:String,anchorEmpty:Bool,oldTokenPresent:Bool) throws -> BootRecovery {
        guard UUID(uuidString:recorded) != nil,UUID(uuidString:current) != nil else{throw fail("Boot identity is unknown")}
        if recorded==current{return .sameBoot}
        guard anchorEmpty,!oldTokenPresent else{throw fail("Different boot: old token ownership is invalid; never release a colliding token")}
        return .clearRebootedSession
    }
}
extension Status {
    public mutating func ipcUnavailable() {
        phase="unverified";verified=false;udp="无法核验";monitor="助手失联，观测状态未确认"
        message="助手通信失败；防护状态未确认，请勿启动 Claude，按手册恢复"
    }
}
