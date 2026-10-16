import Foundation
import GuardCore

public enum BannerTone {case protected,waiting,blocked}
extension AppModel {
    public var bannerTone:BannerTone {
        if !failure.isEmpty || state.phase=="recoveryBlocked" || interruptionAlert != nil {return .blocked}
        if !communicationWarning.isEmpty || (state.phase=="armed" && state.heartbeatDiagnostic?.delayed==true) {return .waiting}
        if state.phase=="armed" && state.verified {return .protected}
        if needsIPv6Off || guidance.severe || guidance.category=="IP 未匹配" {return .blocked}
        return .waiting
    }
    public var bannerTitle:String {
        switch bannerTone {
        case .protected:return "防护已验证，持续监控中"
        case .waiting:
            if !communicationWarning.isEmpty {return "助手状态响应延迟，正在重试"}
            if state.phase=="armed" {return "控制界面响应延迟，防护仍在运行"}
            return busy ? "正在验证，请稍候":"尚未启动防护，等待运行"
        case .blocked:return guidance.title
        }
    }
    public var blockCountText:String {
        guard let count=state.blockedPackets else{return "—"}
        return count.formatted()
    }
    public var blockCountCaption:String {
        if state.phase=="off" {return state.blockedPackets == nil ? "开启防护后统计":"上次会话 · 整机"}
        if state.blockedPackets==nil {return "统计暂不可用"}
        return state.phase=="armed" ? "本次会话 · 整机":"最后采样 · 整机"
    }
    public var blockCountHelp:String {
        "PF 实际丢弃的数据包数量，排除启动自检及此前流量。涵盖整机，不代表 Claude 的请求数或恶意行为；重传也会计数。正常代理流量不计入。最后采样："+(state.blockedPacketsAt ?? "暂无")
    }
    /// Two distinct services must agree recently; this only helps fill the expected egress.
    public var detectedEgress:String? {
        guard !ipStale,!testingIP,let check=ipCheck,Date().timeIntervalSince(check.startedAt)<120,
              Set(check.samples.map(\.service))==Set(["ipify","webshare"]),check.samples.count==2,
              let first=check.samples.first,IPv4.isPublic(first.ip),
              check.samples.allSatisfy({$0.error.isEmpty && $0.ip==first.ip}) else{return nil}
        return first.ip
    }
    public func useDetectedEgress() {
        guard !busy,state.phase=="off",let ip=detectedEgress else{return}
        settings.expectedEgress=ip
    }
}
