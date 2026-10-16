import Foundation
import GuardCore

public enum BannerTone {case protected,waiting,blocked}
extension AppModel {
    public var bannerTone:BannerTone {
        if !failure.isEmpty || state.phase=="recoveryBlocked" || interruptionAlert != nil {return .blocked}
        if state.phase=="armed" && state.verified {return .protected}
        if needsIPv6Off || guidance.severe || guidance.category=="IP 未匹配" {return .blocked}
        return .waiting
    }
    public var bannerTitle:String {
        switch bannerTone {
        case .protected:return "防护已验证，持续监控中"
        case .waiting:return busy ? "正在验证，请稍候":"尚未启动防护，等待运行"
        case .blocked:return guidance.title
        }
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
