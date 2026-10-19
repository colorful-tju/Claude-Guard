import Foundation
import GuardRuntime

/// Presentation only: never grants verification or relaxes daemon checks.
public struct Guidance:Equatable {
    public let category:String,title:String,action:String
    public let severe:Bool
    public init(_ category:String,_ title:String,_ action:String,severe:Bool=false){self.category=category;self.title=title;self.action=action;self.severe=severe}
    public static func reason(_ raw:String)->Guidance {
        if raw.contains("IPv6 default route detected") {
            return .init("需要操作","当前 IPv6 路径不受本版支持","保持 OFF，退出 Claude/Code，点击「临时 IPv6 · 关闭」后重新验证。")
        }
        if raw.contains("Probe worker failed at dual-https") {
            return .init("启动核验失败","防护开启后的 HTTPS 出口未能完成核验","查看下方 ipify / webshare 错误详情并导出反馈；尚未证明泄漏，不要放宽防护规则。",severe:true)
        }
        if raw.contains("Periodic egress mismatch") {
            return .init("出口异常","检测到非预期公网出口，已停止会话","核对节点与预期 IP；原始检测地址保存在反馈中。未单凭此判定国内 IP 已泄漏。",severe:true)
        }
        if raw.contains("Periodic egress retry limit") || raw.contains("Periodic egress proof expired") {
            return .init("核验中断","出口核验持续失败或超过时限","已保守停止 Claude。请检查代理连通性并导出反馈；这不等于检测到了不同 IP。")
        }
        if raw.contains("Expected egress mismatch") || raw.contains("Periodic egress") {
            return .init("网络未通过","出口不匹配或检测服务无法完成核验","检查 已登记代理 节点及 IP 检测结果；网络稳定后重新验证。未据此认定已泄漏。")
        }
        if raw.contains("routeFingerprint") || raw.contains("premises changed") || raw.contains("epoch") || raw.contains("Runtime changed") {
            return .init("保护条件变化","网络前提发生变化，防护验证已失效","确认 已登记代理/TUN 与当前网络稳定，再重新验证；详细差异保留在日志。")
        }
        if raw.contains("Incomplete runtime node, process, interface or TUN evidence") {
            return .init("保护条件待核验","运行态证据不再满足防护要求","这不等于已确认虚拟网卡变动或 IP 泄漏。请导出记录检查具体差异，再重新验证。")
        }
        if raw.contains("Socket inventory") || raw.contains("Socket owner identity") {
            return .init("检测异常","代理进程连接信息未能完整核验","连接变化或系统读取失败均可能触发；未据此认定泄漏。请稍后重新验证，反复出现时导出反馈。")
        }
        if raw.contains("Unique registered proxy Core") || raw.contains("TUN") {
            return .init("需要操作","尚未确认 已登记代理 的虚拟网卡","手动准备 已登记代理、HTTP 节点与 TUN，然后重新检测配置。")
        }
        if raw.contains("Provider endpoint confirmation") {
            return .init("需要操作","当前端点尚未确认或配置已改变","重新检测配置，核对服务商网关与端口，再点击「确认代理端点」。")
        }
        if raw.contains("heartbeat") {
            return .init("会话中断","启动器通信超时，已保守结束防护会话","不是已确认泄漏。保持启动器运行；恢复完成后重试，反复出现请导出反馈。")
        }
        if raw.contains("UI process") || raw.contains("sleep/wake") {
            return .init("会话中断","启动器心跳中断或电脑发生睡眠唤醒","保持启动器运行；确认恢复完成后重新验证。")
        }
        if raw.contains("deadline") || raw.contains("timeout") {
            return .init("检测异常","检测步骤超时，尚未完成验证","先点离线自检；再次失败时导出反馈，不要连续重试启动。",severe:true)
        }
        if raw.contains("inventory") || raw.contains("identity unreadable") {
            return .init("检测异常","进程信息未能完整读取","稍后重新检测配置；反复出现请导出反馈。",severe:true)
        }
        if raw.contains("IPC") || raw.contains("助手") {
            return .init("程序异常","无法确认助手状态","先关闭防护；仍失败请导出反馈并按手册使用恢复工具。",severe:true)
        }
        return .init("检测异常","本次操作未完成，原因需要进一步检查","请查看下方原始详情并导出反馈；不要将此提示视为已发生泄漏。",severe:true)
    }
    public static func current(_ state:Status,failure:String,busy:Bool,confirmation:Bool,ip:IPCheck?,stale:Bool)->Guidance {
        if state.phase=="recoveryBlocked" {return .init("需要处理","恢复受阻：Claude 退出或网络恢复尚未确认","先点击「关闭防护」；无效时按手册执行独立恢复。",severe:true)}
        if busy {return .init("正在执行","正在执行指令，请稍候","下方持续显示实际阶段；需要取消时点击「关闭防护」。")}
        if !failure.isEmpty {return reason(failure)}
        if state.verified && state.phase=="armed" {return .init("防护运行","防护已验证，持续监控中","保持 已登记代理 与启动器运行；结束使用后点击「关闭防护」。")}
        if let event=state.interruption,state.lastRisk==event.reason {
            let detail=reason(event.reason)
            return .init("自动停止",event.exitConfirmed ? "启动器已关闭 Claude":event.requestedClaudeStop ? "已请求关闭 Claude，退出尚未确认":"启动器已结束防护验证",detail.title+"；"+detail.action,severe:true)
        }
        if state.message.contains("rejected(") || state.message.contains("unsupported(") {return reason(state.message)}
        if !state.processInventoryComplete {return .init("需要检查","进程状态尚未完整确认","点击「重新检测配置」；有读取错误时查看日志并反馈。")}
        if state.fingerprint.isEmpty || !confirmation {return .init("需要操作","请先核对并确认代理端点","重新检测配置，核对网关和预期出口，再点击「确认代理端点」。")}
        if let ip,!stale,!ip.matches {return .init("IP 未匹配","当前 IP 检测未通过","核对当前节点与预期出口，再点击检测 IP；此信息不是泄漏判定。")}
        return .init("待启动","准备就绪，可开始防护验证","点击「仅验证防护」或「安全启动 Claude」；IPv6 临时关闭本身不是错误。")
    }
}
