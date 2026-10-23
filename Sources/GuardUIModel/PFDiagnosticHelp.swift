import Foundation

/// Presentation only. No repair command is executed and no guard gate changes.
public struct PFDiagnosticHelp:Sendable {
    public let title:String
    public let steps:String
    public let readOnlyCommand="sudo /bin/bash '/Applications/ClaudeSafeLauncher.app/Contents/Resources/scripts/capture-pf-environment.sh'"
    public init?(reason:String) {
        if reason.contains("PF display failed") {
            title="无法完整读取防火墙规则"
            steps="这不是已确认规则冲突或 IP 泄漏。\n1. 导出反馈，复制下方只读诊断命令，在终端运行并保留输出。\n2. 不要清空规则或停用整个 PF 来通过检查。\n3. 若恢复受阻，先使用恢复工具；保持 OFF 后再检查助手权限与安装状态。"
        } else if reason.contains("PF anchor inventory changed") || reason.contains("PF Internet Sharing inventory changed") {
            title="检查期间共享/防火墙规则发生变化"
            steps="1. 保持 OFF，等待网络及共享服务稳定。\n2. 不要同时启动或退出虚拟机、容器及互联网共享。\n3. 稳定后重新验证；反复出现时导出反馈并采集只读规则。不能据此认定已经泄漏。"
        } else if reason.contains("PF Internet Sharing") {
            title="共享网络仍有活跃规则或未知分支"
            steps="1. 保持 OFF，先保存虚拟机内的工作，正常关闭虚拟机并退出相关软件；检查系统设置 → 通用 → 共享 → 互联网共享。\n2. Parallels 后台仍运行时，可按官方方法正常停止服务，不使用 --force。\n3. 本版允许已知全空的残留分支，无需手动删 anchor；只读检查确认规则已清空后，重新验证。\n若必须同时使用虚拟机共享网络，当前版本未保证兼容。不要清空 PF 或删除网桥。"
        } else if reason.contains("Unknown PF root anchor") || reason.contains("Unknown PF Apple child anchor") || reason.contains("PF has conflicting/unknown rules") || reason.contains("Unknown PF NAT environment") {
            title="防火墙存在尚未支持的规则"
            steps="1. 保持 OFF，导出反馈，并运行只读规则采集命令。\n2. 根据实际分支名称确认所属软件，再通过该软件正常停止相关网络服务；不要猜测或强制结束系统进程。\n3. 不要手工删除 PF 规则。确认环境兼容后重新验证；此提示不等于 IP 泄漏。"
        } else {return nil}
    }
}
