# Claude Guard 0.5.0 · 首个公开测试版

先验证出口与 PF 防护，再启动 Claude Desktop / 本机 Claude Code。

## 下载

| Mac 类型 | 文件 |
|---|---|
| Apple Silicon（M 系列） | Claude-Guard-0.5.0-macOS-AppleSilicon-arm64.dmg |
| Intel | Claude-Guard-0.5.0-macOS-Intel-x86_64.dmg |

要求 macOS 14 或更新版本。Apple Silicon 包在开发机完成离线运行验证；Intel 包为交叉编译，完成架构、签名与资源静态检查，尚无 Intel 真机防护验收。

## 本版功能

- PF 默认拒绝与接口/网关 allowlist，启动前出口与物理接口负向验证。
- Claude Desktop / 本机 Claude Code 生命周期管理、运行条件监控及异常提醒。
- 临时 IPv6 手动管理；关闭防护保留设置，恢复并退出时还原。
- 网络设置一键「检测并填入出口 IP」：两个服务一致才自动填写预期出口；不推断代理网关或端口，不代表防护已验证。
- 菜单栏、中文首次引导、内置离线恢复/移除工具及反馈导出。
- 卸载清理用户偏好并复查，处理删除命令成功但 plist 残留的情况。

## 使用与限制

打开对应 DMG，双击安装器，无需拖入应用程序。升级前先在旧版「恢复并退出」。管理员权限用于本机助手；不会自动切换代理、节点或 TUN。先按完整验证手册验收。

仅支持已登记核心、单节点 HTTP/TCP 数字 IPv4 endpoint 和可核验 TUN 路径；不是任意 VPN 通用启动器。PF 会影响其他应用的新出站连接。未对所有 macOS、代理核心、Claude 工作流作兼容保证。

本包采用 ad-hoc 签名，尚未完成 Developer ID 签名及 Apple 公证，可能被 Gatekeeper 拦截；不建议关闭系统安全机制。此 Release 明确标为 Pre-release，不作为生产安全保证。

源码可见，个人非商业使用，禁止商用和二次开发；详见 LICENSE，不是 OSI 开源许可。无自动遥测或日志上传。反馈前删除密码、私人配置和网络地址。

## 恢复兜底

App「恢复工具」或 DMG 安装器「恢复工具」可打开离线手册与文件夹。运行恢复网络.command，先选 2 清除本工具限制；仍断网才选 3（全局停用 PF，影响其他防火墙）。保留输出，恢复受阻时不要强删事务。
