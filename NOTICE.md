# 作者、第三方与隐私说明

- 作者：**colorful**，GitHub [@colorful-tju](https://github.com/colorful-tju)。公开资料核对日期：2026-10-16。
- 当前项目仓库尚未公开发布；作者主页不是项目仓库。
- Claude Guard 是独立项目，与 Anthropic、Apple、Webshare、FLClash、Clash Verge 等无隶属、合作或背书关系。相关名称归各自权利人所有。
- 软件使用 macOS 自带 SwiftUI、AppKit、Security、SystemConfiguration、PF 与命令行工具；SwiftPM 未声明第三方包依赖。不捆绑代理软件、Claude、代理节点或账号凭据。
- 样式采用系统材质与 SF Symbols；关于页组织参考常见 macOS 项目的“作者 / 版本 / 许可 / 支持 / 第三方”布局，例如 [Rectangle](https://rectangleapp.com/)。未复制其代码或许可。
- 本项目按随附 LICENSE 提供：非商业、禁止二次开发。此限制与 [OSI 开源定义](https://opensource.org/osd) 不兼容，因此使用“源码可见”标注。

## 网络与本机数据

没有遥测、账号登录或自动上传报告。界面公网 IP 检测会请求 `https://api.ipify.org/` 与 `https://ipv4.webshare.io/`，这些服务会看到请求的网络出口。防护验证还会向固定 TCP / UDP / STUN 测试目标发出探针，以验证物理路径被阻断。初次启动即会执行界面的 IP 检测；它不是防护验收。

设置仅保存在当前用户的本机偏好中。代理核心登记、PF / IPv6 恢复事务和运行日志由管理员助手保存在 `/Library/Application Support/ClaudeSafeLauncher`。启动器读取用户指定配置以验证节点和指纹，不在 UI 输出或另存其中的代理密码。报告包含进程、时间、接口、网络地址等诊断数据；请人工检查并脱敏后分享。

测试数据中的地址用于模拟和断言，不是预置代理服务。发行包不包含个人偏好、历史故障报告或实机采集文件。
