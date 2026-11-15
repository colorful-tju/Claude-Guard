# 0.5.37 测试版：第一轮 TCP 前置适配

## 本轮范围

- VLESS TCP/TLS、TCP/Reality，允许 TCP 下 xtls-rprx-vision；保留 WS/TLS。
- Trojan TCP/TLS、TCP/Reality、WS/TLS；TLS 缺省开启，显式 false 拒绝。
- HTTP/SOCKS5 的原有明文端点和 TLS 身份限制保持不变。
- Reality 只支持 TCP，公钥严格为规范的 32 字节 base64url，short-id 为最多 8 字节的偶数长度十六进制，要求受支持客户端指纹。ALPN 不允许 h3。无未知参数透传，不开放插件、外部证书文件、MPTCP、TFO 或额外拨号路径。
- WS Reality 不开放：固定 Core 版本对应 WS 分支未使用该 Reality 配置，不能把加载成功当作认证方式被采用。

## 默认值依据

FLClash v0.9.3 Core 子模块为 `chen08209/Clash.Meta@024245dc72bc92f48237f865119afe0cd53ac9e6`。
Trojan SNI 缺省为原 server；WS Host 显式值保留，缺省取 SNI。VLESS WS SNI 缺省按显式 Host 再原 server，TCP SNI 缺省取原 server。只在临时隔离配置中固定候选数字 IP，不修改用户配置。

源码依据：https://github.com/chen08209/Clash.Meta/blob/024245dc72bc92f48237f865119afe0cd53ac9e6/adapter/outbound/trojan.go

## 策略组与界面

支持当前拓展脚本使用的 exclude-filter：字面关键词、竖线分隔、外层括号和前导 (?i)。复杂正则明确拒绝，避免 Ruby 与 Core 正则引擎语义不同。filter 使用相同有限语法，作用于自动引入节点。exclude-type 兼容 Shadowsocks/ss、ShadowsocksR/ssr、Socks/socks5 等类型名称。超过 128 个有效候选明确报错，不截断。

暂未适配的 VMess/SS 等保留在既有候选范围时，验证会明确提示协议不支持。不会把同端口 DoH IP 硬编码排除，也不会把它们当作已验证入口。

修正通过 IP 的候选标签；前置名称、入口 IP、物理接口、路径模式或配置/Core 身份变化仍使结果过期。仅填写最终预期出口不使前置结果过期，完整防护仍独立核验出口。

## 验证范围

生产 Swift 序列化及 FIFO 输出送入真实 Core 禁网加载：VLESS WS/TLS、TCP/TLS/Vision、TCP/Reality/Vision，Trojan TCP/TLS、WS/TLS、TCP/Reality 共六组。包含负向参数、H3、嵌套未知选项、Reality/flow、过滤数量边界等测试。

当前本地生成配置经过排除条件及原 IPv4/TCP 候选筛选后，58 个候选均通过参数提取：14 个 VLESS TCP/Reality、21 个 VLESS WS/TLS、19 个 HTTP TLS、4 个 Trojan TCP。此统计不是公网连接成功率，也不代表所有机场或其他 Core 版本受支持。

## 手动验收

1. 关闭防护后更新到 0.5.37+65，先在原来已通过的 WS 节点复测前置验证。
2. 由用户手动在 FLClash 选择一个 VLESS TCP/Reality 前置，保持原拓展脚本，读取当前链路，验证前置。不要根据未测试 IP 手动猜选。
3. 再以同样方式测试一个 Trojan TCP 节点。每次切换前先关闭防护。
4. 只有前置验证成功后，再确认端点、检测最终加拿大出口、开启“仅验证防护”。测试网页，最后关闭防护。记录节点类型、时间、失败阶段，导出反馈。

开发过程中不切换节点或启用真实 PF。握手、泄漏拦截和恢复的实机验收仍待用户完成；Intel 是交叉构建。

兜底：先点关闭防护；失败则使用离线恢复工具，优先正常/仅本工具恢复，模式 3 仅作最后手段。未通过实机验证前不要据离线结果推断全链路安全。
