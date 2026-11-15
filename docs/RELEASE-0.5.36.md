# 0.5.36 测试版：UDP 防护中的 TUN DNS 兼容修复

## 改动与边界

此前 UDP-only 的全接口 UDP 拒绝规则，也阻断了提交给 TUN 的 DNS 请求。新规则只为已登记、签名身份匹配的代理 Core 实际持有且 UP 的唯一 TUN 增加 IPv4 UDP 53 例外，不凭接口前缀放行所有 TUN。身份包括 Core 进程启动时间、代码身份、接口索引和 IPv4；每轮监控复核。允许规则使用 no state。

物理接口 UDP DNS、STUN、QUIC、新接口及非回环 IPv6 UDP 继续默认阻断；保留有限 DHCP。没有改变完整 Claude 防护的规则，没有修改代理配置。此模式仍不保证 TCP 出口或 DNS 服务商地区。

启动时先验证物理 UDP/STUN 拦截与计数，再做 HTTPS 可用性检查，两个回显服务任一个取得有效 IPv4 即可（不要求指定出口）。均失败则走原事务回滚，不显示已验证。命中缓存可能让 HTTPS 检查无法证明每一次 DNS 查询都可用，所以仍需下列实机验收。

若代理启动/重连仍需直接 UDP bootstrap DNS，该流量不会获准；应在代理自身配置中使用适当的 TCP/DoH bootstrap，而不是放开物理 UDP。软件不会自动修改配置。

## 已完成与待完成

规则语义测试、真实 pfctl 只解析测试、连接失败回滚和 TUN 身份变化测试。未在开发期间启用 PF、切换代理或进行实机泄漏探针；不得据离线测试声称网络验收完成。

## 用户手动验收

1. 关闭旧版防护，按 DMG 说明更新。确认 0.5.36+64。先不要启动 Claude。
2. 由你手动准备原有 FLClash TCP 链式代理/TUN。关闭 UDP 防护时，确认 https://api.ipify.org/ 和 https://ipv4.webshare.io/ 及普通网页可访问。
3. 点击“仅 UDP 防护”。允许完成阻断探针和 HTTPS 检查。成功后报告应包含 `UDP-only DNS/HTTPS availability passed; TUN DNS exception=utun…`，以及 boundUDP、boundSTUN 的计数增加。
4. 打开上述两个网址及 https://www.google.com/ ，尝试 Codex 对话，持续 2–3 分钟。导出反馈，说明成功/失败网址、启用时间和是否仍有网页明显变慢。
5. 点“关闭防护”，确认 OFF、网页正常，再导出反馈。此模式不会退出任何应用。

失败时不要连续重试，保留反馈。若提示 TUN DNS exception=none，表示没有得到已登记 Core 持有 TUN 的证据，不会猜选接口。

## 每次测试的兜底

先点“关闭防护”。若无法关闭或断网，在 App 的恢复工具中打开离线恢复工具，先用正常恢复/仅本工具恢复；模式 3 是最后手段，可能影响其他 PF 使用者。保持恢复工具提前可在本地打开。开发者不会自动切换代理或启用防护。
