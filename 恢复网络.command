#!/bin/bash
set -u
cd "$(/usr/bin/dirname "$0")" || exit 2
echo 'Claude 安全启动器：离线恢复入口（不需要 .app 或网络）'
echo '请先完全退出 Claude Desktop。'
echo '1：正常恢复（完整验收，需要助手）'
echo '2：强制只解除本工具阻断（助手/日志损坏时用；保留恢复资产）'
echo '3：最后兜底：临时停用整个 PF，其他软件的 PF 防护也会停用'
read -r -p '输入 1 / 2 / 3，其他输入退出：' choice
case "$choice" in
  1) /bin/bash scripts/emergency-recover.sh ;;
  2) /bin/bash scripts/emergency-recover.sh --force-own ;;
  3) /bin/bash scripts/emergency-recover.sh --last-resort ;;
  *) exit 0 ;;
esac
result=$?
echo "恢复工具退出码：$result。保留终端原文；不要继续安全启动。"
read -r -p '按回车关闭窗口。' ignored
exit "$result"
