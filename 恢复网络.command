#!/bin/bash
set -u
cd "$(/usr/bin/dirname "$0")" || exit 2
umask 077
recovery_log=$(/usr/bin/mktemp "${HOME}/Desktop/ClaudeGuard恢复-XXXXXX" 2>/dev/null) ||
  recovery_log=$(/usr/bin/mktemp "${TMPDIR:-/tmp}/ClaudeGuard-recovery-XXXXXX" 2>/dev/null) || recovery_log=""
run_recovery() {
  if [[ -n "$recovery_log" ]]; then
    /bin/bash scripts/emergency-recover.sh "$@" 2>&1 | /usr/bin/tee -a "$recovery_log"
    return "${PIPESTATUS[0]}"
  fi
  /bin/bash scripts/emergency-recover.sh "$@"
}
if [[ -n "$recovery_log" ]]; then
  echo "恢复记录：$recovery_log"
else
  echo '无法创建记录文件；恢复操作仍可继续，请保留终端原文。'
fi
echo 'Claude 安全启动器：离线恢复入口（不需要 .app 或网络）'
echo '请先完全退出 Claude Desktop。'
echo '1：正常恢复（完整验收，需要助手）'
echo '2：强制只解除本工具阻断（助手/日志损坏时用；保留恢复资产）'
echo '3：最后兜底：临时停用整个 PF，其他软件的 PF 防护也会停用'
read -r -p '输入 1 / 2 / 3，其他输入退出：' choice
case "$choice" in
  1) run_recovery ;;
  2) run_recovery --force-own
     if [[ $? -ne 0 ]]; then
       echo '模式 2 受阻。若仅因 Claude 退出无法确认，可选择解除本工具规则。助手停止、事务锁和规则清理仍须通过核验；不禁用全局 PF。'
       read -r -p '接受 Claude 可能失去保护，输入 UNPROTECT_OWN：' confirmation
       if [[ "$confirmation" == UNPROTECT_OWN ]]; then
         run_recovery --force-own --confirm-unprotected
       else
         false
       fi
     fi ;;
  3) run_recovery --last-resort
     if [[ $? -ne 0 ]]; then
       echo '常规兜底受阻。继续将忽略助手/进程/锁的核验失败，停用整个 PF；可能被其他进程重新启用，不代表恢复完成。'
       read -r -p '确认已退出 Claude 并接受解除所有 PF 防护，输入 UNPROTECT：' confirmation
       if [[ "$confirmation" == UNPROTECT ]]; then
         run_recovery --last-resort --confirm-unprotected
       else
         false
       fi
     fi ;;
  *) exit 0 ;;
esac
result=$?
echo "恢复工具退出码：${result}。保留终端原文；不要继续安全启动。"
read -r -p '按回车关闭窗口。' ignored
exit "$result"
