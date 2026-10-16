#!/bin/bash
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then exec sudo /bin/bash "$0" "$@"; fi
owner_uid="${SUDO_UID:-}"
[[ "$owner_uid" =~ ^[0-9]+$ && "$owner_uid" -ge 501 ]] || { echo '无法确认卸载用户，拒绝误清 root 偏好。'; exit 2; }
script_dir="$(cd "$(dirname "$0")" && pwd)"
root='/Library/Application Support/ClaudeSafeLauncher'
label='local.claudesafelauncher.guard'
[[ ! -L "$root" ]] || { echo '拒绝符号链接事务目录'; exit 2; }
install_lock="$root.install-lock"
/bin/mkdir -m 700 "$install_lock" || { echo '另一安装/卸载事务存在；保留资产。'; exit 2; }
trap '/bin/rmdir "$install_lock"' EXIT
/bin/launchctl bootout "system/$label" 2>/dev/null || true
helper="/Library/PrivilegedHelperTools/$label"
if ! "$helper" --assert-off; then
  /bin/launchctl bootstrap system "/Library/LaunchDaemons/$label.plist" || true
  echo '恢复资产保留；先完成 OFF/恢复。'
  exit 2
fi
if ! /usr/bin/sudo -H -u "#$owner_uid" /bin/bash "$script_dir/reset-user-preferences.sh"; then
  /bin/launchctl bootstrap system "/Library/LaunchDaemons/$label.plist" || true
  echo '用户偏好未确认清空；保留应用和助手。'
  exit 2
fi
# Keep the executable recovery path until all other removals have succeeded.
# A partial deletion can then be retried with the same installed helper.
[[ ! -L "$root" ]] || exit 2
/bin/rm -rf /Applications/ClaudeSafeLauncher.app
/bin/rm -rf "$root"
/bin/rm -f "/Library/LaunchDaemons/$label.plist"
/bin/rm -f "$helper"
echo '仅删除本应用及助手；未改动系统代理、DNS、路由或 Apple PF 规则。'
