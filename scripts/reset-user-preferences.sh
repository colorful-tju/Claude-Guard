#!/bin/bash
# Run in the installing user's context, after OFF and before removing app assets.
set -euo pipefail
[[ "$EUID" -ne 0 ]] || { echo '拒绝清理 root 偏好；必须指定原用户。'; exit 2; }
processes=$(/bin/ps -u "$EUID" -o comm=)
if /usr/bin/awk '$0 == "ClaudeSafeLauncher" || /\/Contents\/MacOS\/ClaudeSafeLauncher$/ {found=1} END {exit !found}' <<< "$processes"; then
  echo '启动器仍在运行，请先从菜单栏恢复并退出；未删除偏好。'; exit 2
fi
domain=local.claudesafelauncher.app
for scope in standard host; do
  args=(/usr/bin/defaults); [[ "$scope" != host ]] || args+=( -currentHost )
  # A missing domain is already clean. Other read/delete errors are not success.
  if result=$("${args[@]}" read "$domain" 2>&1); then
    "${args[@]}" delete "$domain"
  elif [[ "$result" != *'does not exist'* ]]; then
    echo "无法读取 $scope 偏好；保留应用以便重试。"; exit 2
  fi
  # macOS can acknowledge a domain delete while the persistent plist survives.
  # Remove only this application's user-owned regular preference files, then reread.
  files=("$HOME/Library/Preferences/$domain.plist")
  if [[ "$scope" == host ]]; then
    files=("$HOME/Library/Preferences/ByHost/$domain".*.plist)
  fi
  for pref in "${files[@]}"; do
    [[ -e "$pref" || -L "$pref" ]] || continue
    [[ ! -L "$pref" && -f "$pref" && "$(/usr/bin/stat -f %u "$pref")" == "$EUID" ]] || {
      echo '偏好文件类型或所有者异常；拒绝删除。'; exit 2;
    }
    /bin/rm -- "$pref"
  done
  if result=$("${args[@]}" read "$domain" 2>&1); then
    echo "偏好仍存在：$scope；未完成卸载。"; exit 2
  elif [[ "$result" != *'does not exist'* ]]; then
    echo "无法确认 $scope 偏好已删除。"; exit 2
  fi
done
echo 'USER_PREFERENCES_CLEARED：节点及首次引导标记已删除并核验。'
