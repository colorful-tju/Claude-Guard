#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$EUID" -ne 0 ]]; then exec sudo /bin/bash "$PWD/scripts/install.sh" "$@"; fi
if [[ -f "$PWD/architecture" ]]; then
  expected_arch="$(cat "$PWD/architecture")"
  [[ "$expected_arch" == "$(/usr/bin/uname -m)" ]] || { echo '芯片架构不匹配，请下载对应 Apple Silicon 或 Intel 的 DMG。'; exit 2; }
fi
user_id="${SUDO_UID:-}"
[[ "$user_id" =~ ^[0-9]+$ && "$user_id" -ge 501 ]] || { echo '请使用普通用户账户打开图形安装器并授权。'; exit 2; }
root='/Library/Application Support/ClaudeSafeLauncher'
label='local.claudesafelauncher.guard'
app='/Applications/ClaudeSafeLauncher.app'
helper="/Library/PrivilegedHelperTools/$label"
plist="/Library/LaunchDaemons/$label.plist"
[[ ! -L "$root" && ! -L "$app" && ( ! -e "$root" || -d "$root" ) ]] || { echo '拒绝不可信安装目标'; exit 2; }
[[ ! -e "$root/ipv6-override.json" && ! -L "$root/ipv6-override.json" && ! -e "$root/session.json" && ! -L "$root/session.json" ]] || { echo '存在安全事务，请先关闭安全模式或完成紧急恢复，不能更新。'; exit 2; }
archive="$PWD/dist/ClaudeSafeLauncher-0.5.0-test.zip"
[[ -f "$archive" && ! -L "$archive" ]] || { echo '安装资源缺失，请重新获取完整磁盘映像。'; exit 2; }
# Separate from daemon.lock: serialize delivery changes without bypassing the
# helper's authoritative OFF assertion under the daemon transaction lock.
install_lock="$root.install-lock"
/bin/mkdir -m 700 "$install_lock" || { echo '另一安装/卸载事务存在；保留现场，请勿删除未知锁后重试。'; exit 2; }
task_install=''
stop_started=0
commit_started=0
keep_evidence=0
service_was_loaded=0
targets=("$app" "$helper" "$root/guard-probe" "$root/read-node.rb" "$root/installation.json" "$plist")
service_state() {
  local rc=0
  /bin/launchctl print "system/$label" > "$task_install/service.stdout" 2> "$task_install/service.stderr" || rc=$?
  if [[ "$rc" -eq 0 ]]; then service_present=1; return 0; fi
  local missing
  missing=$(printf 'Bad request.\nCould not find service "%s" in domain for system' "$label")
  if [[ "$rc" -eq 113 && ! -s "$task_install/service.stdout" && "$(cat "$task_install/service.stderr")" == "$missing" ]]; then service_present=0; return 0; fi
  echo '无法核验 launchd 状态；不覆盖组件。'
  return 1
}
rollback() {
  # Never restore/remove executable files while a possibly running new helper
  # still owns them. Preserve the backup if absence cannot be established.
  /bin/launchctl bootout "system/$label" > /dev/null 2>&1 || true
  if ! service_state || [[ "$service_present" -ne 0 ]]; then return 1; fi
  if [[ "$commit_started" -eq 1 ]]; then
    local i=0 failed=0
    for target in "${targets[@]}"; do
      /bin/rm -rf "$target" || failed=1
      if [[ -e "$task_install/backup/$i" ]]; then
        /usr/bin/ditto --norsrc --noextattr "$task_install/backup/$i" "$target" || failed=1
      fi
      i=$((i + 1))
    done
    [[ "$failed" -eq 0 ]] || return 1
  fi
  if [[ "$service_was_loaded" -eq 1 ]]; then
    /bin/launchctl bootstrap system "$plist" || return 1
    service_state && [[ "$service_present" -eq 1 ]] || return 1
  fi
  return 0
}
finish() {
  local result=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ "$result" -ne 0 && "$stop_started" -eq 1 ]]; then
    if rollback; then
      echo '安装失败；原组件、登记信息及原助手加载状态已恢复。'
    else
      keep_evidence=1
      echo "安装失败且回滚未完成；恢复资产保留于：$task_install"
      echo '助手和防护状态未确认；不要继续安全启动或删除备份。'
    fi
  fi
  if [[ "$keep_evidence" -eq 0 ]]; then
    [[ -z "$task_install" ]] || /bin/rm -rf "$task_install"
    /bin/rmdir "$install_lock"
  else
    echo "安装锁保留于：$install_lock"
  fi
  exit "$result"
}
trap finish EXIT
trap 'exit 130' HUP INT TERM
task_install="$(mktemp -d /private/tmp/claude-safe-install.XXXXXX)"
/bin/chmod 700 "$task_install"
/usr/bin/ditto -x -k "$archive" "$task_install"
source_app="$task_install/ClaudeSafeLauncher.app"
/usr/bin/codesign --verify --strict --deep "$source_app"
for tool in "$source_app/Contents/MacOS/ClaudeSafeLauncher" "$source_app/Contents/Resources/guard-daemon" "$source_app/Contents/Resources/guard-probe" "$source_app/Contents/Resources/guardctl"; do
  [[ -f "$tool" && ! -L "$tool" && -x "$tool" ]] || { echo '安装包缺少正常可执行组件'; exit 2; }
done
[[ -f "$source_app/Contents/Resources/read-node.rb" && ! -L "$source_app/Contents/Resources/read-node.rb" ]] || exit 2
# Registration uses these same fixed signed dependencies. Catch missing/invalid
# builds before stopping the existing working helper or replacing its assets.
# Optional explicit registration for another compatible Mihomo/TUN core.
[[ "$#" -eq 0 || "$#" -eq 2 ]] || { echo '用法：install.sh [核心可执行文件绝对路径 配置文件绝对路径]'; exit 2; }
proxy_core="${1:-/Applications/FlClash.app/Contents/MacOS/FlClashCore}"
[[ "$proxy_core" == /* ]] || { echo '核心路径必须为绝对路径'; exit 2; }
if [[ "$#" -eq 2 ]]; then
  [[ "$2" == /* && -f "$2" && ! -L "$2" ]] || { echo '配置必须是普通文件的绝对路径'; exit 2; }
fi
for dependency in '/Applications/Claude.app' "$proxy_core"; do
  /usr/bin/codesign --verify --strict "$dependency"
done
for target in "${targets[@]}"; do
  [[ ! -L "$target" ]] || { echo '拒绝符号链接恢复资产'; exit 2; }
done
service_state
service_was_loaded=$service_present
stop_started=1
/bin/launchctl bootout "system/$label" > /dev/null 2>&1 || true
service_state
[[ "$service_present" -eq 0 ]] || { echo '原助手仍加载，拒绝更新'; exit 2; }
if [[ ! -e "$root" ]]; then /usr/bin/install -d -o root -g wheel -m 755 "$root"; fi
# The prepared signed helper performs no recovery or mutation in --assert-off.
# It uses the same fixed daemon.lock and verifies journal/marker/own anchor.
"$source_app/Contents/Resources/guard-daemon" --assert-off
[[ ! -e "$root/ipv6-override.json" && ! -L "$root/ipv6-override.json" && ! -e "$root/session.json" && ! -L "$root/session.json" ]] || exit 2
/bin/mkdir "$task_install/backup"
i=0
for target in "${targets[@]}"; do
  if [[ -e "$target" ]]; then /usr/bin/ditto --norsrc --noextattr "$target" "$task_install/backup/$i"; fi
  i=$((i + 1))
done
commit_started=1
/bin/rm -rf "$app"
/usr/bin/ditto --norsrc --noextattr --noqtn "$source_app" "$app"
/usr/bin/xattr -cr "$app"
/usr/sbin/chown -R root:wheel "$app"
/bin/chmod -R go-w "$app"
/usr/bin/codesign --verify --strict --deep "$app"
/usr/bin/install -o root -g wheel -m 755 "$app/Contents/Resources/guard-daemon" "$helper"
/usr/bin/install -o root -g wheel -m 755 "$app/Contents/Resources/guard-probe" "$root/guard-probe"
/usr/bin/install -o root -g wheel -m 644 "$app/Contents/Resources/read-node.rb" "$root/read-node.rb"
"$helper" --register "$user_id" "$@"
cat > "$plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>Label</key><string>local.claudesafelauncher.guard</string>
<key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/local.claudesafelauncher.guard</string><string>--serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>StandardOutPath</key><string>/Library/Application Support/ClaudeSafeLauncher/daemon.stdout.log</string>
<key>StandardErrorPath</key><string>/Library/Application Support/ClaudeSafeLauncher/daemon.stderr.log</string>
<key>Umask</key><integer>63</integer>
</dict></plist>
PLIST
/usr/sbin/chown root:wheel "$plist"
/bin/chmod 644 "$plist"
for log in daemon.stdout.log daemon.stderr.log; do
  [[ -e "$root/$log" ]] || /usr/bin/install -o root -g wheel -m 600 /dev/null "$root/$log"
done
/bin/launchctl bootstrap system "$plist"
service_state
[[ "$service_present" -eq 1 ]] || { echo '新助手未加载'; exit 2; }
echo '已安装。助手空闲，不自动启用 PF、不启动 Claude、不切换代理。'
