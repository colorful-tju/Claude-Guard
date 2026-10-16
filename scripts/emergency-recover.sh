#!/bin/bash
set -euo pipefail
if [[ "$#" -eq 1 && ( "$1" == '--force-own' || "$1" == '--last-resort' ) ]]; then
  if [[ "$EUID" -ne 0 ]]; then exec /usr/bin/sudo /bin/bash "$0" "$@"; fi
  unset RUBYOPT RUBYLIB GEM_HOME GEM_PATH
  script_directory=$(cd "$(/usr/bin/dirname "$0")" && pwd)
  exec /usr/bin/ruby "$script_directory/rescue-network.rb" "$1"
fi
[[ "$#" -eq 0 ]] || { echo '用法：emergency-recover.sh [--force-own | --last-resort]'; exit 2; }
if [[ "$EUID" -ne 0 ]]; then exec sudo /bin/bash "$0" "$@"; fi
label='local.claudesafelauncher.guard'
helper="/Library/PrivilegedHelperTools/$label"
[[ -f "$helper" ]] || { echo '助手不存在；可运行 --force-own。仅当它无法解除阻断时，明确选择 --last-resort。'; exit 2; }
/bin/launchctl bootout "system/$label" 2>/dev/null || true
result=0
"$helper" --recover || result=$?
/bin/launchctl bootstrap system "/Library/LaunchDaemons/$label.plist" || true
exit "$result"
