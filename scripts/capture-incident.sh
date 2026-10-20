#!/bin/bash
# Read-only incident collection. No PF enable/disable/load/flush, probes,
# process signals, launchd changes, proxy/TUN/DNS changes, or file deletion.
set -u
if [[ "$EUID" -ne 0 ]]; then
  echo '请使用 sudo /bin/bash scripts/capture-incident.sh，仅用于读取事故日志。'
  exit 2
fi
echo 'readOnly=true; no firewall/network/process changes; no probes'
/bin/date -u '+capturedUTC=%Y-%m-%dT%H:%M:%SZ'
/usr/sbin/sysctl -n kern.bootsessionuuid
script_directory=$(cd "$(/usr/bin/dirname "$0")" && pwd)
root='/Library/Application Support/ClaudeSafeLauncher'
for file in events.log last-validation.json last-monitoring-failure.json last-monitoring-degradation.json last-socket-observation.json daemon.stderr.log daemon.stdout.log session.json enable-result.txt; do
  echo "--- $file ---"
  if [[ -f "$root/$file" && ! -L "$root/$file" ]]; then
    if [[ "$file" == 'session.json' || "$file" == 'last-validation.json' || "$file" == 'last-monitoring-failure.json' || "$file" == 'last-monitoring-degradation.json' || "$file" == 'last-socket-observation.json' ]]; then
      /usr/bin/ruby "$script_directory/redact-incident.rb" "$root/$file"
    elif [[ "$file" == 'enable-result.txt' ]]; then
      echo 'Enable result present; raw PF reference withheld'
    else
      /usr/bin/tail -n 250 "$root/$file"
    fi
  else
    echo 'Not present or not a regular non-symlink file'
  fi
done
echo '--- IPv6 temporary override asset (contents withheld) ---'
if [[ -e "$root/ipv6-override.json" || -L "$root/ipv6-override.json" ]]; then echo 'ipv6OverridePresent=true'; else echo 'ipv6OverridePresent=false'; fi
echo '--- Current relevant processes: PID PPID UID executable ---'
/bin/ps -axo pid,ppid,uid,comm | /usr/bin/awk '/Claude|FlClash|clash-verge|verge-mihomo|local.claudesafelauncher.guard/ {print}'
echo '--- IPv6 default route (read only) ---'
/sbin/route -n get -inet6 default
echo '--- PF environment (read only) ---'
script_directory=$(cd "$(/usr/bin/dirname "$0")" && pwd)
/bin/bash "$script_directory/capture-pf-environment.sh"
