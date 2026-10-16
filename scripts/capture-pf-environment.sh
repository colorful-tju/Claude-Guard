#!/bin/bash
# Only fixed PF display operations. Never loads/flushes/enables/disables rules,
# releases a token, starts proxy apps, sends a probe, or changes network settings.
set -u
if [[ "$EUID" -ne 0 ]]; then
  echo '需要管理员权限读取 /dev/pf；请使用 sudo /bin/bash scripts/capture-pf-environment.sh。'
  exit 2
fi
umask 077
capture_temp=$(/usr/bin/mktemp -d /private/tmp/csg-pf-display.XXXXXX) || exit 2
trap '/bin/rm -rf "$capture_temp"' EXIT
failures=0
last_read_ok=1
show() {
  local title="$1";shift
  local rc=0
  echo "--- $title ---"
  /sbin/pfctl "$@" > "$capture_temp/stdout" 2> "$capture_temp/stderr" || rc=$?
  /bin/cat "$capture_temp/stderr" "$capture_temp/stdout"
  echo "readExitCode=$rc"
  last_read_ok=1
  # pfctl can report DIOCGETRULES errors but still exit zero. Only the two
  # known benign ALTQ diagnostics are accepted; other diagnostics invalidate
  # the capture. Also reject error diagnostics printed on stdout.
  if [[ "$rc" -ne 0 ]] || ! /usr/bin/awk '
    FILENAME == ARGV[1] {
      if ($0 != "No ALTQ support in kernel" &&
          $0 != "ALTQ related functions disabled" &&
          $0 !~ /^[[:space:]]*$/) bad=1
      next
    }
    /^[[:space:]]*pfctl:/ {bad=1}
    END {exit bad}
  ' "$capture_temp/stderr" "$capture_temp/stdout"; then
    echo "Read failed or diagnostic rejected: $title"
    failures=$((failures + 1))
    last_read_ok=0
  fi
}
echo 'readOnly=true; no PF/route/proxy/DNS changes; no network probes'
/bin/date -u '+capturedUTC=%Y-%m-%dT%H:%M:%SZ'
echo '--- Current proxy processes (PID PPID UID executable) ---'
/bin/ps -axo pid,ppid,uid,comm | /usr/bin/awk '/\/Applications\/FlClash.app\/Contents\/MacOS\/(FlClash|FlClashCore)$/ || /\/Applications\/Clash Verge.app\/Contents\/MacOS\/(clash-verge|verge-mihomo)$/ {print}'
show 'Main filter rules: exact input to environment checker' -sr
show 'Root anchor inventory' -s Anchors
show 'Apple child anchors: exact input to environment checker' -a com.apple -s Anchors
apple_inventory_ok=$last_read_ok
/bin/cp "$capture_temp/stdout" "$capture_temp/apple-children"
show 'Interfaces/skip flags: exact input to environment checker' -s Interfaces -v
show 'Main NAT/rdr rules' -sn
# Direct display queries avoid the failing wildcard-recursion ioctl. Unknown
# or nested anchors still appear in the inventories; this is evidence capture,
# not a declaration that any named Apple anchor is safe or empty.
for anchor in com.apple com.apple/200.AirDrop com.apple/250.ApplicationFirewall com.apple/000.local.claudesafelauncher; do
  if [[ "$anchor" != com.apple ]]; then
    if [[ "$apple_inventory_ok" -ne 1 ]]; then
      echo "--- Cannot verify presence: $anchor; prior inventory read failed ---"
      continue
    fi
    if ! /usr/bin/awk -v full="$anchor" -v short="${anchor#com.apple/}" '
      {line=$0;sub(/^[[:space:]]+/,"",line);sub(/[[:space:]]+$/,"",line)}
      line==full || line==short {found=1}
      END {exit !found}
    ' "$capture_temp/apple-children"; then
      echo "--- Absent from successful Apple child inventory: $anchor; content queries skipped ---"
      continue
    fi
  fi
  show "Direct filter rules: $anchor" -a "$anchor" -sr
  show "Direct NAT/rdr rules: $anchor" -a "$anchor" -sn
  show "Direct child anchors: $anchor" -a "$anchor" -s Anchors
done
show 'PF enabled/disabled and counters' -s info
show 'Enable references (read only)' -s References
echo "captureReadFailures=$failures"
exit "$failures"
