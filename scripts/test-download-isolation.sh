#!/bin/bash
# Test only a disposable archive copy; never installs or invokes privileged modes.
set -euo pipefail
archive="$1"
work="$(mktemp -d /private/tmp/guard-download-test.XXXXXX)"
trap '/bin/rm -rf "$work"' EXIT
cp -X "$archive" "$work/payload.zip"
/usr/bin/xattr -w com.apple.quarantine '0083;00000000;Safari;00000000-0000-0000-0000-000000000000' "$work/payload.zip"
/usr/bin/ditto -x -k "$work/payload.zip" "$work/extract"
app="$work/extract/ClaudeSafeLauncher.app"
# Ensure coverage even when a local ditto version does not propagate the archive flag.
/usr/bin/xattr -w com.apple.quarantine '0083;00000000;Safari;00000000-0000-0000-0000-000000000000' "$app"
/usr/bin/xattr -w com.apple.quarantine '0083;00000000;Safari;00000000-0000-0000-0000-000000000000' "$app/Contents/Resources/guard-daemon"
/usr/bin/codesign --verify --strict --deep "$app"
/usr/bin/xattr -dr com.apple.quarantine "$app"
/usr/bin/codesign --verify --strict --deep "$app"
if /usr/bin/xattr -r "$app" | /usr/bin/grep -q com.apple.quarantine; then exit 2; fi
# This mode runs without constructing a privileged controller, sockets, PF or probes.
"$app/Contents/Resources/guard-daemon" --self-test-timer
echo 'PASS disposable downloaded archive and nested helper: scoped quarantine cleanup, signature and harmless launch'
