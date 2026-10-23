#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-$PWD/.build/clang-module-cache}"
export SWIFTPM_MODULECACHE_OVERRIDE="${SWIFTPM_MODULECACHE_OVERRIDE:-$PWD/.build/swift-module-cache}"
devdir="$(xcode-select -p)"
frameworks="$devdir/Library/Frameworks"
interop="$devdir/usr/lib"
if [[ -d "$devdir/Library/Developer/Frameworks/Testing.framework" ]]; then
  frameworks="$devdir/Library/Developer/Frameworks"
  interop="$devdir/Library/Developer/usr/lib"
fi
args=(--disable-xctest)
if [[ -d "$frameworks/Testing.framework" ]]; then
  args+=(-Xswiftc -F -Xswiftc "$frameworks" -Xlinker -rpath -Xlinker "$frameworks" -Xlinker -rpath -Xlinker "$interop")
fi
swift test "${args[@]}" "$@"
# Exercise the executable's Swift 6 main isolation, not only a library test queue.
# This mode runs before root checks and never constructs the privileged controller.
swift build --product guard-simulation
.build/debug/guard-simulation
swift build --product guard-daemon
.build/debug/guard-daemon --self-test-timer
python3 scripts/test-config-preflight.py
bash scripts/test-native-process.sh
bash scripts/test-deleted-executable.sh
python3 scripts/test-pf-capture.py
python3 scripts/test-network-rescue.py

python3 scripts/test-native-probe.py
python3 scripts/test-command-runner.py
python3 scripts/test-installation.py
.build/debug/guard-probe --self-test
python3 scripts/test-incident-redaction.py

python3 scripts/test-monitor-capture.py

# Pure handler checks only; no administrator prompt or applet run handler.
python3 scripts/test-delivery.py

python3 scripts/test-preferences-reset.py

python3 scripts/test-node-parser.py
python3 scripts/test-profile-summaries.py
