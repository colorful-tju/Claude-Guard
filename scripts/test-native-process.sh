#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_native="$(mktemp -d /private/tmp/claude-native-test.XXXXXX)"
trap '/bin/rm -rf "$task_native"' EXIT
/usr/bin/clang -Wall -Wextra -I Sources/NativeGuard/include Sources/NativeGuard/native.c Tests/NativeProcessTests.c -lproc -lbsm -o "$task_native/test-process"
"$task_native/test-process"
