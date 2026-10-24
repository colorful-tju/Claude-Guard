#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir="$(mktemp -d /private/tmp/claude-lifetime-test.XXXXXX)"
trap '/bin/rm -rf "$task_dir"' EXIT
/usr/bin/clang -Wall -Wextra -Dsysctl=csg_test_sysctl -I Sources/NativeGuard/include -c Sources/NativeGuard/native.c -o "$task_dir/native.o"
/usr/bin/clang -Wall -Wextra -I Sources/NativeGuard/include Tests/NativeLifetimeTests.c "$task_dir/native.o" -lproc -lbsm -o "$task_dir/test"
"$task_dir/test"
