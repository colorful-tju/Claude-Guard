#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d /private/tmp/csg-deleted-test.XXXXXX)"
trap '/bin/rm -rf "$work"' EXIT
clang -Wall -Wextra -I Sources/NativeGuard/include Sources/NativeGuard/native.c Tests/DeletedExecutableTests.c -lproc -lbsm -o "$work/test"
mkdir -p "$work/Claude.app/Contents/MacOS"
cp "$work/test" "$work/Claude.app/Contents/MacOS/Claude"
"$work/test" "$work/Claude.app/Contents/MacOS/Claude"

clang -Wall -Wextra -I Sources/NativeGuard/include Tests/DeletedExecutableBoundaryTests.c -lproc -lbsm -o "$work/boundary"
"$work/boundary"
