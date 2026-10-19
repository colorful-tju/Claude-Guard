#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-$PWD/.build/clang-module-cache}"
export SWIFTPM_MODULECACHE_OVERRIDE="${SWIFTPM_MODULECACHE_OVERRIDE:-$PWD/.build/swift-module-cache}"
arch="${1:-arm64}"
[[ "$arch" == arm64 || "$arch" == x86_64 ]] || exit 2
swift build -c release --arch "$arch"
bin_path="$(swift build -c release --arch "$arch" --show-bin-path)"
mkdir -p "dist/$arch"
mkdir -p dist
task_build="$(mktemp -d /private/tmp/claude-safe-build.XXXXXX)"
trap '/bin/rm -rf "$task_build"' EXIT
app="$task_build/ClaudeSafeLauncher.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp -X "${bin_path}/ClaudeSafeLauncher" "$app/Contents/MacOS/ClaudeSafeLauncher"
for tool in guard-daemon guardctl guard-probe; do cp -X "$bin_path/$tool" "$app/Contents/Resources/$tool"; done
cp -X Resources/read-node.rb "$app/Contents/Resources/read-node.rb"
swift scripts/draw-icon.swift "$task_build/AppIcon.iconset"
/usr/bin/iconutil -c icns "$task_build/AppIcon.iconset" -o "$app/Contents/Resources/AppIcon.icns"
cp -X README.md LICENSE NOTICE.md "$app/Contents/Resources/"
cp -X docs/完整验证手册.md "$app/Contents/Resources/新版界面与IPv6验证.md"
cp -X docs/RELEASE-0.5.10.md "$app/Contents/Resources/RELEASE-0.5.10.md"
mkdir -p "$app/Contents/Resources/scripts"
for recovery_tool in emergency-recover.sh rescue-network.rb capture-incident.sh capture-pf-environment.sh redact-incident.rb; do cp -X "scripts/$recovery_tool" "$app/Contents/Resources/scripts/$recovery_tool"; done
cp -X 恢复网络.command "$app/Contents/Resources/恢复网络.command"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.claudesafelauncher.app</string>
<key>CFBundleName</key><string>Claude Safe Launcher</string>
<key>CFBundleDisplayName</key><string>Claude 安全启动器 · 测试版</string>
<key>CFBundleExecutable</key><string>ClaudeSafeLauncher</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.5.10</string>
<key>CFBundleVersion</key><string>37</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/xattr -cr "$app"
for tool in guard-daemon guardctl guard-probe; do codesign --force --sign - --options runtime --identifier "local.claudesafelauncher.$tool" "$app/Contents/Resources/$tool"; done
# The offline kit survives deleting the app and requires no Swift build.
kit="$app/Contents/Resources/Recovery"
mkdir -p "$kit/scripts"
cp -X "$app/Contents/Resources/guard-daemon" "$kit/guard-daemon"
cp -X 恢复网络.command "$kit/恢复网络.command"
cp -X docs/完整验证手册.md "$kit/恢复说明.md"
cp -X docs/RELEASE-0.5.10.md "$kit/RELEASE-0.5.10.md"
cp -X LICENSE "$kit/LICENSE"
for recovery_tool in emergency-recover.sh rescue-network.rb capture-incident.sh capture-pf-environment.sh redact-incident.rb; do cp -X "scripts/$recovery_tool" "$kit/scripts/$recovery_tool"; done
cp -X docs/技术与功能详解.md "$app/Contents/Resources/技术与功能详解.md"
uninstaller="$kit/移除 Claude Guard.app"
/usr/bin/osacompile -o "$uninstaller" Resources/Delivery/Uninstaller.applescript
mkdir -p "$uninstaller/Contents/Resources/payload/scripts"
cp -X scripts/uninstall.sh scripts/reset-user-preferences.sh "$uninstaller/Contents/Resources/payload/scripts/"
cp -X "$app/Contents/Resources/AppIcon.icns" "$uninstaller/Contents/Resources/applet.icns"
/usr/bin/xattr -cr "$uninstaller"
codesign --force --sign - --identifier local.claudesafelauncher.Uninstaller "$uninstaller"
codesign --force --sign - --options runtime --identifier local.claudesafelauncher.app "$app"
codesign --verify --strict --deep "$app"
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist"

# Keep a signed archive; this workspace may be managed by a FileProvider that adds FinderInfo.
/usr/bin/ditto -c -k --keepParent --norsrc --noextattr "$app" "$PWD/dist/$arch/ClaudeSafeLauncher-0.5.10-test.zip"
echo "Verified signed $arch archive created."
