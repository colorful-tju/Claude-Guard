#!/bin/bash
# Packaging only. Does not install, launch helper, change PF or execute applets.
set -euo pipefail
cd "$(dirname "$0")/.."
version=0.5.17
arch="${1:-arm64}"
case "$arch" in arm64) platform=AppleSilicon;; x86_64) platform=Intel;; *) exit 2;; esac
archive="$PWD/dist/$arch/ClaudeSafeLauncher-$version-test.zip"
[[ -f "$archive" ]] || exit 2
stage="$(mktemp -d /private/tmp/claude-dmg.XXXXXX)"
trap '/bin/rm -rf "$stage"' EXIT
image="$stage/image"
mkdir -p "$image" "$stage/extract"
/usr/bin/ditto -x -k "$archive" "$stage/extract"
source_app="$stage/extract/ClaudeSafeLauncher.app"
/usr/bin/codesign --verify --strict --deep "$source_app"
for mode in Installer; do
  if [[ "$mode" == Installer ]]; then title='双击安装 Claude Guard'; else title='移除 Claude Guard'; fi
  app="$image/$title.app"
  /usr/bin/osacompile -o "$app" "Resources/Delivery/$mode.applescript"
  resources="$app/Contents/Resources"
  mkdir -p "$resources/payload/scripts" "$resources/payload/dist"
  if [[ "$mode" == Installer ]]; then
    echo "$arch" > "$resources/payload/architecture"
    cp -X scripts/install.sh "$resources/payload/scripts/"
    cp -X "$archive" "$resources/payload/dist/"
  else
    cp -X scripts/uninstall.sh "$resources/payload/scripts/"
  fi
  cp -X "$source_app/Contents/Resources/AppIcon.icns" "$resources/applet.icns"
  /usr/bin/plutil -replace CFBundleIdentifier -string "local.claudesafelauncher.$mode" "$app/Contents/Info.plist"
  /usr/bin/plutil -replace CFBundleName -string "$title" "$app/Contents/Info.plist"
  /usr/bin/plutil -replace CFBundleShortVersionString -string "$version" "$app/Contents/Info.plist"
  /usr/bin/plutil -replace LSMinimumSystemVersion -string 14.0 "$app/Contents/Info.plist"
  /usr/bin/ditto --norsrc --noextattr "$source_app/Contents/Resources/Recovery" "$resources/Recovery"
  /usr/bin/xattr -cr "$app"
  /usr/bin/codesign --force --sign - --identifier "local.claudesafelauncher.$mode" "$app"
  /usr/bin/codesign --verify --strict --deep "$app"
done
# Reuse the already sealed, self-contained remover; never run its handler here.
/usr/bin/ditto --norsrc --noextattr "$source_app/Contents/Resources/Recovery/移除 Claude Guard.app" "$image/移除 Claude Guard.app"
/usr/bin/codesign --verify --strict --deep "$image/移除 Claude Guard.app"
cat > "$image/请先阅读：先卸载旧版再安装新版.txt" <<'INSTRUCTIONS'
Claude Guard — 先卸载旧版，再安装新版

首次安装：没有旧版时，直接双击「双击安装 Claude Guard」。无需拖入应用程序。

已有旧版：
1. 记下原有网关 IP、端口、预期出口及自定义核心/配置文件路径。
2. 在旧版菜单栏选择「恢复并退出」，确认 Claude/Code 已退出、防护 OFF、临时 IPv6 已恢复。
3. 双击本窗口的「移除 Claude Guard」，授权并等待显示移除完成。
4. 双击「双击安装 Claude Guard」，授权安装新版，再重新填写网络设置。

注意：卸载会清空节点设置和首次引导记录；这是一套全新安装流程，不保留旧配置。
若移除失败，不要继续安装或强删文件。打开安装器并选择「恢复工具」。
网络异常兜底：恢复网络.command 先选 2，仍断网选 3；受阻时按提示确认 UNPROTECT（影响整个 PF）。仍无法联网请重启并保留输出。

本测试版未获 Apple 公证；系统可能要求在「隐私与安全性」确认来源。不要关闭 Gatekeeper 或 SIP。
INSTRUCTIONS
cp -X "$source_app/Contents/Resources/AppIcon.icns" "$image/.VolumeIcon.icns"
/usr/bin/SetFile -a C "$image"
/usr/bin/hdiutil create -volname "Claude Guard $version $platform" -srcfolder "$image" -format UDZO -ov "$PWD/dist/Claude-Guard-$version-macOS-$platform-$arch.dmg"
/usr/bin/hdiutil verify "$PWD/dist/Claude-Guard-$version-macOS-$platform-$arch.dmg"
echo 'DMG created and verified. No install or network changes performed.'
