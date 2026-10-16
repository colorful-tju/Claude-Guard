#!/bin/bash
# Packaging only. Does not install, launch helper, change PF or execute applets.
set -euo pipefail
cd "$(dirname "$0")/.."
version=0.5.3
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
cp -X "$source_app/Contents/Resources/AppIcon.icns" "$image/.VolumeIcon.icns"
/usr/bin/SetFile -a C "$image"
/usr/bin/hdiutil create -volname "Claude Guard $version $platform" -srcfolder "$image" -format UDZO -ov "$PWD/dist/Claude-Guard-$version-macOS-$platform-$arch.dmg"
/usr/bin/hdiutil verify "$PWD/dist/Claude-Guard-$version-macOS-$platform-$arch.dmg"
echo 'DMG created and verified. No install or network changes performed.'
