#!/usr/bin/env python3
"""Read-only delivery audit. Never executes installer/uninstaller run handlers."""
from pathlib import Path
import subprocess, plistlib, tempfile, struct, sys
root=Path(__file__).resolve().parent.parent
arch=sys.argv[1] if len(sys.argv)>1 else 'arm64'
assert arch in ('arm64','x86_64')
platform='AppleSilicon' if arch=='arm64' else 'Intel'
image=root/f'dist/Claude-Guard-0.5.16-macOS-{platform}-{arch}.dmg'
def run(*args):return subprocess.run(args,check=True,capture_output=True).stdout
mount=None
try:
    attached=plistlib.loads(run('/usr/bin/hdiutil','attach','-readonly','-nobrowse','-plist',str(image)))
    mount=next(Path(e['mount-point']) for e in attached['system-entities'] if 'mount-point' in e)
    for name in ('双击安装 Claude Guard',):
        app=mount/(name+'.app')
        run('/usr/bin/codesign','--verify','--strict','--deep',str(app))
        info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
        assert info['CFBundleShortVersionString']=='0.5.16'
        assert (app/'Contents/Resources/applet.icns').stat().st_size>1000
    assert {p.name for p in mount.iterdir() if not p.name.startswith('.')} == {'双击安装 Claude Guard.app','移除 Claude Guard.app','请先阅读：先卸载旧版再安装新版.txt'}
    remover=mount/'移除 Claude Guard.app'
    run('/usr/bin/codesign','--verify','--strict','--deep',str(remover))
    for script in ('uninstall.sh','reset-user-preferences.sh'):
        assert (remover/'Contents/Resources/payload/scripts'/script).read_bytes()==(root/'scripts'/script).read_bytes()
    instructions=(mount/'请先阅读：先卸载旧版再安装新版.txt').read_text()
    for required in ('恢复并退出','清空节点设置','首次安装','UNPROTECT'):
        assert required in instructions
    payload=mount/'双击安装 Claude Guard.app/Contents/Resources/payload'
    assert (payload/'architecture').read_text().strip()==arch
    assert (payload/'scripts/install.sh').read_bytes()==(root/'scripts/install.sh').read_bytes()
    assert (mount/'双击安装 Claude Guard.app/Contents/Resources/Recovery/移除 Claude Guard.app/Contents/Resources/payload/scripts/uninstall.sh').read_bytes()==(root/'scripts/uninstall.sh').read_bytes()
    assert (mount/'双击安装 Claude Guard.app/Contents/Resources/Recovery/恢复网络.command').is_file()
    assert (mount/'双击安装 Claude Guard.app/Contents/Resources/Recovery/移除 Claude Guard.app/Contents/Resources/payload/scripts/reset-user-preferences.sh').read_bytes()==(root/'scripts/reset-user-preferences.sh').read_bytes()
    assert (mount/'双击安装 Claude Guard.app/Contents/Resources/Recovery/恢复说明.md').read_bytes()==(root/'docs/完整验证手册.md').read_bytes()
    with tempfile.TemporaryDirectory(prefix='guard-dmg-audit-') as tmp:
        tmp=Path(tmp)
        run('/usr/bin/ditto','-x','-k',str(payload/'dist/ClaudeSafeLauncher-0.5.16-test.zip'),str(tmp))
        app=tmp/'ClaudeSafeLauncher.app'
        run('/usr/bin/codesign','--verify','--strict','--deep',str(app))
        info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
        assert info['CFBundleVersion']=='43' and info['CFBundleIconFile']=='AppIcon'
        assert run('/usr/bin/lipo','-archs',str(app/'Contents/MacOS/ClaudeSafeLauncher')).strip()==arch.encode()
        resources=app/'Contents/Resources'
        assert (resources/'技术与功能详解.md').read_bytes()==(root/'docs/技术与功能详解.md').read_bytes()
        run('/usr/bin/codesign','--verify','--strict','--deep',str(resources/'Recovery/移除 Claude Guard.app'))
        assert (resources/'Recovery/恢复网络.command').is_file()
        for name in ('README.md','NOTICE.md','LICENSE'):
            assert (resources/name).read_bytes()==(root/name).read_bytes()
        assert (resources/'guard-daemon').read_bytes()==(mount/'双击安装 Claude Guard.app/Contents/Resources/Recovery/guard-daemon').read_bytes()
        run('/usr/bin/iconutil','-c','iconset','-o',str(tmp/'Icon.iconset'),str(resources/'AppIcon.icns'))
        for size in (16,32,128,256,512):
            for scale in (1,2):
                name=f'icon_{size}x{size}'+('@2x' if scale==2 else '')+'.png'
                png=(tmp/'Icon.iconset'/name).read_bytes()
                assert struct.unpack('>II',png[16:24])==(size*scale,size*scale)
        for tool in ('guard-probe','guard-daemon','guardctl'):
            assert run('/usr/bin/lipo','-archs',str(resources/tool)).strip()==arch.encode()
        if arch=='arm64':
            print(run(str(resources/'guard-probe'),'--self-test').decode().strip())
            print(run(str(resources/'guard-daemon'),'--self-test-timer').decode().strip())
        else: print('Intel cross-build: static verification only; no Intel hardware acceptance')
    print(f'PASS DMG: installer signed; payload matches; {arch} build43; ten icon sizes; recovery parity')
finally:
    if mount is not None:run('/usr/bin/hdiutil','detach',str(mount))
