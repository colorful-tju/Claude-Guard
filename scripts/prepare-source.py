#!/usr/bin/env python3
"""Create a reviewable source snapshot using an allowlist; never publishes anything."""
from pathlib import Path
import zipfile
import re
root = Path(__file__).resolve().parent.parent
files = [root / name for name in ('Package.swift','README.md','LICENSE','NOTICE.md','.gitignore','恢复网络.command')]
for directory in ('Sources','Tests','Resources'):
    files += [p for p in (root/directory).rglob('*') if p.is_file() and p.suffix in ('.swift','.c','.h','.rb','.json','.applescript')]
scripts = ('build-app.sh','build-dmg.sh','verify-dmg.py','draw-icon.swift','install.sh','uninstall.sh','reset-user-preferences.sh','test.sh','emergency-recover.sh',
           'rescue-network.rb','capture-incident.sh','capture-pf-environment.sh','redact-incident.rb','prepare-source.py')
files += [root/'scripts'/name for name in scripts]
files += list((root/'scripts').glob('test-*'))
files += [root/'docs/完整验证手册.md', root/'docs/技术与功能详解.md', root/'docs/RELEASE-0.5.0.md', root/'docs/RELEASE-0.5.1.md', root/'docs/RELEASE-0.5.2.md', root/'docs/RELEASE-0.5.3.md', root/'docs/RELEASE-0.5.4.md', root/'docs/RELEASE-0.5.5.md', root/'docs/RELEASE-0.5.6.md', root/'docs/RELEASE-0.5.7.md', root/'docs/RELEASE-0.5.8.md', root/'docs/RELEASE-0.5.9.md', root/'docs/RELEASE-0.5.10.md', root/'docs/RELEASE-0.5.11.md', root/'docs/RELEASE-0.5.12.md', root/'docs/RELEASE-0.5.13.md', root/'docs/RELEASE-0.5.14.md', root/'docs/RELEASE-0.5.15.md', root/'docs/RELEASE-0.5.16.md', root/'docs/RELEASE-0.5.17.md', root/'docs/RELEASE-0.5.18.md']
# Refuse known private development identifiers; do not silently redact production code.
for path in files:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f'Not a regular source file: {path.name}')
    data=path.read_bytes()
    if re.search(rb'/Users/(?!(?:example|test)(?:/|\"|$))[A-Za-z0-9_-]+|82[.]23[.](?:92|98)[.]', data):
        raise SystemExit(f'Private development identifier in {path.relative_to(root)}')
out=root/'dist/ClaudeSafeLauncher-0.5.18-source.zip'
out.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(set(files)):
        archive.write(path,Path('ClaudeSafeLauncher')/path.relative_to(root))
print(f'{out.name}: {len(set(files))} allowlisted files; no upload')
