"""Real macOS preference service test against unique disposable domains only."""
from pathlib import Path
import subprocess, tempfile, unittest, uuid
root=Path(__file__).resolve().parent.parent
class ResetTests(unittest.TestCase):
 def test_old_uninstall_preserves_preferences_then_new_cleanup_resets_both_scopes(self):
  domain='local.claudesafelauncher.test.'+uuid.uuid4().hex
  with tempfile.TemporaryDirectory() as folder:
   script=Path(folder)/'reset.sh'
   source=(root/'scripts/reset-user-preferences.sh').read_text().replace('domain=local.claudesafelauncher.app','domain='+domain)
   # Isolate the process gate from the real running user application.
   source=source.replace('processes=$(/bin/ps -u "$EUID" -o comm=)','processes=""')
   script.write_text(source)
   def defaults(*args):return subprocess.run(['/usr/bin/defaults',*args],capture_output=True,text=True)
   try:
    for scope in [[],['-currentHost']]:
     self.assertEqual(defaults(*scope,'write',domain,'publicOnboardingV1','-bool','true').returncode,0)
     self.assertEqual(defaults(*scope,'write',domain,'publicSettingsV1','-string','isolated-test-endpoint').returncode,0)
    # Old script only removed system assets; preference domains survive that operation.
    fakeapp=Path(folder)/'App';fakeapp.mkdir();fakeapp.rmdir()
    self.assertEqual(defaults('read',domain,'publicOnboardingV1').stdout.strip(),'1')
    result=subprocess.run(['/bin/bash',str(script)],capture_output=True,text=True)
    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    self.assertIn('USER_PREFERENCES_CLEARED',result.stdout)
    for scope in [[],['-currentHost']]:
     self.assertNotEqual(defaults(*scope,'read',domain).returncode,0)
    self.assertEqual(subprocess.run(['/bin/bash',str(script)],capture_output=True).returncode,0)
    # Read via Foundation in a fresh process, as the relaunched UI does.
    reader=Path(folder)/'reader.swift'
    reader.write_text('import Foundation\nlet p=UserDefaults(suiteName:CommandLine.arguments[1])!\nprint(p.bool(forKey:"publicOnboardingV1"))\nprint(p.object(forKey:"publicSettingsV1")==nil)\n')
    fresh=subprocess.run(['/usr/bin/swift',str(reader),domain],capture_output=True,text=True)
    self.assertEqual(fresh.returncode,0,fresh.stderr)
    self.assertEqual(fresh.stdout.strip(),'false\ntrue')
   finally:
    for scope in [[],['-currentHost']]:defaults(*scope,'delete',domain)
 def test_successful_defaults_delete_with_persistent_file_is_repaired(self):
  import os
  with tempfile.TemporaryDirectory() as folder:
   base=Path(folder);prefs=base/'Library/Preferences';prefs.mkdir(parents=True)
   domain='local.claudesafelauncher.app'
   plist=prefs/(domain+'.plist');plist.write_text('stale-private-settings-fixture')
   unrelated=prefs/'another.app.plist';unrelated.write_text('keep')
   tool=base/'fake-defaults'
   tool.write_text('#!/bin/bash\nif [[ "$*" == *delete* ]]; then exit 0; fi\nif [[ "$*" != *currentHost* && -e "$HOME/Library/Preferences/local.claudesafelauncher.app.plist" ]]; then echo stale; exit 0; fi\necho "Domain does not exist" >&2;exit 1\n')
   tool.chmod(0o755)
   script=base/'reset.sh'
   source=(root/'scripts/reset-user-preferences.sh').read_text().replace('processes=$(/bin/ps -u "$EUID" -o comm=)','processes=""').replace('/usr/bin/defaults',str(tool))
   script.write_text(source)
   result=subprocess.run(['/bin/bash',str(script)],env={**os.environ,'HOME':folder},capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stdout+result.stderr)
   self.assertFalse(plist.exists());self.assertEqual(unrelated.read_text(),'keep')
 def test_symlink_preference_is_rejected(self):
  import os
  with tempfile.TemporaryDirectory() as folder:
   base=Path(folder);prefs=base/'Library/Preferences';prefs.mkdir(parents=True)
   target=base/'untouched';target.write_text('keep')
   (prefs/'local.claudesafelauncher.app.plist').symlink_to(target)
   tool=base/'fake-defaults';tool.write_text('#!/bin/bash\nexit 0\n');tool.chmod(0o755)
   script=base/'reset.sh';script.write_text((root/'scripts/reset-user-preferences.sh').read_text().replace('processes=$(/bin/ps -u "$EUID" -o comm=)','processes=""').replace('/usr/bin/defaults',str(tool)))
   result=subprocess.run(['/bin/bash',str(script)],env={**os.environ,'HOME':folder},capture_output=True,text=True)
   self.assertEqual(result.returncode,2);self.assertEqual(target.read_text(),'keep')
 def test_running_app_refuses_reset(self):
  with tempfile.TemporaryDirectory() as folder:
   script=Path(folder)/'reset.sh'
   source=(root/'scripts/reset-user-preferences.sh').read_text().replace('processes=$(/bin/ps -u "$EUID" -o comm=)','processes="/Applications/ClaudeSafeLauncher.app/Contents/MacOS/ClaudeSafeLauncher"')
   # The gate exits before any defaults invocation, never touching real preferences.
   script.write_text(source)
   result=subprocess.run(['/bin/bash',str(script)],capture_output=True,text=True)
   self.assertEqual(result.returncode,2)
   self.assertIn('仍在运行',result.stdout)
if __name__=='__main__':unittest.main()
