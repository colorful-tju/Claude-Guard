"""Run real installation scripts against disposable command/filesystem fixtures.
Only temporary script copies replace fixed paths, commands and the root gate.
No root installation, launchd/PF command, process signal or network request runs.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPTS = pathlib.Path(__file__).parent


class InstallationTests(unittest.TestCase):
    def exercise(self, failure='', active=False, loaded=True, old=True, script='install.sh', locked=False, marker=False, unsafe_root=False, ipv6=False, wrong_arch=False, consent=True):
        with tempfile.TemporaryDirectory(prefix='csg-install-test-') as temp:
            base = pathlib.Path(temp)
            project = base / 'project'
            (project / 'scripts').mkdir(parents=True)
            (project / 'dist').mkdir()
            private = base / 'Library/Application Support/ClaudeSafeLauncher'
            app = base / 'Applications/ClaudeSafeLauncher.app'
            helper = base / 'Library/PrivilegedHelperTools/local.claudesafelauncher.guard'
            plist = base / 'Library/LaunchDaemons/local.claudesafelauncher.guard.plist'
            for directory in [private, helper.parent, plist.parent, app.parent]:
                directory.mkdir(parents=True, exist_ok=True)
            if unsafe_root:
                private.chmod(0o777)
            if wrong_arch: (project/'architecture').write_text('unsupported-architecture')
            calls = base / 'calls.jsonl'
            service = base / 'service.json'
            service.write_text(json.dumps({'loaded': loaded and old}))
            state = base / 'fixture.json'
            state.write_text(json.dumps({'failure': failure, 'failed': False}))
            tool_source = f'''#!{sys.executable}
import json,pathlib,sys,shutil,zipfile,os
base=pathlib.Path({str(base)!r}); calls=base/'calls.jsonl'; fixture=base/'fixture.json'; service=base/'service.json'
args=sys.argv[1:]; tool=pathlib.Path(sys.argv[0]).name
with calls.open('a') as out:out.write(json.dumps([tool]+args)+'\\n')
s=json.loads(fixture.read_text())
def fail_once(name):
 if s['failure']==name and not s['failed']:
  s['failed']=True;fixture.write_text(json.dumps(s));sys.exit(9)
if tool=='rm':
 if any(a.endswith('/Applications/ClaudeSafeLauncher.app') for a in args):fail_once('remove_app')
 os.execv('/bin/rm',['/bin/rm']+args)
if tool=='sudo':
 fail_once('preferences');sys.exit(0)
if tool=='launchctl':
 if s['failure']=='launch_error':print('launchd unavailable',file=sys.stderr);sys.exit(1)
 current=json.loads(service.read_text())
 if args[0]=='print':
  if current['loaded']:print('service loaded');sys.exit(0)
  print('Bad request.\\nCould not find service "local.claudesafelauncher.guard" in domain for system',file=sys.stderr);sys.exit(113)
 if args[0]=='bootout':current['loaded']=False
 if args[0]=='bootstrap':
  fail_once('bootstrap');current['loaded']=True
 service.write_text(json.dumps(current));sys.exit(0)
if tool=='codesign':
 if 'FlClashCore' in args[-1]:fail_once('dependency')
 sys.exit(0 if pathlib.Path(args[-1]).exists() else 8)
if tool in ['chown','xattr']:sys.exit(0)
if tool=='ditto':
 if '-x' in args:
  with zipfile.ZipFile(args[-2]) as archive:
   archive.extractall(args[-1])
   for member in archive.infolist():
    if not member.is_dir():os.chmod(pathlib.Path(args[-1])/member.filename,(member.external_attr>>16)&0o777)
 else:
  source,target=map(pathlib.Path,args[-2:])
  if s['failure']=='rollback' and '/backup/' in str(source):sys.exit(9)
  shutil.copytree(source,target,dirs_exist_ok=True,copy_function=shutil.copy2) if source.is_dir() else shutil.copy2(source,target)
  if 'claude-safe-install.' in str(source) and str(target).endswith('/Applications/ClaudeSafeLauncher.app'):fail_once('copy')
 sys.exit(0)
if tool=='install':
 clean=[];i=0
 while i<len(args):
  if args[i] in ['-o','-g']:i+=2;continue
  clean.append(args[i]);i+=1
 os.execv('/usr/bin/install',['/usr/bin/install']+clean)
if tool in ['helper','guard-daemon','local.claudesafelauncher.guard']:
 if args[0]=='--self-test-timer':fail_once('new_helper_launch')
 if args[0]=='--assert-off':
  private=base/'Library/Application Support/ClaudeSafeLauncher'
  sys.exit(2 if (private.stat().st_mode & 0o022) or (private/'session.json').exists() or (private/'enable-result.txt').exists() or (private/'ipv6-override.json').exists() else 0)
 if args[0]=='--register':
  if s['failure']=='rollback':sys.exit(9)
  fail_once('register')
  (base/'Library/Application Support/ClaudeSafeLauncher/installation.json').write_text('new-registration')
 sys.exit(0)
raise SystemExit('unexpected fixture command '+tool)
'''
            tools = base / 'tools'
            tools.mkdir()
            for name in ['launchctl', 'codesign', 'chown', 'xattr', 'ditto', 'install', 'helper', 'sudo', 'rm']:
                path = tools / name
                path.write_text(tool_source)
                path.chmod(0o755)
            for dependency in ['FlClash.app/Contents/MacOS/FlClashCore', 'FlClash.app/Contents/MacOS/FlClash', 'Claude.app/Contents/MacOS/Claude']:
                path = app.parent / dependency
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('signed dependency fixture')
            old_assets = [app/'Contents/MacOS/ClaudeSafeLauncher', helper,
                          private/'guard-probe', private/'read-node.rb',
                          private/'installation.json', plist]
            if old:
                for path in old_assets:
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_text('old-'+path.name)
                shutil.copy2(tools/'helper',helper)
            if locked:
                pathlib.Path(str(private)+'.install-lock').mkdir()
            if marker:
                (private/'enable-result.txt').write_text('uncertain-token-preserved')
            if ipv6:
                (private/'ipv6-override.json').write_text('original-ipv6-preserved')
            if active:
                (private/'session.json').write_text('active-transaction-preserved')
            before = {str(path):path.read_bytes() for path in old_assets if path.exists()}
            staged = base / 'archive/ClaudeSafeLauncher.app'
            for relative in ['Contents/MacOS/ClaudeSafeLauncher','Contents/Resources/guard-daemon','Contents/Resources/guard-probe','Contents/Resources/guardctl','Contents/Resources/read-node.rb','Contents/Info.plist']:
                path=staged/relative
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('new-'+path.name)
                path.chmod(0o755)
            shutil.copy2(tools/'helper',staged/'Contents/Resources/guard-daemon')
            for version in ['0.2.7','0.2.8','0.2.9','0.3.0','0.3.1','0.3.2','0.4.0','0.4.1','0.4.2','0.4.3','0.4.4','0.4.5','0.4.6','0.5.3']:
                with zipfile.ZipFile(project/f'dist/ClaudeSafeLauncher-{version}-test.zip','w') as archive:
                    for path in staged.rglob('*'):
                        archive.write(path,path.relative_to(staged.parent))
            source=(SCRIPTS/script).read_text()
            source=source.replace('if [[ "$EUID" -ne 0 ]]; then','if false; then')
            source=source.replace('/Library/',str(base)+'/Library/').replace('/Applications/',str(base)+'/Applications/')
            source=source.replace('/private/tmp/',str(base)+'/')
            for name,original in [('rm','/bin/rm'),('sudo','/usr/bin/sudo'),('launchctl','/bin/launchctl'),('codesign','/usr/bin/codesign'),('chown','/usr/sbin/chown'),('xattr','/usr/bin/xattr'),('ditto','/usr/bin/ditto'),('install','/usr/bin/install')]:
                source=source.replace(original+' ',str(tools/name)+' ') if name=='rm' else source.replace(original,str(tools/name))
            test_script=project/'scripts'/script
            test_script.write_text(source)
            result=subprocess.run(['/bin/bash',str(test_script)],text=True,capture_output=True,
                                  env={'CLAUDE_GUARD_ALLOW_UNNOTARIZED':('1' if consent else '0'),'SUDO_UID':'501','PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},timeout=20)
            entries=[json.loads(row) for row in calls.read_text().splitlines()] if calls.exists() else []
            after={str(path):path.read_bytes() for path in old_assets if path.exists()}
            preserved=all(after.get(path)==content for path,content in before.items())
            service_state=json.loads(service.read_text());service_state['assetCount']=len(after)
            service_state['rootMode']=(private.stat().st_mode & 0o777) if private.exists() else None
            service_state['markerPresent']=(private/'enable-result.txt').exists()
            service_state['sessionPresent']=(private/'session.json').exists()
            service_state['dependenciesPresent']=(app.parent/'FlClash.app').exists() and (app.parent/'Claude.app').exists()
            return result,entries,service_state,preserved,sorted(str(path.relative_to(base)) for path in base.glob('claude-safe-install.*'))

    def test_personal_test_requires_explicit_consent(self):
        result,calls,service,preserved,_=self.exercise(consent=False)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(calls,[])
        self.assertTrue(preserved and service['loaded'])

    def test_new_helper_launch_failure_precedes_stopping_old_service(self):
        result,calls,service,preserved,_=self.exercise(failure='new_helper_launch')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved and service['loaded'])
        self.assertFalse(any(c[0]=='launchctl' and c[1]=='bootout' for c in calls))
        self.assertTrue(any(c[0]=='xattr' and c[1:3]==['-dr','com.apple.quarantine'] for c in calls))

    def test_wrong_chip_package_rejected_before_service_changes(self):
        result,calls,service,preserved,_=self.exercise(wrong_arch=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(calls,[])
        self.assertTrue(preserved and service['loaded'])

    def test_registration_failure_restores_previous_assets_and_loaded_service(self):
        result,_,service,preserved,_=self.exercise(failure='register')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved,result.stdout+result.stderr)
        self.assertTrue(service['loaded'],result.stdout+result.stderr)

    def test_partial_copy_failure_restores_previous_assets_and_service(self):
        result,_,service,preserved,_=self.exercise(failure='copy')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved,result.stdout+result.stderr)
        self.assertTrue(service['loaded'])

    def test_bootstrap_failure_restores_previous_assets_and_service(self):
        result,_,service,preserved,_=self.exercise(failure='bootstrap')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved,result.stdout+result.stderr)
        self.assertTrue(service['loaded'])

    def test_dependency_failure_does_not_stop_previous_service(self):
        result,calls,service,preserved,_=self.exercise(failure='dependency')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(call[:2]==['launchctl','bootout'] for call in calls))
        self.assertTrue(preserved and service['loaded'])

    def test_ipv6_backup_prevents_install_and_uninstall(self):
        for script in ['install.sh','uninstall.sh']:
            result,calls,service,preserved,_=self.exercise(script=script,ipv6=True)
            self.assertNotEqual(result.returncode,0)
            self.assertTrue(preserved and service['loaded'])

    def test_active_transaction_is_rejected_without_service_changes(self):
        result,calls,service,preserved,_=self.exercise(active=True)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(call[0]=='launchctl' for call in calls))
        self.assertTrue(preserved and service['loaded'])
        self.assertTrue(service['sessionPresent'])

    def test_success_runs_off_assertion_before_registration(self):
        result,calls,service,_,_=self.exercise()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        assertion=next(index for index,call in enumerate(calls) if '--assert-off' in call)
        registration=next(index for index,call in enumerate(calls) if '--register' in call)
        bootstrap=next(index for index,call in enumerate(calls) if call[:2]==['launchctl','bootstrap'])
        self.assertLess(assertion,registration)
        self.assertLess(registration,bootstrap)
        self.assertTrue(service['loaded'])
        self.assertFalse(any(call[0]=='pfctl' for call in calls))

    def test_failed_update_keeps_previously_stopped_service_stopped(self):
        result,_,service,preserved,_=self.exercise(failure='register',loaded=False)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved)
        self.assertFalse(service['loaded'])

    def test_failed_first_install_removes_partial_delivery_assets(self):
        result,_,service,_,_=self.exercise(failure='register',old=False)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(service['assetCount'],0)
        self.assertFalse(service['loaded'])

    def test_uncertain_reference_marker_refuses_commit_and_restores_service(self):
        result,calls,service,preserved,_=self.exercise(marker=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(any('--assert-off' in call for call in calls))
        self.assertFalse(any('--register' in call for call in calls))
        self.assertTrue(service['markerPresent'])
        self.assertTrue(preserved and service['loaded'])

    def test_unknown_launchd_status_cannot_start_update(self):
        result,calls,service,preserved,_=self.exercise(failure='launch_error')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(call[:2]==['launchctl','bootout'] for call in calls))
        self.assertTrue(preserved and service['loaded'])

    def test_rollback_failure_preserves_backup_and_reports_evidence_path(self):
        result,_,_,_,evidence=self.exercise(failure='rollback')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(evidence,result.stdout+result.stderr)
        self.assertIn('回滚未完成',result.stdout)

    def test_uninstall_refuses_delivery_lock_before_stopping_or_deleting(self):
        result,calls,service,preserved,_=self.exercise(script='uninstall.sh',locked=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(calls,[])
        self.assertTrue(preserved and service['loaded'])

    def test_install_refuses_existing_delivery_lock(self):
        result,calls,service,preserved,_=self.exercise(locked=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(calls,[])
        self.assertTrue(preserved and service['loaded'])

    def test_uninstall_active_transaction_retains_assets(self):
        result,_,service,preserved,_=self.exercise(script='uninstall.sh',active=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved and service['loaded'] and service['sessionPresent'])

    def test_uninstall_preference_failure_preserves_assets(self):
        result,_,service,preserved,_=self.exercise(script='uninstall.sh',failure='preferences')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved and service['loaded'])

    def test_uninstall_failed_app_removal_retains_recovery_helper(self):
        result, calls, service, preserved, _ = self.exercise(script='uninstall.sh',failure='remove_app')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(preserved)
        self.assertFalse(service['loaded'])
        self.assertFalse(any(c[0]=='rm' and c[-1].endswith('/PrivilegedHelperTools/local.claudesafelauncher.guard') for c in calls))

    def test_uninstall_removes_delivery_without_deleting_dependencies(self):
        result,calls,service,_,_=self.exercise(script='uninstall.sh')
        self.assertTrue(any(c[0]=='sudo' and '#501' in c for c in calls))
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(service['assetCount'],0)
        self.assertFalse(service['loaded'])
        self.assertTrue(service['dependenciesPresent'])

    def test_untrusted_existing_directory_is_not_repaired_to_pass_assertion(self):
        result,_,service,preserved,_=self.exercise(unsafe_root=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(service['rootMode'],0o777)
        self.assertTrue(preserved and service['loaded'])


if __name__=='__main__':
    unittest.main()
