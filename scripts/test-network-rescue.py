"""Execute the independent rescue against disposable process/PF command fixtures.
Only test copies substitute fixed command paths and the root gate; no real
privileged command, existing-process signal, or network operation is run.
"""
import json
import fcntl
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name('rescue-network.rb')


class RescueTests(unittest.TestCase):
    def run_rescue(self, mode, diagnostic=False, disable_fails=False, daemon_stuck=False,
                   launch_error=False, claude_ancestor=False, unsafe_directory=False,
                   busy_bad_lock=False, override=False):
        with tempfile.TemporaryDirectory(prefix='csg-rescue-test-') as temp:
            root = pathlib.Path(temp)
            private = root / 'private'
            private.mkdir(mode=0o700)
            if unsafe_directory:
                private.chmod(0o777)
            journal = private / 'session.json'
            journal.write_text('{corrupt journal preserved}')
            calls = root / 'calls.jsonl'
            state = root / 'state.json'
            state.write_text(json.dumps({'enabled': True, 'own': True}))
            held_lock = None
            if busy_bad_lock:
                held_lock = (private / 'daemon.lock').open('w')
                (private / 'daemon.lock').chmod(0o666)
                fcntl.flock(held_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            for tool in ['pfctl', 'launchctl', 'pkill', 'pgrep']:
                fake = root / tool
                fake.write_text(f'#!{sys.executable}\nimport sys,json\n'
                    f"calls={str(calls)!r}; state={str(state)!r}; tool={tool!r}\n"
                    "args=sys.argv[1:]\n"
                    "with open(calls,'a') as f:f.write(json.dumps([tool]+args)+'\\n')\n"
                    "s=json.load(open(state))\n"
                    "if tool=='launchctl':\n"
                    "    if args[0]=='print':\n"
                    f"        if {daemon_stuck!r}:sys.exit(0)\n"
                    f"        if {launch_error!r}:print('launchd unavailable',file=sys.stderr);sys.exit(1)\n"
                    "        print('Bad request.\\nCould not find service \\\"local.claudesafelauncher.guard\\\" in domain for system',file=sys.stderr)\n"
                    "        sys.exit(113)\n"
                    "    sys.exit(0)\n"
                    f"if tool=='pgrep' and {claude_ancestor!r} and '-a' in args:print('42');sys.exit(0)\n"
                    "if tool in ['pkill','pgrep']:sys.exit(1)\n"
                    "print('No ALTQ support in kernel',file=sys.stderr)\n"
                    "print('ALTQ related functions disabled',file=sys.stderr)\n"
                    "if args==['-s','Anchors']:print('com.apple')\n"
                    "elif args==['-a','com.apple','-s','Anchors']:\n"
                    "    print('com.apple/200.AirDrop')\n"
                    "    if s['own']:print('com.apple/000.local.claudesafelauncher')\n"
                    "elif args[-1:]==['-sr']:\n"
                    f"    if {diagnostic!r}:print('pfctl: DIOCGETRULES: Invalid argument',file=sys.stderr)\n"
                    "    elif s['own']:print('block drop out quick all')\n"
                    "elif args[-2:]==['-F','rules']:s['own']=False\n"
                    f"elif args==['-d'] and not {disable_fails!r}:s['enabled']=False\n"
                    "elif args==['-s','info']:print('Status: '+('Enabled' if s['enabled'] else 'Disabled'))\n"
                    "json.dump(s,open(state,'w'))\n")
                fake.chmod(0o700)
            # The first RED also handles the not-yet-created independent tool.
            source = SCRIPT.read_text() if SCRIPT.exists() else "abort '助手不存在，无法恢复'\n"
            source = source.replace('Process.euid == 0', 'true')
            source = source.replace("'/Library/Application Support/ClaudeSafeLauncher'", repr(str(private)))
            for tool, original in [('pfctl','/sbin/pfctl'),('launchctl','/bin/launchctl'),
                                   ('pkill','/usr/bin/pkill'),('pgrep','/usr/bin/pgrep')]:
                source = source.replace(original, str(root / tool))
            copy = root / 'rescue.rb'
            copy.write_text(source)
            result = subprocess.run(['/usr/bin/ruby',str(copy),mode]+(['--confirm-unprotected'] if override else []),text=True,capture_output=True,
                                    env={'SUDO_UID':'501','PATH':'/usr/bin:/bin'},timeout=15)
            if held_lock:
                held_lock.close()
            entries = [json.loads(row) for row in calls.read_text().splitlines()] if calls.exists() else []
            return result, entries, json.loads(state.read_text()), journal.read_text()

    def test_force_own_works_without_app_helper_or_valid_journal(self):
        result, calls, state, journal = self.run_rescue('--force-own')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(state['own'])
        self.assertTrue(state['enabled'])
        self.assertNotIn(['pfctl','-d'],calls)
        self.assertEqual(journal,'{corrupt journal preserved}')
        self.assertTrue(any(call[0]=='launchctl' and call[1]=='bootout' for call in calls))
        self.assertNotIn('OFF verified',result.stdout)
        self.assertTrue(all('-X' not in call and '-f' not in call and 'states' not in call and 'all' not in call for call in calls))
        self.assertTrue(all(call == ['pfctl','-a','com.apple/000.local.claudesafelauncher','-F','rules'] for call in calls if '-F' in call))

    def test_last_resort_bypasses_bad_rule_reads_and_verifies_global_disable(self):
        result, calls, state, _ = self.run_rescue('--last-resort',diagnostic=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(state['enabled'])
        self.assertFalse(state['own'])
        self.assertIn(['pfctl','-d'],calls)
        self.assertIn('PF_DISABLED_VERIFIED',result.stdout)

    def test_failed_global_disable_cannot_report_success(self):
        result, _, state, _ = self.run_rescue('--last-resort',disable_fails=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(state['enabled'])
        self.assertNotIn('PF_DISABLED_VERIFIED',result.stdout)

    def test_zero_exit_read_error_blocks_normal_scope_rescue(self):
        result, calls, _, _ = self.run_rescue('--force-own',diagnostic=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(['pfctl','-d'],calls)

    def test_loaded_daemon_blocks_rescue_mutation(self):
        result, calls, state, _ = self.run_rescue('--last-resort',daemon_stuck=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(state['own'] and state['enabled'])
        self.assertFalse(any(call[0]=='pfctl' for call in calls))

    def test_explicit_override_can_disable_despite_unverifiable_preconditions(self):
        for fault in ['daemon_stuck','launch_error','claude_ancestor','busy_bad_lock']:
            result, calls, state, journal = self.run_rescue('--last-resort',override=True,**{fault:True})
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertFalse(state['enabled'])
            self.assertIn('EMERGENCY_UNPROTECTED',result.stdout)
            self.assertNotIn('PF_DISABLED_VERIFIED',result.stdout)
            self.assertEqual(journal,'{corrupt journal preserved}')

    def test_override_cannot_claim_success_if_pf_disable_fails(self):
        result, _, state, _ = self.run_rescue('--last-resort',override=True,daemon_stuck=True,disable_fails=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(state['enabled'])

    def test_unknown_flag_has_no_side_effects(self):
        result, calls, _, _ = self.run_rescue('--unknown')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(calls,[])

    def test_unknown_launchctl_failure_is_not_proof_of_daemon_absence(self):
        result, calls, state, _ = self.run_rescue('--last-resort',launch_error=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(state['enabled'])
        self.assertFalse(any(call[0]=='pfctl' for call in calls))

    def test_claude_ancestor_blocks_mutation_without_killing_its_recovery_shell(self):
        result, calls, state, _ = self.run_rescue('--last-resort',claude_ancestor=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(state['enabled'] and state['own'])
        self.assertFalse(any(call[0]=='pfctl' for call in calls))
        self.assertFalse(any(call[0]=='pkill' and '-a' in call for call in calls))

    def test_last_resort_does_not_depend_on_trusting_damaged_private_metadata(self):
        result, _, state, journal = self.run_rescue('--last-resort',unsafe_directory=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(state['enabled'])
        self.assertEqual(journal,'{corrupt journal preserved}')
        result, calls, state, _ = self.run_rescue('--force-own',unsafe_directory=True)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(state['enabled'])
        self.assertFalse(any(call[0]=='pfctl' for call in calls))

    def test_busy_lock_still_blocks_last_resort_when_its_mode_is_damaged(self):
        result, calls, state, _ = self.run_rescue('--last-resort',busy_bad_lock=True)
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue(state['enabled'] and state['own'])
        self.assertFalse(any(call[0]=='pfctl' for call in calls))


if __name__=='__main__':
    unittest.main()
