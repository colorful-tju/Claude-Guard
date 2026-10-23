"""Run the real collector with PF/process commands and the root gate substituted.

No privileged commands or network probes run. The substitutes exist only in a
temporary test copy, never as environment overrides in the production script.
"""
import json
import pathlib
import subprocess
import tempfile
import unittest


class CaptureTests(unittest.TestCase):
    def capture(self, diagnostic=False, own_present=True, sharing=False):
        original = pathlib.Path(__file__).with_name("capture-pf-environment.sh").read_text()
        with tempfile.TemporaryDirectory(prefix="csg-pf-capture-") as temp:
            directory = pathlib.Path(temp)
            calls = directory / "calls.jsonl"
            fake = directory / "pfctl"
            fake.write_text("#!/usr/bin/env python3\nimport json, sys\n"
                            f"with open({str(calls)!r}, 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                            "print('No ALTQ support in kernel', file=sys.stderr)\n"
                            "print('ALTQ related functions disabled', file=sys.stderr)\n"
                            "if sys.argv[1:] == ['-s', 'Anchors']: print('com.apple')\n"
                            f"if {sharing!r} and sys.argv[1:] == ['-s', 'Anchors']: print('com.apple.internet-sharing')\n"
                            f"if {sharing!r} and sys.argv[1:] == ['-a', 'com.apple.internet-sharing', '-s', 'Anchors']: print('com.apple.internet-sharing/host_v4\\ncom.apple.internet-sharing/host_v6')\n"
                            "if sys.argv[1:] == ['-a', 'com.apple', '-s', 'Anchors']:\n"
                            "    print('  com.apple/200.AirDrop\\n  com.apple/250.ApplicationFirewall')\n"
                            f"    if {own_present!r}: print('  com.apple/000.local.claudesafelauncher')\n"
                            f"if not {own_present!r} and 'com.apple/000.local.claudesafelauncher' in sys.argv:\n"
                            "    print('pfctl: DIOCGETRULES: Invalid argument', file=sys.stderr)\n"
                            f"if {diagnostic!r} and sys.argv[1:] in "
                            "[['-a', '*', '-sr'], ['-a', 'com.apple/200.AirDrop', '-sr']]:\n"
                            "    print('pfctl: DIOCGETRULES: Invalid argument', file=sys.stderr)\n"
                            "# This macOS failure returns zero despite the error diagnostic.\n")
            fake.chmod(0o700)
            script = directory / "capture.sh"
            script.write_text(original.replace('if [[ "$EUID" -ne 0 ]]; then', 'if false; then')
                              .replace('/sbin/pfctl', str(fake)).replace('/bin/ps -axo pid,ppid,uid,comm', '/usr/bin/true'))
            result = subprocess.run(['/bin/bash', str(script)], capture_output=True, text=True)
            return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_sharing_children_are_captured_when_present_only(self):
        for sharing in [False, True]:
            result, calls = self.capture(sharing=sharing)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for anchor in ["com.apple.internet-sharing", "com.apple.internet-sharing/host_v4", "com.apple.internet-sharing/host_v6"]:
                for suffix in [["-sr"], ["-sn"], ["-s", "Anchors"]]:
                    self.assertEqual(["-a", anchor] + suffix in calls, sharing)

    def test_zero_exit_with_ioctl_error_is_reported_as_failed_capture(self):
        result, _ = self.capture(diagnostic=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('captureReadFailures=0', result.stdout)
        self.assertIn('DIOCGETRULES', result.stdout)

    def test_empty_anchor_bodies_are_queried_directly_without_recursive_ioctl(self):
        result, calls = self.capture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('captureReadFailures=0', result.stdout)
        for anchor in ['com.apple', 'com.apple/200.AirDrop',
                       'com.apple/250.ApplicationFirewall',
                       'com.apple/000.local.claudesafelauncher']:
            for arguments in [['-sr'], ['-sn'], ['-s', 'Anchors']]:
                self.assertIn(['-a', anchor] + arguments, calls)
        for arguments in calls:
            self.assertNotIn('*', arguments)
            self.assertTrue(all(value not in arguments for value in
                                ['-E', '-X', '-d', '-e', '-f', '-F']))

    def test_known_absent_own_anchor_is_not_queried_or_reported_as_failed(self):
        result, calls = self.capture(own_present=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('captureReadFailures=0', result.stdout)
        self.assertFalse(any('com.apple/000.local.claudesafelauncher' in call for call in calls))


if __name__ == '__main__':
    unittest.main()
