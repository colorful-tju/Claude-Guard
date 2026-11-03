"""Recovery UI smoke tests using a fake script; never runs privileged commands."""
import os
import pathlib
import subprocess
import tempfile
import unittest

class EntryTests(unittest.TestCase):
    def test_log_failure_does_not_block_explicit_scoped_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            source=pathlib.Path(__file__).resolve().parent.parent/'恢复网络.command'
            (root/'entry.command').write_text(source.read_text())
            (root/'scripts').mkdir()
            (root/'scripts/emergency-recover.sh').write_text('echo "FIXTURE $*"; [[ "$2" == --confirm-unprotected ]]')
            result=subprocess.run(['/bin/bash',str(root/'entry.command')],input='2\nUNPROTECT_OWN\n\n',capture_output=True,text=True,errors="replace",env={**os.environ,'HOME':str(root/'missing'),'TMPDIR':str(root/'missing')},timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('无法创建记录文件',result.stdout)
            self.assertIn('FIXTURE --force-own --confirm-unprotected',result.stdout)
            self.assertNotIn('FIXTURE --last-resort',result.stdout)

if __name__=='__main__': unittest.main()
