"""Execute real early read-only handler. Never root, sudo, install or network."""
from pathlib import Path
import shutil,subprocess,tempfile,unittest
root=Path(__file__).resolve().parents[1]
class ResourceTests(unittest.TestCase):
 def test_actual_payload_and_missing_or_symlink_rejection(self):
  with tempfile.TemporaryDirectory() as folder:
   p=Path(folder);(p/'scripts').mkdir();(p/'dist').mkdir()
   shutil.copy2(root/'scripts/install.sh',p/'scripts/install.sh')
   archive=p/'dist/ClaudeSafeLauncher-test.zip'
   def check():return subprocess.run(['/bin/bash',str(p/'scripts/install.sh'),'--check-resources'],capture_output=True,text=True,timeout=3)
   self.assertEqual(check().returncode,2)
   # A historical filename must not satisfy the real resource check.
   (p/'dist/ClaudeSafeLauncher-0.5.29-test.zip').write_bytes(b'fixture')
   self.assertEqual(check().returncode,2)
   archive.write_bytes(b'fixture')
   result=check();self.assertEqual(result.returncode,0,result.stderr);self.assertIn('未安装或修改系统',result.stdout)
   archive.unlink();archive.symlink_to('ClaudeSafeLauncher-0.5.29-test.zip');self.assertEqual(check().returncode,2)
if __name__=='__main__':unittest.main()
