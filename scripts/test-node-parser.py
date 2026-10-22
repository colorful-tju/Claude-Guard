"""Pure candidate parser validation; no network or privileged operations."""
import json,hashlib,pathlib,subprocess,tempfile,unittest
class ParserTests(unittest.TestCase):
 def test_reject_ambiguous_documents_and_invalid_ipv4(self):
  template="mode: rule\nproxies:\n  - name: test\n    type: http\n    server: ADDRESS\n    port: 8080\nrules: [MATCH,test]\n"
  with tempfile.TemporaryDirectory() as folder:
   path=pathlib.Path(folder)/'node.yaml'
   for address,suffix,valid in [('1.2.3.4','',True),('999.2.3.4','',False),('01.2.3.4','',False),('1.2.3.4','---\nmode: direct\n',False)]:
    path.write_text(template.replace('ADDRESS',address)+suffix)
    result=subprocess.run(['/usr/bin/ruby','Resources/read-node.rb',str(path)],capture_output=True)
    self.assertEqual(result.returncode==0,valid,result.stderr.decode())
    stdin=subprocess.run(['/usr/bin/ruby','Resources/read-node.rb','--stdin'],input=path.read_bytes(),capture_output=True)
    self.assertEqual(stdin.returncode==0,valid,stdin.stderr.decode())
    if valid:
     self.assertEqual(json.loads(stdin.stdout),json.loads(result.stdout))
     self.assertEqual(json.loads(stdin.stdout)['fingerprint'],hashlib.sha256(path.read_bytes()).hexdigest())
if __name__=='__main__':unittest.main()
