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
 def test_friend_old_config_reports_count_without_secrets(self):
  raw=json.dumps({'mode':'rule','proxies':[{'name':'private-name','type':'trojan','password':'NEVER_EMIT_SECRET'}]*22})
  result=subprocess.run(['/usr/bin/ruby','Resources/read-node.rb','--stdin'],input=raw.encode(),capture_output=True)
  self.assertEqual(result.returncode,1)
  self.assertNotIn(b'NEVER_EMIT_SECRET',result.stdout+result.stderr)
  self.assertEqual(json.loads(result.stdout),{'errorCode':'node-count','nodeCount':22})
 def test_errors_are_structured_and_hide_yaml(self):
  for raw,code in [('x: [NEVER_EMIT_SECRET','yaml-invalid'),('{"mode":"rule","proxies":{}}','proxies-shape')]:
   result=subprocess.run(['/usr/bin/ruby','Resources/read-node.rb','--stdin'],input=raw.encode(),capture_output=True)
   self.assertEqual(result.returncode,1)
   self.assertEqual(json.loads(result.stdout)['errorCode'],code)
   self.assertNotIn(b'NEVER_EMIT_SECRET',result.stdout+result.stderr)
if __name__=='__main__':unittest.main()
