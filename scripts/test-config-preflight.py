"""Run staged read-only preflight as ordinary user, without private root/daemon lock."""
from pathlib import Path
import os,subprocess,tempfile,shutil,json
root=Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='guard-config-preflight-') as directory:
 p=Path(directory)
 shutil.copy2(root/'.build/debug/guard-daemon',p/'guard-daemon')
 shutil.copy2(root/'Resources/read-node.rb',p/'read-node.rb')
 node=p/'node.yaml'
 for count in [1,22]:
  node.write_text(json.dumps({'mode':'rule','proxies':[{'name':'test','type':'http','server':'1.2.3.4','port':8080}]*count}))
  result=subprocess.run([str(p/'guard-daemon'),'--check-config',str(os.getuid()),str(node)],capture_output=True,text=True,timeout=15)
  assert (result.returncode==0)==(count==1),result.stderr
  if count==22:assert '22' in result.stderr
print('PASS staged configuration preflight without private root or daemon lock; no network changes')
