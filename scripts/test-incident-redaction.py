import json, pathlib, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    file=pathlib.Path(temp)/'session.json'
    file.write_text(json.dumps({'token':'SECRET1','initialReferences':'SECRET2','policy':{'gateway':'23.20.10.8'},'nested':{'ownReference':'SECRET3'},'allowedStates':['SECRET4']}))
    result=subprocess.run(['/usr/bin/ruby',str(root/'scripts/redact-incident.rb'),str(file)],capture_output=True,text=True,check=True)
    assert 'SECRET' not in result.stdout
    assert json.loads(result.stdout)['policy']['gateway']=='23.20.10.8'
    file.write_text('invalid SECRET5')
    result=subprocess.run(['/usr/bin/ruby',str(root/'scripts/redact-incident.rb'),str(file)],capture_output=True,text=True)
    assert result.returncode!=0 and 'SECRET' not in result.stdout+result.stderr
print('PASS incident nested token redaction and parse-error suppression')
