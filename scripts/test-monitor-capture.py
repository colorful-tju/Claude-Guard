"""Only disposable collection fixtures; never real PF, root operations, or public probes."""
import json,pathlib,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='monitor-capture-') as temp:
    base=pathlib.Path(temp);private=base/'private';private.mkdir();scripts=base/'scripts';scripts.mkdir()
    (private/'last-monitoring-failure.json').write_text(json.dumps({'kind':'monitoringFailure','diagnosticMarker':'SAMPLE029','baseline':{'ownReference':'SECRET_MONITOR_TOKEN'},'current':None}))
    (private/'last-socket-observation.json').write_text(json.dumps({'meaning':'SOCKET031 passive metadata only','ownReference':'SECRET_SOCKET_TOKEN'}))
    (private/'last-monitoring-degradation.json').write_text(json.dumps({'state':'recovered','diagnosticMarker':'INVENTORY016'}))
    source=(root/'scripts/capture-incident.sh').read_text().replace('if [[ "$EUID" -ne 0 ]]; then','if false; then')
    source=source.replace("root='/Library/Application Support/ClaudeSafeLauncher'",'root='+str(private))
    source=source.replace('/usr/sbin/sysctl -n kern.bootsessionuuid','echo fixture-boot')
    source=source.replace('/bin/ps -axo pid,ppid,uid,comm','echo fixture-processes')
    source=source.replace('/sbin/route -n get -inet6 default','echo fixture-no-route')
    (scripts/'capture-incident.sh').write_text(source)
    (scripts/'redact-incident.rb').write_text((root/'scripts/redact-incident.rb').read_text())
    (scripts/'capture-pf-environment.sh').write_text('echo fixture-PF-read-only\n')
    result=subprocess.run(['/bin/bash',str(scripts/'capture-incident.sh')],capture_output=True,text=True,check=True)
    assert 'INVENTORY016' in result.stdout
    assert 'SOCKET031' in result.stdout and 'SECRET_SOCKET_TOKEN' not in result.stdout+result.stderr
    assert 'SAMPLE029' in result.stdout,'New monitoring report missing from incident collector'
    assert 'SECRET_MONITOR_TOKEN' not in result.stdout+result.stderr
    (private/'last-monitoring-failure.json').write_text('invalid SECRET_MALFORMED_MONITOR')
    result=subprocess.run(['/bin/bash',str(scripts/'capture-incident.sh')],capture_output=True,text=True)
    assert 'SECRET_MALFORMED_MONITOR' not in result.stdout+result.stderr
print('PASS collector includes monitoring failure and suppresses raw tokens on valid/invalid JSON')
