#!/usr/bin/env python3
"""Opt-in integration test. Real copied Core, synthetic config, IP network denied.
Usage: python3 scripts/test-entry-core-offline.py --core /path/to/FlClashCore
No existing IPC, user profile, PF, TUN, system proxy or real probe is used.
"""
import argparse,copy,json,os,pathlib,socket,struct,subprocess,tempfile,threading,time
root=pathlib.Path(__file__).resolve().parents[1]

def run(core, config, serialized=None):
    with tempfile.TemporaryDirectory(prefix='cg-offline-',dir='/private/tmp') as td:
        home=pathlib.Path(td);binary=home/'core'
        binary.write_bytes(core.read_bytes());binary.chmod(0o700)
        subprocess.run(['/usr/bin/codesign','--verify','--strict',str(binary)],check=True,capture_output=True)
        path=str(home/'ipc');listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen(1);listener.settimeout(8)
        profile=f'(version 1)(allow default)(deny network*)(allow network-outbound (literal "{path}"))'
        process=subprocess.Popen(['/usr/bin/sandbox-exec','-p',profile,str(binary),path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={'HOME':td,'TMPDIR':td,'PATH':'/usr/bin:/bin'})
        connection=None
        try:
            connection,_=listener.accept()
            def rpc(identifier,method,arguments):
                deadline=time.monotonic()+8
                def read(count):
                    result=b''
                    while len(result)<count:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:raise TimeoutError('offline IPC deadline')
                        connection.settimeout(remaining)
                        chunk=connection.recv(count-len(result))
                        if not chunk:raise RuntimeError('offline IPC EOF')
                        result+=chunk
                    return result
                payload=json.dumps(dict(id=identifier,method=method,arguments=arguments)).encode()
                connection.sendall(struct.pack('<I',len(payload))+payload)
                for _ in range(32):
                    size=struct.unpack('<I',read(4))[0]
                    if not 0<size<=262144:raise RuntimeError('offline frame size')
                    reply=json.loads(read(size))
                    if reply.get('id')==identifier:return reply
                    if reply.get('method')!='message':raise RuntimeError('unexpected offline IPC')
                raise RuntimeError('too many offline events')
            initial=rpc('1','core.init',{'home-dir':td,'version':0})
            assert not initial.get('error'),initial
            os.mkfifo(home/'config.yaml',0o600)
            def feed():
                with open(home/'config.yaml','w') as writer:
                    os.unlink(home/'config.yaml')
                    writer.write(serialized if serialized is not None else json.dumps(config))
            thread=threading.Thread(target=feed,daemon=True);thread.start()
            result=rpc('2','config.setup',{'selected-map':{},'options':{'skip-cert-verify':False}})
            thread.join(timeout=1);assert not thread.is_alive(),'config FIFO incomplete'
            return result
        finally:
            if connection:connection.close()
            listener.close()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--core',type=pathlib.Path,required=True);parser.add_argument('--serialized-config',type=pathlib.Path);args=parser.parse_args()
    if os.getuid()==0 or os.geteuid()!=os.getuid():raise SystemExit('Run as an unprivileged user')
    if args.serialized_config:
        wire=args.serialized_config.read_text()
        config=json.loads(wire)
        assert config['dns']['enable'] is False and config['tun']['enable'] is False
        old_wire=wire.replace('/',r'\/')
        if old_wire != wire:
            failure=run(args.core,config,old_wire)
            assert failure.get('error',{}).get('message')=='yaml: found unknown escape character',failure
        success=run(args.core,config,wire)
        assert success.get('error') is None and 'result' in success,success
        print('PASS: production Swift FIFO bytes loaded; slash negative checked when applicable; IP network denied')
        raise SystemExit(0)
    node={'name':'synthetic','type':'vless','server':'entry.example.com','port':443,'network':'ws','tls':True,'servername':'tls.example.com','flow':None,'uuid':'01234567-89ab-cdef-0123-456789abcdef','ws-opts':{'path':'/synthetic','headers':{'Host':'tls.example.com'}}}
    request=dict(yaml=json.dumps({'proxies':[node]}),nodeName='synthetic',entryIPv4='1.2.3.4',physical='en0')
    extracted=subprocess.run(['/usr/bin/ruby',str(root/'Resources/prepare-entry-probe.rb')],input=json.dumps(request),text=True,capture_output=True,check=True)
    config=json.loads(extracted.stdout)['config']
    assert config['dns']['enable'] is False and config['tun']['enable'] is False
    broken=copy.deepcopy(config);broken['dns']['default-nameserver']=[]
    failure=run(args.core,broken)
    assert failure.get('error',{}).get('code')=='config_rejected',failure
    assert failure['error']['message']=='default nameserver should have at least one nameserver',failure
    success=run(args.core,config)
    assert success.get('error') is None and 'result' in success,success
    print('PASS: full generated config accepted; old empty-bootstrap config rejected; IP network denied; no probe called')
