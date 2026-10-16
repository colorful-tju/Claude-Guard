#!/usr/bin/env python3
"""Offline process regressions; compiles the production runner with a local child."""
from pathlib import Path
import subprocess, tempfile
root = Path(__file__).resolve().parents[1]
child_source = r'''
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include "NativeGuard.h"
int main(int argc,char **argv) {
 if(argc<2)return 2;
 if(!strcmp(argv[1],"nested")){CSGCommand child;char *args[]={"/bin/sleep","2",NULL};if(csg_command_spawn_inherited("/bin/sleep",args,&child))return 4;return 0;}
 if(!strcmp(argv[1],"hold")){if(fork()==0){signal(SIGTERM,SIG_IGN);usleep(1200000);_exit(0);}return 0;}
 if(!strcmp(argv[1],"stdin")){usleep(300000);char b[4096];while(read(0,b,sizeof(b))>0){}return 0;}
 if(!strcmp(argv[1],"sleep")){signal(SIGTERM,SIG_IGN);usleep(1200000);return 0;}
 if(!strcmp(argv[1],"flood")){char b[16384];memset(b,'x',sizeof(b));for(int i=0;i<512;i++)if(write(1,b,sizeof(b))<0)return 0;return 0;}
 if(!strcmp(argv[1],"echo")){write(1,"output\n",7);write(2,"error\n",6);return 0;}
 if(!strcmp(argv[1],"marker")){write(2,"native-start\n",13);signal(SIGTERM,SIG_IGN);usleep(1200000);return 0;}
 if(!strcmp(argv[1],"fdcheck")){return fcntl(atoi(argv[2]),F_GETFD)<0?0:3;}
 if(!strcmp(argv[1],"closed-input")){close(0);usleep(20000);return 0;}
 return 2;
}
'''
harness = r'''
import Foundation
import Darwin
struct LocalFailure:Error,CustomStringConvertible {var description:String}
func fail(_ message:String)->LocalFailure{.init(description:message)}
final class LocalCancellation:@unchecked Sendable {
 let lock=NSLock(),started=DispatchSemaphore(value:0);var calls=0,flag=false
 func poll()->Bool{lock.lock();defer{lock.unlock()};calls+=1;if calls==2{started.signal()};return flag}
 func cancel(){lock.lock();flag=true;lock.unlock()}
}
@main enum LocalRunnerTests {
 static func main() throws {
  let child=CommandLine.arguments[1],command=Commands()
  func bounded(_ mode:String,input:Data?=nil)throws {
   let start=DispatchTime.now().uptimeNanoseconds
   var rejected=false
   do{_ = try command.run(child,[mode],timeout:0.08,input:input)}catch{rejected=true}
   let elapsed=Double(DispatchTime.now().uptimeNanoseconds-start)/1e9
   guard rejected,elapsed<1.0 else{throw fail("FAIL \(mode): rejected=\(rejected) elapsed=\(elapsed)")}
   print("PASS \(mode) deadline \(elapsed)")
  }
  try bounded("hold")
  try bounded("nested")
  try bounded("stdin",input:Data(repeating:65,count:1024*1024))
  try bounded("sleep")
  var rejected=false
  do{_ = try command.run(child,["flood"],timeout:2)}catch{rejected=true}
  guard rejected else{throw fail("FAIL output cap")}
  let r=try command.run(child,["echo"])
  guard r.status==0,r.output=="output\n",r.error=="error\n" else{throw fail("FAIL stdout/stderr")}
  print("PASS cap and stdout/stderr")
  try command.assertQuiescent()
  let gate=LocalCancellation(),done=DispatchGroup();done.enter()
  DispatchQueue.global().async{defer{done.leave()};_ = try? command.run(child,["sleep"],timeout:2,cancelled:{gate.poll()})}
  guard gate.started.wait(timeout:.now()+2) == .success else{throw fail("FAIL worker start")}
  var activeRejected=false;do{try command.assertQuiescent()}catch{activeRejected=true}
  gate.cancel();guard done.wait(timeout:.now()+2) == .success,activeRejected else{throw fail("FAIL active worker quiescence")}
  try command.assertQuiescent()
  var brokenRejected=false
  do{_ = try command.run(child,["closed-input"],timeout:1,input:Data(repeating:1,count:1024*1024))}catch{brokenRejected=true}
  guard brokenRejected else{throw fail("FAIL incomplete stdin")};try command.assertQuiescent()
  let cancelAt=DispatchTime.now().uptimeNanoseconds+30_000_000
  let start=DispatchTime.now().uptimeNanoseconds
  do{_ = try command.run(child,["sleep"],timeout:2,cancelled:{DispatchTime.now().uptimeNanoseconds>=cancelAt});throw fail("FAIL cancellation accepted")}
  catch let error as CommandFailure{guard error.stage=="cancelled",Double(DispatchTime.now().uptimeNanoseconds-start)/1e9<1 else{throw fail("FAIL cancellation deadline")}}
  try command.assertQuiescent()
  do{_ = try command.run(child,["marker","SECRET_ARGUMENT"],timeout:0.08);throw fail("FAIL marker accepted")}
  catch let error as CommandFailure{guard error.stderrPrefix.contains("native-start"),!error.description.contains("native-start"),!error.description.contains("SECRET_ARGUMENT") else{throw fail("FAIL diagnostics privacy")}}
  let recording=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
  let fd=open(recording,O_RDWR|O_CREAT|O_EXCL,0o600)
  guard fd>=0 else{throw fail("FAIL recording create")}
  defer{close(fd);unlink(recording)}
  _ = try command.checked(child,["echo"],recordingTo:fd)
  let data=try Data(contentsOf:URL(fileURLWithPath:recording)),text=String(decoding:data,as:UTF8.self)
  guard text.contains("output\n"),text.contains("error\n") else{throw fail("FAIL streamed recording")}
  _ = try command.checked(child,["fdcheck",String(fd)])
  let environment=try command.checked("/usr/bin/env",[])
  guard !environment.contains("HOME="),environment.contains("LC_ALL=C") else{throw fail("FAIL sanitized environment")}
  try command.assertQuiescent()
  print("PASS cancellation, bounded private diagnostics, durable tee, descriptor isolation, quiescence")
 }
}
'''
with tempfile.TemporaryDirectory(prefix='csg-command-test-') as temp:
 p=Path(temp);(p/'child.c').write_text(child_source);(p/'Tests.swift').write_text(harness)
 runner=root/'Sources/GuardRuntime/CommandRunner.swift'
 if runner.exists():
  source=runner.read_text().replace('import GuardCore\n','')
 else:
  support=(root/'Sources/GuardRuntime/Support.swift').read_text()
  source='import Foundation\nimport Darwin\n'+support[support.index('private final class OutputBox:'):support.index('public func codeHash')]
 (p/'Runner.swift').write_text(source)
 (p/'module.modulemap').write_text('module NativeGuard { header "'+str(root/'Sources/NativeGuard/include/NativeGuard.h')+'" export * }\n')
 subprocess.run(['clang','-c','-I',str(root/'Sources/NativeGuard/include'),str(root/'Sources/NativeGuard/native.c'),'-o',str(p/'native.o')],check=True)
 subprocess.run(['clang','-I',str(root/'Sources/NativeGuard/include'),str(p/'child.c'),str(p/'native.o'),'-lproc','-lbsm','-o',str(p/'child')],check=True)
 subprocess.run(['swiftc','-swift-version','6','-module-cache-path',str(p/'cache'),'-I',str(p),str(p/'Runner.swift'),str(p/'Tests.swift'),str(p/'native.o'),'-lproc','-lbsm','-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test'),str(p/'child')],check=True,timeout=15)
