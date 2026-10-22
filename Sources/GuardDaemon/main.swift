import Foundation
import Darwin
import GuardRuntime
import NativeGuard
// No privileged operations occur without --serve / --recover / --register and real root.
do {
    let args=Array(CommandLine.arguments.dropFirst())
    if args == ["--self-test-timer"] {
        let queue=DispatchQueue(label:"guard.timer-self-test")
        let done=DispatchSemaphore(value:0)
        let timer=DaemonTimer.start(on:queue,after:0.02,repeating:0.02) {
            dispatchPrecondition(condition:.onQueue(queue));done.signal()
        }
        for _ in 0..<3 {
            guard done.wait(timeout:.now()+2) == .success else{throw fail("Timer self-test timeout")}
        }
        timer.cancel();print("Timer self-test passed (3 off-main ticks); no privileged operations");exit(0)
    }
    guard geteuid()==0 else{throw fail("GuardDaemon requires administrator installation; do not run via UI as root")}
    var st=stat();guard lstat(Paths.root,&st)==0,st.st_uid==0,(st.st_mode&S_IFMT)==S_IFDIR,(st.st_mode&0o022)==0 else{throw fail("Private root directory is not trustworthy")}
    let lockfd=open(Paths.root+"/daemon.lock",O_RDWR|O_CREAT|O_NOFOLLOW,0o600)
    guard lockfd>=0,flock(lockfd,LOCK_EX|LOCK_NB)==0 else{throw fail("Another daemon owns the transaction")}
    if [2,4].contains(args.count),args[0]=="--register",let uid=UInt32(args[1]),uid>=501,let pwd=getpwuid(uid) {
        guard !FileManager.default.fileExists(atPath:Paths.root+"/ipv6-override.json"), !FileManager.default.fileExists(atPath:Paths.root+"/session.json") else{throw fail("Recover active session before updating")}
        let corePath=args.count==4 ? args[2]:"/Applications/FlClash.app/Contents/MacOS/FlClashCore"
        let configPath=args.count==4 ? args[3]:String(cString:pwd.pointee.pw_dir)+"/Library/Application Support/com.follow.clash/config.yaml"
        guard corePath.hasPrefix("/"),configPath.hasPrefix("/"), !corePath.contains("\n"), !configPath.contains("\n") else{throw fail("Proxy registration requires absolute paths")}
        var install=Installation(uid:uid,home:String(cString:pwd.pointee.pw_dir),clients:[try codeHash(path:Paths.app+"/Contents/MacOS/ClaudeSafeLauncher"),try codeHash(path:Paths.app+"/Contents/Resources/guardctl")],coreHash:try codeHash(path:corePath),flclashHash:"",claudeHash:try codeHash(path:"/Applications/Claude.app"))
        install.proxyCorePath=corePath;install.proxyConfigPath=configPath
        try PrivateFiles.write(install,to:Paths.root+"/installation.json");print("Registered UID and signed build identities; no PF or network changes")
    } else if args==["--assert-off"] {
        guard !FileManager.default.fileExists(atPath:Paths.root+"/ipv6-override.json"), !FileManager.default.fileExists(atPath:Paths.root+"/session.json"),
              !FileManager.default.fileExists(atPath:Paths.root+"/enable-result.txt") else{throw fail("Active or uncertain transaction remains")}
        guard try PacketFilter(commands:Commands()).canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("Own anchor is not empty")}
        print("OFF assets check under daemon lock passed")
    } else if args==["--restore-ipv6"] {
        // Explicit recovery after --force-own. Never releases PF assets or launches an app.
        let install=try PrivateFiles.read(Paths.root+"/installation.json",as:Installation.self)
        guard try PacketFilter(commands:Commands()).canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("Clear own PF restrictions before standalone IPv6 recovery")}
        try NativeProcesses.terminateClaude(uid:install.uid)
        try TemporaryIPv6().restore()
        print("IPv6 original preferences restored and read back; PF transaction assets unchanged")
    } else if args==["--serve"] || args==["--recover"] {
        let install=try PrivateFiles.read(Paths.root+"/installation.json",as:Installation.self)
        let controller=try Controller(installation:install)
        if args==["--recover"] {
            let reply=controller.handle(.init(.shutdown));print(String(decoding:try JSONEncoder().encode(reply),as:UTF8.self));if !reply.ok{exit(2)}
        } else {
            let queue=controller.queue
            let admission=RequestAdmission()
            let server=csg_listen(Paths.socket,install.uid);guard server>=0 else{throw fail("Cannot create restricted control socket")}
            let timer=DaemonTimer.start(on:queue){controller.tick()}
            defer{timer.cancel()}
            // Socket authentication/read off the transaction queue: heartbeat remains independent of probes.
            while true {
                let client=accept(server,nil,nil);if client<0 {if errno==EINTR{continue};throw fail("IPC accept failed")}
                DispatchQueue.global().async {
                    defer{close(client)}
                    do {
                        var token=[UInt8](repeating:0,count:32);var uid:UInt32=0;var pid:Int32=0
                        guard csg_peer(client,&token,&uid,&pid)==0,uid==install.uid,install.clients.contains(try guestHash(token:Data(token))) else{throw fail("Unregistered client rejected")}
                        // Per-client read/write deadline guards against partial-frame stalls.
                        var timeout=timeval(tv_sec:5,tv_usec:0);setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,socklen_t(MemoryLayout<timeval>.size));setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,socklen_t(MemoryLayout<timeval>.size))
                        let request=try JSONDecoder().decode(Request.self,from:Wire.read(client))
                        guard request.protocolVersion==BuildIdentity.protocolVersion,UUID(uuidString:request.id) != nil else{throw fail("IPC protocol mismatch")}
                        if [.refreshClaudeRegistration,.heartbeat,.selfTest,.start,.verify,.ipv6Off,.ipv6Automatic,.ipv6Restore].contains(request.operation) {
                            guard try guestHash(token:Data(token))==install.clients.first else{throw fail("Only the registered desktop UI may start or keep a session alive")}
                        }
                        if request.operation == .heartbeat {
                            try controller.heartbeat(clientPID:pid);var ack=Status();ack.phase="heartbeatAcknowledged"
                            var reply=Reply(ok:true,status:ack);reply.requestID=request.id
                            try Wire.write(JSONEncoder().encode(reply),client);return
                        }
                        if request.operation == .progress {
                            var reply=Reply(ok:true,status:controller.progressStatus());reply.requestID=request.id
                            try Wire.write(JSONEncoder().encode(reply),client);return
                        }
                        let ticket=admission.ticket()
                        if [.refreshClaudeRegistration,.selfTest,.start,.verify,.ipv6Off,.ipv6Automatic,.ipv6Restore].contains(request.operation){try controller.heartbeat(clientPID:pid)}
                        if [.stop,.shutdown].contains(request.operation){admission.cancelPendingStarts();controller.requestStop(restoreIPv6:request.operation == .shutdown)}
                        var reply=queue.sync{ ()->Reply in
                            if [.refreshClaudeRegistration,.selfTest,.start,.verify,.ipv6Off,.ipv6Automatic,.ipv6Restore].contains(request.operation),!admission.accepts(ticket){return Reply(ok:false,status:controller.status,error:"Queued start cancelled by OFF")}
                            return controller.handle(request)
                        };reply.requestID=request.id
                        try Wire.write(JSONEncoder().encode(reply),client)
                    }catch { /* Fail closed; no state-changing command processed on unauthenticated input. */ }
                }
            }
        }
    } else {throw fail("Use --serve, --recover or --register <uid>")}
} catch {fputs("GuardDaemon: \(error)\n",stderr);exit(1)}
