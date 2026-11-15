import Foundation
import Darwin
import NativeGuard
import GuardCore

/// User-initiated diagnostic only. Never installs PF or authorizes a protected session.
public struct EntryProbeResult:Sendable {
    public let entry:String
    public let exit:String
}
public struct EntryProbeDiagnostic:Codable,Sendable {
    public let candidate:String
    public let stage:String
    public let outcome:String
    public let timestamp:String
    public init(candidate:String,stage:String,outcome:String){self.candidate=candidate;self.stage=stage;self.outcome=outcome;self.timestamp=ISO8601DateFormatter().string(from:Date())}
}
public final class EntryProbeCancellation:@unchecked Sendable {
    private let lock=NSLock();private var value=false
    public init(){}
    public func cancel(){lock.lock();value=true;lock.unlock()}
    public var cancelled:Bool {lock.lock();defer{lock.unlock()};return value}
}

/// FLClash 0.9.3 private IPC framing, used ONLY with our own non-setuid child.
/// No connection is ever made to an existing Core IPC or controller.
enum EntryProbeFrame {
    static let maximum=256*1024
    static func encode(_ object:[String:Any]) throws -> Data {
        let body=try JSONSerialization.data(withJSONObject:object)
        guard body.count>0,body.count<=maximum else{throw fail("Entry probe frame oversized")}
        var count=UInt32(body.count).littleEndian
        return withUnsafeBytes(of:&count){Data($0)}+body
    }
    static func length(_ header:Data) throws -> Int {
        guard header.count==4 else{throw fail("Entry probe frame header invalid")}
        let n=header.enumerated().reduce(UInt32(0)){$0 | UInt32($1.element) << (8*$1.offset)}
        guard n>0,n<=maximum else{throw fail("Entry probe frame oversized")};return Int(n)
    }
    static func response(_ bytes:Data,id:String) throws -> [String:Any]? {
        if let event=try JSONSerialization.jsonObject(with:bytes) as? [String:Any],
           Set(event.keys)==Set(["method","arguments"]),event["method"] as? String=="message",event["arguments"] is [Any] {return nil}
        if let value=try JSONSerialization.jsonObject(with:bytes) as? [String:Any],value["id"] as? String==id,
           let error=value["error"] as? [String:Any],error["code"] as? String=="config_rejected" {
            // Never forward arbitrary Core messages: they may contain configuration values.
            if error["message"] as? String=="default nameserver should have at least one nameserver" {
                throw fail("隔离配置加载失败：Core 要求非空 default-nameserver")
            }
            throw fail("隔离配置被 Core 拒绝（config_rejected）")
        }
        guard let value=try JSONSerialization.jsonObject(with:bytes) as? [String:Any],value["id"] as? String==id,value.keys.contains("result"),
              value["error"] == nil || value["error"] is NSNull,
              value["file"] == nil || value["file"] is NSNull else{throw fail("Entry probe IPC reply rejected")}
        return value
    }
}

public enum EntryProbe {
    /// The fingerprint and signed Core identity must come from the authenticated daemon.
    public static func run(status:Status,settings:Settings,resources:String,cancellation:EntryProbeCancellation,diagnostic:@escaping @Sendable (EntryProbeDiagnostic)->Void = {_ in}) throws -> [EntryProbeResult] {
        guard getuid() != 0,geteuid()==getuid(),status.phase=="off",
              let core=status.entryProbeCorePath,let identity=status.entryProbeCoreHash,
              let path=status.configurationPath,let name=settings.entryName,
              let entry=status.chainCandidate?.entries.first(where:{$0.name==name}),
              settings.effectivePathMode == .chain else{throw fail("前置测试条件未满足，请先重新检测配置")}
        // IPC and side-effect semantics have only been reviewed for this release.
        let info=URL(fileURLWithPath:core).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Info.plist")
        guard let plist=NSDictionary(contentsOf:info),plist["CFBundleShortVersionString"] as? String == "0.9.3",
              URL(fileURLWithPath:core).lastPathComponent=="FlClashCore",try codeHash(path:core)==identity else{throw fail("前置独立测试暂仅支持已登记的 FLClash 0.9.3 Core")}
        let raw=try ProxyConfiguration.bytes(path:path,uid:getuid())
        guard hash(raw)==status.fingerprint,let yaml=String(data:raw,encoding:.utf8) else{throw fail("测试前配置已改变，请重新读取")}
        let physical=try UDPProtection.physical(settings.physical)
        let candidates=Array(Set(status.entryCandidates ?? [])).sorted()
        guard !candidates.isEmpty,candidates.count<=8,candidates.allSatisfy(IPv4.isPublic) else{throw fail("未取得可测试的活动 Core 连接（最多 8 个）；请先固定前置并产生一次连接")}
        var results:[EntryProbeResult]=[]
        for ip in candidates {
            diagnostic(.init(candidate:ip,stage:"参数提取",outcome:"开始"))
            if cancellation.cancelled {throw fail("前置验证已取消")}
            guard try UDPProtection.physical(settings.physical)==physical else{throw fail("前置测试期间物理接口改变")}
            let input=try JSONSerialization.data(withJSONObject:["yaml":yaml,"nodeName":name,"entryIPv4":ip,"physical":settings.physical])
            let sanitized=try Commands().run("/usr/bin/ruby",[resources+"/prepare-entry-probe.rb"],timeout:8,input:input,cancelled:{cancellation.cancelled})
            let envelope=(try? JSONSerialization.jsonObject(with:Data(sanitized.output.utf8))) as? [String:Any]
            guard sanitized.status==0,let envelope,
                  envelope["fingerprint"] as? String==status.fingerprint,let config=envelope["config"] as? [String:Any] else{
                throw fail(preparationMessage(envelope?["errorCode"] as? String))
            }
            // Failures for individual candidates are expected (e.g. a DNS-over-HTTPS socket).
            // A result is a hint only until the daemon rechecks the live Core and startup gates.
            if let result=try attempt(core:core,identity:identity,config:config,ip:ip,port:entry.port,physical:physical,cancellation:cancellation,diagnostic:diagnostic){results.append(result)}
        }
        guard !cancellation.cancelled,try UDPProtection.physical(settings.physical)==physical,
              try ProxyConfiguration.bytes(path:path,uid:getuid())==raw,try codeHash(path:core)==identity else{throw fail("前置测试结果已失效：配置、接口或 Core 改变")}
        return results
    }
    static func preparationMessage(_ code:String?) -> String {
        // Fixed messages only: never forward raw parser output or credential values.
        let reasons=["node-type":"前置协议暂不支持独立验证；本轮支持 VLESS、Trojan、HTTP、SOCKS5 的限定 TCP 组合", "node-type-udp":"前置节点为 UDP 隧道协议（如 TUIC）；完整防护仅支持固定 TCP 前置", "reality":"Reality 仅支持 TCP；公钥须为 32 字节 base64url，short-id 须为不超过 8 字节的偶数长度十六进制", "flow":"flow 仅支持空值或 TCP 下的 xtls-rprx-vision", "alpn":"ALPN 仅支持非空 h2/http/1.1 组合，禁止 h3", "client-fingerprint":"客户端指纹不支持，或 Reality 缺少已核验的客户端指纹", "packet-encoding":"packet-encoding 不支持", "credentials":"节点认证字段格式无效", "node-field":"节点可选参数格式不支持", "node-option":"节点包含未支持的选项", "transport":"节点传输协议不在支持范围", "websocket":"WebSocket 参数不在支持范围", "tls-name":"TLS 主机名无效", "uuid":"节点认证标识格式无效", "node-missing":"配置中找不到所选节点", "yaml-invalid":"配置语法或编码不支持", "socks-tls-endpoint":"SOCKS5 TLS 不支持改写域名入口", "plaintext-endpoint":"明文认证不能发送到不同的候选入口"]
        let reason=code.flatMap{reasons[$0]} ?? "配置提取或指纹核验未通过"
        return "前置验证未开始："+reason+"；未降低 TLS 校验或修改原配置"
    }
    static func echo(_ value:[String:Any]) throws -> String {
        guard value["error"]==nil,
              value["chains"] as? [String]==["GuardEntry"],
              let url=value["url"] as? String,["https://api.ipify.org/","https://ipv4.webshare.io/"].contains(url),
              let body=value["body"] as? String else{throw fail("前置回显不属于指定代理测试")}
        let ip=body.trimmingCharacters(in:.whitespacesAndNewlines)
        guard IPv4.isPublic(ip) else{throw fail("前置回显不是有效公网 IPv4")}
        return ip
    }
    private static func attempt(core:String,identity:String,config:[String:Any],ip:String,port:UInt16,physical:InterfaceIdentity,cancellation:EntryProbeCancellation,diagnostic:@escaping @Sendable (EntryProbeDiagnostic)->Void) throws -> EntryProbeResult? {
        var stage="隔离 Core 启动",outcome="失败"
        func mark(_ value:String){stage=value;diagnostic(.init(candidate:ip,stage:stage,outcome:"开始"))}
        defer{diagnostic(.init(candidate:ip,stage:stage,outcome:cancellation.cancelled ? "已取消":outcome))}
        mark(stage)
        // mkdtemp supplies atomic private ownership. Do not copy the source's setuid mode/xattrs.
        var template=Array("/private/tmp/cg-entry-XXXXXX".utf8CString)
        guard let created=mkdtemp(&template) else{throw fail("前置测试临时目录创建失败")}
        let dir=String(cString:created),executable=dir+"/core",socketPath=dir+"/ipc"
        let child=Process();var connection:Int32 = -1,listener:Int32 = -1
        defer {
            if connection>=0 {shutdown(connection,SHUT_RDWR);close(connection)}
            if listener>=0 {close(listener)}
            // Process retains the launched child's identity; never signal the installed Core.
            if child.isRunning {
                child.terminate()
                let end=ProcessInfo.processInfo.systemUptime+1
                while child.isRunning && ProcessInfo.processInfo.systemUptime<end {usleep(10_000)}
                if child.isRunning {_=kill(child.processIdentifier,SIGKILL)}
                child.waitUntilExit()
            }
            try? FileManager.default.removeItem(atPath:dir)
        }
        let binary=try Data(contentsOf:URL(fileURLWithPath:core),options:.mappedIfSafe)
        try binary.write(to:URL(fileURLWithPath:executable),options:.withoutOverwriting)
        guard chmod(executable,0o700)==0,try codeHash(path:executable)==identity,try codeHash(path:core)==identity else{throw fail("隔离 Core 身份核验失败")}
        let configFile=dir+"/config.yaml"
        let configPipe=try EntryProbeConfigPipe(path:configFile,config:config)
        var sendConfig=false
        listener=csg_listen(socketPath,getuid())
        guard listener>=0,fcntl(listener,F_SETFD,FD_CLOEXEC)==0 else{throw fail("独立 Core IPC 创建失败")}
        child.executableURL=URL(fileURLWithPath:executable);child.arguments=[socketPath]
        child.environment=["HOME":dir,"TMPDIR":dir,"PATH":"/usr/bin:/bin"]
        child.standardInput=FileHandle.nullDevice;child.standardOutput=FileHandle.nullDevice;child.standardError=FileHandle.nullDevice
        try child.run()
        func wait(_ fd:Int32,event:Int16,end:Double,observe:()->Void = {}) throws {
            while ProcessInfo.processInfo.systemUptime<end {
                guard !cancellation.cancelled,child.isRunning else{throw fail("独立前置测试已取消或 Core 退出")}
                if sendConfig {try configPipe.pump()}
                observe()
                var p=pollfd(fd:fd,events:event,revents:0)
                let n=poll(&p,1,10)
                if n>0 {return};if n<0 && errno != EINTR {throw fail("独立 Core IPC 不可读")}
            }
            throw fail("独立前置测试超时")
        }
        do {
            mark("等待独立 IPC 连接")
            try wait(listener,event:Int16(POLLIN),end:ProcessInfo.processInfo.systemUptime+5)
            connection=accept(listener,nil,nil);guard connection>=0 else{throw fail("独立 Core IPC 接受失败")}
            mark("IPC 与子进程身份核验")
            var token=[UInt8](repeating:0,count:32),uid:UInt32=0,pid:Int32=0
            guard csg_peer(connection,&token,&uid,&pid)==0,uid==getuid(),pid==child.processIdentifier,
                  try guestHash(token:Data(token))==identity else{throw fail("独立 Core IPC 身份不符")}
            let initial=try NativeProcesses.record(pid)
            guard initial.uid==getuid(),initial.path==executable else{throw fail("独立 Core 未以普通用户运行")}
            var observed=false,unexpected=false,unreadable=false
            func observe() {
                do {
                    let current=try NativeProcesses.record(pid)
                    guard current.started==initial.started,current.path==initial.path,current.uid==getuid() else{unreadable=true;return}
                    for var s in try NativeProcesses.sockets(pid) {
                        if s.kind==1 && s.protocol_number==IPPROTO_UDP {unexpected=true}
                        guard s.kind==2 && s.state==4 else{continue}
                        let local=NativeProcesses.text(&s.local),remote=NativeProcesses.text(&s.remote)
                        if remote==ip && s.remote_port==port && local==physical.ipv4 {observed=true}
                        else {unexpected=true}
                    }
                }catch{unreadable=true}
            }
            func rpc(_ method:String,_ arguments:[String:Any],seconds:Double,watch:Bool=false) throws -> [String:Any] {
                let id=UUID().uuidString,end=ProcessInfo.processInfo.systemUptime+seconds
                let frame=try EntryProbeFrame.encode(["id":id,"method":method,"arguments":arguments])
                var noSignal:Int32=1
                guard setsockopt(connection,SOL_SOCKET,SO_NOSIGPIPE,&noSignal,socklen_t(MemoryLayout<Int32>.size))==0 else{throw fail("独立 Core IPC 断开保护设置失败")}
                try frame.withUnsafeBytes { bytes in
                    var sent=0
                    while sent<bytes.count {
                        try wait(connection,event:Int16(POLLOUT),end:end)
                        let n=send(connection,bytes.baseAddress!.advanced(by:sent),bytes.count-sent,MSG_DONTWAIT)
                        guard n>0 else{throw fail("独立 Core IPC 发送失败")};sent+=n
                    }
                }
                func read(_ size:Int) throws -> Data {
                    var data=Data()
                    while data.count<size {
                        try wait(connection,event:Int16(POLLIN),end:end,observe:watch ? observe:{})
                        var buffer=[UInt8](repeating:0,count:min(size-data.count,8192))
                        let n=recv(connection,&buffer,buffer.count,MSG_DONTWAIT)
                        if n<0 && [EAGAIN,EINTR].contains(errno){continue}
                        guard n>0 else{throw fail("独立 Core IPC 接收失败")};data.append(contentsOf:buffer.prefix(n))
                    };return data
                }
                // Desktop Core emits batched lifecycle events without a subscription.
                // Consume only that envelope, with one absolute deadline and bounded work.
                var total=0
                for _ in 0..<64 {
                    let size=try EntryProbeFrame.length(read(4));total+=size
                    guard total<=EntryProbeFrame.maximum*2 else{throw fail("独立 Core IPC 事件过多")}
                    if let reply=try EntryProbeFrame.response(read(size),id:id){return reply}
                }
                throw fail("独立 Core IPC 无匹配应答")
            }
            mark("Core 初始化")
            _=try rpc("core.init",["home-dir":dir,"version":0],seconds:5)
            mark("隔离配置传输与加载")
            sendConfig=true
            _=try rpc("config.setup",["selected-map":[:],"options":["skip-cert-verify":false]],seconds:5)
            guard configPipe.completed else{throw fail("独立 Core 未读取完整配置")}
            sendConfig=false
            mark("代理协议与 HTTPS 回显")
            let reply=try rpc("probe.outboundIp",["proxy-name":"GuardEntry","urls":["https://api.ipify.org/","https://ipv4.webshare.io/"],"timeout":8000],seconds:10,watch:true)
            guard let result=reply["result"] as? [String:Any] else{return nil}
            if let code=result["error"] as? String {
                outcome=["timeout","failed","cancelled","proxy_not_found"].contains(code) ? code:"Core 返回失败"
                return nil
            }
            mark("回显响应核验")
            let exit=try echo(result)
            observe()
            mark("物理连接证据核验")
            guard observed,!unexpected,!unreadable,IPv4.isPublic(exit) else{
                outcome=unreadable ? "子进程连接信息无法读取":unexpected ? "发现非预期连接":"未观察到指定物理源地址的已建立连接"
                return nil
            }
            outcome="通过"
            return .init(entry:ip,exit:exit)
        } catch {
            if cancellation.cancelled {throw fail("前置验证已取消")}
            if case GuardFailure.rejected(let message)=error {
                let allowed=["隔离配置加载失败：Core 要求非空 default-nameserver","隔离配置被 Core 拒绝（config_rejected）","独立前置测试超时","独立前置测试已取消或 Core 退出","独立 Core IPC 身份不符","独立 Core 未以普通用户运行","Entry probe IPC reply rejected","独立 Core IPC 接收失败","前置回显不属于指定代理测试","前置回显不是有效公网 IPv4"]
                if allowed.contains(message){outcome=message}
            }
            return nil // Never emit arbitrary Core responses/configuration/credentials.
        }
    }
}

/// Named pipe contains no persistent credential data, including after parent crash.
/// pump() is nonblocking and runs under the RPC absolute deadline/cancellation gate.
final class EntryProbeConfigPipe {
    let path:String
    private var data:Data
    private var fd:Int32 = -1
    private var offset=0
    private(set) var completed=false
    // The Core reads this stream as YAML, not JSON. JSON's optional \/ escape
    // is rejected by its YAML parser. Keep all other string escaping intact.
    convenience init(path:String,config:[String:Any]) throws {
        try self.init(path:path,bytes:JSONSerialization.data(withJSONObject:config,options:[.withoutEscapingSlashes]))
    }
    init(path:String,bytes:Data) throws {
        guard !bytes.isEmpty,bytes.count<=64*1024,mkfifo(path,0o600)==0 else{throw fail("独立配置管道创建失败")}
        self.path=path;self.data=bytes
    }
    deinit {if fd>=0 {close(fd)};unlink(path)}
    func pump() throws {
        if completed{return}
        if fd<0 {
            fd=open(path,O_WRONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
            if fd<0,errno==ENXIO{return}
            guard fd>=0 else{throw fail("独立配置管道不可写")}
            // Unlink as soon as both ends are open: no other reader may attach.
            guard unlink(path)==0 else{throw fail("独立配置管道清理失败")}
            guard fcntl(fd,F_SETNOSIGPIPE,1)==0 else{throw fail("独立配置管道断开保护设置失败")}
        }
        let n=data.withUnsafeBytes{Darwin.write(fd,$0.baseAddress!.advanced(by:offset),data.count-offset)}
        if n<0,[EAGAIN,EINTR].contains(errno){return}
        guard n>0 else{throw fail("独立配置管道传输失败")}
        offset+=n
        if offset==data.count {close(fd);fd = -1;completed=true;data=Data()}
    }
}
