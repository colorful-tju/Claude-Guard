import Foundation
import GuardCore
import Darwin
import NativeGuard
public struct Settings: Codable, Sendable {
    public var gateway:String=""; public var port:UInt16=0; public var expectedEgress:String=""
    public var physical:String="en0"; public var providerConfirmed:Bool=false
    public var confirmationFingerprint:String=""
    public init() {}
}
public enum GuardOperation:String,Codable,Sendable {case selfTest,progress,status,inspect,verify,start,stop,shutdown,heartbeat,export,ipv6Off,ipv6Automatic,ipv6Restore}
public struct Request:Codable,Sendable {
    public var operation:GuardOperation;public var settings:Settings?
    public var id:String=UUID().uuidString;public var protocolVersion:Int=BuildIdentity.protocolVersion
    public init(_ operation:GuardOperation,settings:Settings?=nil){self.operation=operation;self.settings=settings}
}
public struct ProtectionInterruption:Codable,Sendable,Identifiable {
    public var id:String=UUID().uuidString
    public var timestamp:String=ISO8601DateFormatter().string(from:Date())
    public var reason:String
    public var requestedClaudeStop:Bool
    public var exitConfirmed:Bool=false
    public init(reason:String,requestedClaudeStop:Bool){self.reason=reason;self.requestedClaudeStop=requestedClaudeStop}
}
public struct HeartbeatDiagnostic:Codable,Sendable {
    public var ageSeconds:Double?
    public var maxGapSeconds:Double
    public var limitSeconds:Double
    public var monitorIntervalSeconds:Double? = nil
    public var delayed:Bool {(ageSeconds ?? 0)>=6}
}
public struct Status:Codable,Sendable {
    public var periodicEgress:EgressDiagnostic?
    public var egressRechecking:Bool?
    public var heartbeatDiagnostic:HeartbeatDiagnostic?
    public var blockedPackets:UInt64?
    public var blockedPacketsAt:String?
    public var blockedPacketsIssue:String?

    public var interruption:ProtectionInterruption?

    public var phase:String="off",message:String="尚未检测",lastRisk:String="",gateway:String="",egress:String="",physical:String="",tun:String=""
    public var country:String="未核验",ipv6:String="未核验",udp:String="OFF",monitor:String="未启动（有限观测）"
    public var flclash:Bool=false,claude:Bool=false,verified:Bool=false
    public var fingerprint:String="",report:String="",refreshedAt:String=""
    public var processInventoryComplete:Bool=false,processWarning:String=""
    public var ipv6Override:String="未临时修改"
    public var daemonBuildID:String=BuildIdentity.buildID,workerBuildID:String=""
    public init(){}
}
public struct Reply:Codable,Sendable {public var requestID:String?;public var protocolVersion:Int=BuildIdentity.protocolVersion;public var ok:Bool;public var status:Status;public var error:String?;public init(ok:Bool,status:Status,error:String?=nil){self.ok=ok;self.status=status;self.error=error}}
public struct Installation:Codable,Sendable {
    // Registered by the administrator; never accepted from an untrusted UI request.
    public var proxyCorePath:String?
    public var proxyConfigPath:String?
    public var registeredCorePath:String {proxyCorePath ?? "/Applications/FlClash.app/Contents/MacOS/FlClashCore"}
    public var registeredConfigPath:String {proxyConfigPath ?? home+"/Library/Application Support/com.follow.clash/config.yaml"}
    public var uid:UInt32;public var home:String;public var clients:[String];public var coreHash:String;public var flclashHash:String;public var claudeHash:String
    public init(uid:UInt32,home:String,clients:[String],coreHash:String,flclashHash:String,claudeHash:String){self.uid=uid;self.home=home;self.clients=clients;self.coreHash=coreHash;self.flclashHash=flclashHash;self.claudeHash=claudeHash}
}
public enum Wire {
    private static let maxFrame=65536
    private static func wait(_ fd:Int32,_ event:Int16,_ deadline:UInt64) throws {
        while true {
            let now=DispatchTime.now().uptimeNanoseconds
            guard now<deadline else{throw fail("IPC absolute deadline exceeded")}
            var item=pollfd(fd:fd,events:event,revents:0)
            let milliseconds=Int32(min(1000,max(1,(deadline-now)/1_000_000)))
            let n=Darwin.poll(&item,1,milliseconds)
            if n<0,errno==EINTR{continue}
            guard n>=0 else{throw fail("IPC poll failed")}
            if n>0{return}
        }
    }
    private static func deadline(_ timeout:TimeInterval) throws -> UInt64 {
        guard timeout.isFinite,timeout>0,timeout<=120 else{throw fail("Invalid IPC deadline")}
        return DispatchTime.now().uptimeNanoseconds+UInt64(timeout*1e9)
    }
    public static func read(_ fd:Int32,timeout:TimeInterval=5) throws -> Data {
        let end=try deadline(timeout);var result=Data();var byte:UInt8=0
        while result.count<maxFrame {
            try wait(fd,Int16(POLLIN),end)
            let n=recv(fd,&byte,1,MSG_DONTWAIT)
            if n<0,[EINTR,EAGAIN,EWOULDBLOCK].contains(errno){continue}
            guard n==1 else{throw fail("IPC read failed")}
            if byte==10{return result};result.append(byte)
        }
        throw fail("IPC frame too large")
    }
    public static func write(_ data:Data,_ fd:Int32,timeout:TimeInterval=5) throws {
        guard data.count<maxFrame,!data.contains(10) else{throw fail("IPC frame too large or multiline")}
        let end=try deadline(timeout)
        var noSignal:Int32=1
        guard setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&noSignal,socklen_t(MemoryLayout<Int32>.size))==0 else{throw fail("IPC socket configuration failed")}
        var frame=data;frame.append(10)
        try frame.withUnsafeBytes { bytes in
            var sent=0
            while sent<bytes.count {
                try wait(fd,Int16(POLLOUT),end)
                let n=send(fd,bytes.baseAddress!.advanced(by:sent),bytes.count-sent,MSG_DONTWAIT)
                if n<0,[EINTR,EAGAIN,EWOULDBLOCK].contains(errno){continue}
                guard n>0 else{throw fail("IPC write failed")};sent+=n
            }
        }
    }
    public static func validate(_ reply:Reply,for request:Request) throws -> Reply {
        guard reply.requestID==request.id,reply.protocolVersion==BuildIdentity.protocolVersion,
              reply.status.daemonBuildID==BuildIdentity.buildID else{throw fail("IPC reply/build identity mismatch; reinstall matching components")}
        return reply
    }
    static func responseTimeout(for operation:GuardOperation)->TimeInterval {
        if [.start,.verify,.stop,.shutdown].contains(operation){return 90}
        if operation == .selfTest{return 15} // 8s worker + 2s curl + cleanup and reply margin.
        return 8
    }
    public static func client(_ request:Request) throws -> Reply {
        let fd=csg_connect(Paths.socket);guard fd>=0 else{throw fail("GuardDaemon 未安装或未运行")};defer{close(fd)}
        var bytes=[UInt8](repeating:0,count:32);var uid:UInt32=99;var pid:Int32=0
        guard csg_peer(fd,&bytes,&uid,&pid)==0,uid==0 else{throw fail("IPC server is not root")}
        let server=try guestHash(token:Data(bytes));guard server == (try codeHash(path:Paths.daemon)) else{throw fail("IPC daemon identity mismatch")}
        try write(JSONEncoder().encode(request),fd)
        let limit=responseTimeout(for:request.operation)
        return try validate(JSONDecoder().decode(Reply.self,from:read(fd,timeout:limit)),for:request)
    }
}
public enum PrivateFiles {
    public static func read<T:Decodable>(_ path:String,as:T.Type,owner:UInt32=0) throws -> T {
        var st=stat();guard lstat(path,&st)==0,(st.st_mode&S_IFMT)==S_IFREG,st.st_uid==owner,(st.st_mode&0o077)==0 else{throw fail("Private file ownership/mode invalid: \(URL(fileURLWithPath:path).lastPathComponent)")}
        let fd=open(path,O_RDONLY|O_NOFOLLOW);guard fd>=0 else{throw fail("Private file read failed")};defer{close(fd)}
        var check=stat();guard fstat(fd,&check)==0,check.st_ino==st.st_ino,check.st_dev==st.st_dev,check.st_size<4*1024*1024 else{throw fail("Private file changed or oversized")}
        let handle=FileHandle(fileDescriptor:fd,closeOnDealloc:false)
        return try JSONDecoder().decode(T.self,from:handle.readToEnd() ?? Data())
    }
    public static func append(_ data:Data,to path:String,owner:UInt32=0) throws {
        let fd=open(path,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW,0o600);guard fd>=0 else{throw fail("Private append log unavailable")};defer{close(fd)}
        var st=stat();guard fstat(fd,&st)==0,st.st_uid==owner,(st.st_mode&S_IFMT)==S_IFREG,(st.st_mode&0o077)==0 else{throw fail("Append log ownership/mode invalid")}
        try FileHandle(fileDescriptor:fd,closeOnDealloc:false).write(contentsOf:data)
        guard fsync(fd)==0 else{throw fail("Append log fsync failed")}
    }
    public static func write<T:Encodable>(_ value:T,to path:String) throws {
        let data=try JSONEncoder().encode(value);let tmp=path+"."+UUID().uuidString
        let fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0o600);guard fd>=0 else{throw fail("Private journal create failed")};var descriptorOpen=true
        do{let h=FileHandle(fileDescriptor:fd,closeOnDealloc:false);try h.write(contentsOf:data);guard fsync(fd)==0 else{throw fail("Journal fsync failed")};close(fd);descriptorOpen=false;guard rename(tmp,path)==0 else{throw fail("Journal rename failed")};let dir=open(URL(fileURLWithPath:path).deletingLastPathComponent().path,O_RDONLY);guard dir>=0 else{throw fail("Journal directory unavailable")};defer{close(dir)};guard fsync(dir)==0 else{throw fail("Journal directory fsync failed")}}
        catch{if descriptorOpen{close(fd)};unlink(tmp);throw error}
    }
}
public struct Journal:Codable,Sendable {
    public var version:Int=1;public var boot:String;public var policy:GuardPolicy;public var token:String?;public var stage:String
    public var initialMain:String;public var initialReferences:String;public var initialEnabled:Bool;public var allowedStates:[String]
    public var expectedCanonicalRules:String="";public var cleanRuleHistory:Bool=true
    public init(policy:GuardPolicy,boot:String,main:String,references:String,enabled:Bool,states:[ExistingState]){
        self.policy=policy;self.boot=boot;token=nil;stage="intent";initialMain=main;initialReferences=references;initialEnabled=enabled;allowedStates=states.map(\.id)
    }
}
