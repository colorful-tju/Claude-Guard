import Foundation
import Darwin
import NativeGuard

public struct CommandResult: Sendable { public var output:String; public var error:String; public var status:Int32 }

/// Description is safe for logs: arguments, stdout, and stderr may contain secrets.
public struct CommandFailure: Error, Sendable, CustomStringConvertible {
    public let executable:String
    public let stage:String
    public let elapsed:TimeInterval
    /// Inspect only for a known, fixed worker whose diagnostics cannot contain credentials.
    public let stderrPrefix:String
    public var description:String {"Command \(stage): \(executable) elapsed=\(String(format:"%.3f",elapsed))s"}
}

/// Fixed absolute commands, a clean environment, and one deadline for input, exit and output.
/// Children must retain the process group inherited from this runner.
public final class Commands: @unchecked Sendable {
    private let lock=NSLock()
    private var groups=Set<Int32>()
    private var running=0
    private let workerLeafTools:Bool
    /// Only guard-probe may use this for fixed curl/printf leaf tools (no child processes).
    public init(workerLeafTools:Bool=false) {self.workerLeafTools=workerLeafTools}
    private func forget(_ pid:Int32){lock.lock();groups.remove(pid);lock.unlock()}
    private func reaped(_ pid:Int32)->Bool {var status:Int32=0;return waitpid(pid,&status,WNOHANG)==pid}
    private func stopped(_ pid:Int32)->Bool {
        var status:Int32=0
        let exited=csg_command_exited(pid,&status)
        if exited==1,(workerLeafTools || csg_command_group_active(pid)==0),reaped(pid){forget(pid);return true}
        if exited<0,errno==ECHILD,kill(workerLeafTools ? pid : -pid,0)<0,errno==ESRCH {forget(pid);return true}
        return false
    }
    private func terminate(_ pid:Int32)->Bool {
        let start=DispatchTime.now().uptimeNanoseconds
        _=kill(workerLeafTools ? pid : -pid,SIGTERM)
        var killed=false
        while DispatchTime.now().uptimeNanoseconds-start<750_000_000 {
            if stopped(pid){return true}
            if !killed,DispatchTime.now().uptimeNanoseconds-start>=100_000_000 {_=kill(workerLeafTools ? pid : -pid,SIGKILL);killed=true}
            usleep(5_000)
        }
        return stopped(pid)
    }
    /// Call before removing protection; retained unknown workers make cleanup fail closed.
    public func assertQuiescent() throws {
        lock.lock();let active=running,retained=Array(groups);lock.unlock()
        guard active==0 else{throw fail("Command workers are still active; protection retained")}
        for pid in retained where !stopped(pid){throw fail("Command worker group termination unverified; protection retained")}
    }
    public func run(_ path:String,_ args:[String],timeout:TimeInterval=8,input:Data?=nil,
                    cancelled:@Sendable ()->Bool={false},recordingTo:Int32?=nil) throws -> CommandResult {
        guard path.hasPrefix("/"),!path.utf8.contains(0),args.allSatisfy({!$0.utf8.contains(0)}),timeout.isFinite,timeout>0,timeout<86400 else{throw fail("Invalid absolute command or deadline")}
        if workerLeafTools {guard ["/usr/bin/curl","/usr/bin/printf"].contains(path) else{throw fail("Worker leaf executable is not allowlisted")}}
        let began=DispatchTime.now().uptimeNanoseconds
        let deadline=began+UInt64(timeout*1_000_000_000)
        let name=URL(fileURLWithPath:path).lastPathComponent
        var output=Data(),errors=Data(),errorPrefix=Data()
        func failure(_ stage:String)->CommandFailure {.init(executable:name,stage:stage,elapsed:Double(DispatchTime.now().uptimeNanoseconds-began)/1e9,stderrPrefix:String(decoding:errorPrefix,as:UTF8.self))}
        if let fd=recordingTo {var st=stat();guard fstat(fd,&st)==0,(st.st_mode&S_IFMT)==S_IFREG else{throw failure("recording-file-invalid")}}
        guard !cancelled() else{throw failure("cancelled-before-spawn")}
        lock.lock();running+=1;lock.unlock()
        defer{lock.lock();running-=1;lock.unlock()}
        var child=CSGCommand()
        let strings=([path]+args).map{strdup($0)}
        defer{for string in strings{free(string)}}
        guard strings.allSatisfy({$0 != nil}) else{throw failure("argument-allocation")}
        var argv=strings+[nil]
        let spawned=argv.withUnsafeMutableBufferPointer{(workerLeafTools ? csg_command_spawn_inherited(path,$0.baseAddress!,&child):csg_command_spawn(path,$0.baseAddress!,&child))}
        guard spawned==0 else{throw failure("spawn-errno-\(errno)")}
        lock.lock();groups.insert(child.pid);lock.unlock()
        var inputFD=child.input,outputFD=child.output,errorFD=child.error
        defer{for fd in [inputFD,outputFD,errorFD] where fd>=0{close(fd)}}
        var finished=false
        defer{if !finished{_=terminate(child.pid)}}
        let bytes=input ?? Data();var written=0;var status:Int32=0
        if bytes.isEmpty{close(inputFD);inputFD = -1}
        func record(_ data:Data)throws {
            guard let fd=recordingTo else{return}
            try data.withUnsafeBytes { buffer in
                var offset=0
                while offset<buffer.count {
                    let n=Darwin.write(fd,buffer.baseAddress!.advanced(by:offset),buffer.count-offset)
                    if n<0,errno==EINTR{continue}
                    guard n>0 else{throw failure("recording-write-errno-\(errno)")};offset+=n
                }
            }
            guard fsync(fd)==0 else{throw failure("recording-sync-errno-\(errno)")}
        }
        func readStream(_ fd:inout Int32,_ data:inout Data,limit:Int,diagnostic:Bool=false)throws {
            guard fd>=0 else{return}
            var buffer=[UInt8](repeating:0,count:16*1024)
            // A flooding stream must not starve cancellation, stdin, or the other stream.
            for _ in 0..<4 {
                let n=Darwin.read(fd,&buffer,buffer.count)
                if n==0{close(fd);fd = -1;return}
                if n<0 {
                    if errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR{return}
                    throw failure("output-read-errno-\(errno)")
                }
                guard n<=limit-data.count else{throw failure("output-limit")}
                let chunk=Data(buffer.prefix(n));data.append(chunk)
                if diagnostic,errorPrefix.count<1024{errorPrefix.append(chunk.prefix(1024-errorPrefix.count))}
                try record(chunk)
            }
        }
        while true {
            guard !cancelled() else{throw failure("cancelled")}
            let now=DispatchTime.now().uptimeNanoseconds
            guard now<deadline else{throw failure("deadline-exceeded")}
            let exited=csg_command_exited(child.pid,&status)
            guard exited>=0 else{throw failure("wait-errno-\(errno)")}
            if exited==1,outputFD<0,errorFD<0 {
                let descendants=workerLeafTools ? 0:csg_command_group_active(child.pid)
                guard descendants>=0 else{throw failure("group-inventory-unavailable")}
                if descendants==0 {
                    guard inputFD<0 else{throw failure("input-incomplete")}
                    guard reaped(child.pid) else{throw failure("reap-unverified")}
                    forget(child.pid);finished=true
                    return .init(output:String(decoding:output,as:UTF8.self),error:String(decoding:errors,as:UTF8.self),status:status)
                }
            }
            var fds=[pollfd(fd:inputFD,events:Int16(POLLOUT),revents:0),pollfd(fd:outputFD,events:Int16(POLLIN),revents:0),pollfd(fd:errorFD,events:Int16(POLLIN),revents:0)]
            let wait=Int32(min(10,max(1,(deadline-now)/1_000_000)))
            let ready=Darwin.poll(&fds,nfds_t(fds.count),wait)
            if ready<0 {if errno==EINTR{continue};throw failure("poll-errno-\(errno)")}
            if fds[1].revents != 0{try readStream(&outputFD,&output,limit:4*1024*1024)}
            if fds[2].revents != 0{try readStream(&errorFD,&errors,limit:1024*1024,diagnostic:true)}
            if inputFD>=0,fds[0].revents != 0 {
                let n=bytes.withUnsafeBytes{Darwin.write(inputFD,$0.baseAddress!.advanced(by:written),min(64*1024,bytes.count-written))}
                if n<0 {
                    if errno != EAGAIN,errno != EWOULDBLOCK,errno != EINTR{throw failure("input-write-errno-\(errno)")}
                } else {written+=n;if written==bytes.count{close(inputFD);inputFD = -1}}
            }
        }
    }
    public func checked(_ path:String,_ args:[String],timeout:TimeInterval=8,input:Data?=nil,
                        cancelled:@Sendable ()->Bool={false},recordingTo:Int32?=nil) throws -> String {
        let result=try run(path,args,timeout:timeout,input:input,cancelled:cancelled,recordingTo:recordingTo)
        guard result.status==0 else{throw fail("\(URL(fileURLWithPath:path).lastPathComponent) failed (\(result.status)); required evidence unavailable")}
        return result.output
    }
}
