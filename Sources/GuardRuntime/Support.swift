import Foundation
import CryptoKit
import Darwin
import Security
import GuardCore
import NativeGuard
public enum Paths {
    public static let root = "/Library/Application Support/ClaudeSafeLauncher"
    public static let socket = root + "/control.sock"
    public static let daemon = "/Library/PrivilegedHelperTools/local.claudesafelauncher.guard"
    public static let app = "/Applications/ClaudeSafeLauncher.app"
    public static let label = "local.claudesafelauncher.guard"
}
public func hash(_ data: Data) -> String { SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined() }
public func monotonic() -> UInt64 { UInt64(ProcessInfo.processInfo.systemUptime) }
public func fail(_ message: String) -> GuardFailure { .rejected(message) }
public func codeHash(path:String) throws -> String {
    var code:SecStaticCode?;let url=URL(fileURLWithPath:path) as CFURL
    guard SecStaticCodeCreateWithPath(url,[],&code)==errSecSuccess,let code,
          SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),nil)==errSecSuccess else {throw fail("Invalid signed executable")}
    var info:CFDictionary?;guard SecCodeCopySigningInformation(code,[],&info)==errSecSuccess,
          let dict=info as? [String:Any],let data=dict[kSecCodeInfoUnique as String] as? Data else {throw fail("cdhash unavailable")}
    return data.map{String(format:"%02x",$0)}.joined()
}
public func guestHash(token:Data) throws -> String {
    var guest:SecCode?;let attributes=[kSecGuestAttributeAudit as String:token] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil,attributes,[],&guest)==errSecSuccess,let guest,
          SecCodeCheckValidity(guest,SecCSFlags(rawValue:kSecCSStrictValidate),nil)==errSecSuccess else {throw fail("IPC audit-token signature check failed")}
    var staticCode:SecStaticCode?;guard SecCodeCopyStaticCode(guest,[],&staticCode)==errSecSuccess,let staticCode else{throw fail("IPC static identity unavailable")}
    var info:CFDictionary?;guard SecCodeCopySigningInformation(staticCode,[],&info)==errSecSuccess,
          let dict=info as? [String:Any],let data=dict[kSecCodeInfoUnique as String] as? Data else {throw fail("IPC cdhash unavailable")}
    return data.map{String(format:"%02x",$0)}.joined()
}
public struct ProcessRecord: Sendable {
    public var pid:Int32;public var ppid:Int32;public var uid:UInt32;public var started:UInt64;public var path:String;public var name:String
    public var identity:ProcessIdentity { .init(pid:pid,startTime:started,executableIdentity:path) }
}
public enum NativeProcesses {
    struct ReadFailure:Error,CustomStringConvertible {
        var pid:Int32;var result:Int32;var nativeError:Int32;var confirmation:String?=nil
        var description:String {"Process identity unreadable: pid=\(pid) stage=\(result == -1 ? "bsd" : (result == CSG_PROCESS_ZOMBIE ? "confirmed-zombie" : (result == CSG_PROCESS_GONE ? "confirmed-absent":"path"))) rc=\(result) errno=\(nativeError)" + (confirmation.map{"; followup="+$0} ?? "")}
    }
    private static func confirmedInactive(_ pid:Int32,error:Error) -> Bool {
        if let native=error as? ReadFailure,(native.result==CSG_PROCESS_ZOMBIE || native.result==CSG_PROCESS_GONE) {return true}
        // A permission error is not absence. Only a separate proven ESRCH may be ignored.
        return kill(pid,0) == -1 && errno==ESRCH
    }
    public static func record(_ pid:Int32) throws -> ProcessRecord {
        var c=CSGProcess();errno=0;let result=csg_process(pid,&c);let nativeError=errno
        guard result==0 else{
            var detail:String?
            if result<0 {
                var e=CSGProcessEvidence();csg_process_evidence(pid,&e)
                detail="sysctl(rc=\(e.sysctl_rc),errno=\(e.sysctl_error),size=\(e.returned_size)/\(e.expected_size),pid=\(e.observed_pid),status=\(e.status));kill0(rc=\(e.kill_rc),errno=\(e.kill_error))"
            }
            throw ReadFailure(pid:pid,result:result,nativeError:nativeError,confirmation:detail)
        }
        return .init(pid:c.pid,ppid:c.ppid,uid:c.uid,started:c.started,path:withUnsafePointer(to:&c.path){String(cString:UnsafeRawPointer($0).assumingMemoryBound(to:CChar.self))},name:withUnsafePointer(to:&c.name){String(cString:UnsafeRawPointer($0).assumingMemoryBound(to:CChar.self))})
    }
    public static func inventory() -> ProcessInventory {
        var ids=[Int32](repeating:0,count:32768);let n=csg_pids(&ids,Int32(ids.count))
        guard n>0,n<ids.count else{return .init(records:[],issues:["Process inventory failed or truncated: count=\(n)"])}
        return ProcessInventoryCollector.collect(ids:Array(ids.prefix(Int(n))),read:record,inactive:confirmedInactive,wait:Thread.sleep(forTimeInterval:))
    }

    public static func all() throws -> [ProcessRecord] {
        try inventory().requireComplete()
    }
    public static func sockets(_ pid:Int32) throws -> [CSGSocket] {
        try SocketInventoryCollector.collect(pid:pid,identity:{try record($0).identity},read:{ pid in
            var rows=[CSGSocket](repeating:CSGSocket(),count:8192)
            errno=0;let n=csg_sockets(pid,&rows,Int32(rows.count));let nativeError=errno
            guard n>=0,n<rows.count else{throw fail("Native socket read failed: rc=\(n) errno=\(nativeError)")}
            return Array(rows.prefix(Int(n)))
        },wait:Thread.sleep(forTimeInterval:))
    }
    public static func text<T>(_ field:inout T) -> String {withUnsafePointer(to:&field){String(cString:UnsafeRawPointer($0).assumingMemoryBound(to:CChar.self))}}
    public static func claude(_ records:[ProcessRecord],uid:UInt32,known:[ProcessIdentity]=[]) -> [ProcessRecord] {
        // Exclude the control application from roots AND descendant expansion.
        let eligible=records.filter{$0.uid==uid && !$0.path.hasPrefix(Paths.app+"/Contents/")}
        let lifetimes=Dictionary(known.map{($0.pid,$0.startTime)},uniquingKeysWith:{$1})
        var found=eligible.filter{
            let name=$0.name.lowercased()
            return lifetimes[$0.pid]==$0.started || $0.path.contains("/Claude.app/Contents/") || name=="claude" ||
                   name=="claude helper" || name.hasPrefix("claude helper ") || name.hasPrefix("claude helper(")
        }
        var ids=Set(found.map(\.pid));var added=true
        while added {added=false;for r in eligible where ids.contains(r.ppid) && !ids.contains(r.pid){found.append(r);ids.insert(r.pid);added=true}}
        return found
    }
    // Deliberately unavailable to inventory/classification. The termination caller
    // still checks the previously tracked PID/startTime and installation UID.
    static func terminationLifetime(_ pid:Int32) throws -> ProcessRecord {
        var c=CSGProcess();errno=0
        let result=csg_process_lifetime(pid,&c);let nativeError=errno
        guard result==0 else{throw ReadFailure(pid:pid,result:result,nativeError:nativeError)}
        return .init(pid:c.pid,ppid:0,uid:c.uid,started:c.started,path:"",name:withUnsafePointer(to:&c.name){String(cString:UnsafeRawPointer($0).assumingMemoryBound(to:CChar.self))})
    }
    public static func terminateClaude(uid:UInt32,known:[ProcessIdentity]=[],retain:([ProcessIdentity])->Void={_ in}) throws {
        var entries:[String]=[],result="unconfirmed"
        defer {
            // Best-effort diagnostic, separate from all safety decisions. No arguments or paths.
            if geteuid()==0 {
                try? PrivateFiles.write(["timestamp":ISO8601DateFormatter().string(from:Date()),"result":result,"events":entries.joined(separator:"\n")],to:Paths.root+"/last-termination.json")
            }
        }
        do {try ClaudeTermination.run(uid:uid,known:known,inventory:inventory,read:record,inactive:confirmedInactive,send:{pid,signal in
            if kill(pid,signal) != 0 && errno != ESRCH {throw fail("Cannot signal Claude/Code process pid=\(pid) errno=\(errno)")}
        },wait:Thread.sleep(forTimeInterval:),observe:{event in
            if entries.count>=128 {entries.removeFirst()}
            entries.append(String(event.prefix(2048)))
        },retain:retain,lifetime:terminationLifetime)} catch {
            let sent=entries.filter{$0.hasPrefix("signal-returned")}.count
            let failures=entries.filter{$0.hasPrefix("signal-failed") || $0.hasPrefix("target-unverified")}.prefix(4).map{String($0.prefix(512))}
            throw fail("\(error); termination-actions signalReturns=\(sent) (not exit proof); \(failures.joined(separator:"; ")); details=last-termination.json")
        }
        result="exit-confirmed"
    }
}
