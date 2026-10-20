import Foundation
import Darwin
import GuardCore

/// Effect boundaries keep the same transaction controller testable without PF, signals or network access.
public protocol PacketFiltering: Sendable {
    func environment() throws -> (String,String,Bool)
    func states(_ policy:GuardPolicy) throws -> [ExistingState]
    func canonical() throws -> String
    func prepareRules(_ policy:GuardPolicy) throws -> String
    func activateRules(_ policy:GuardPolicy,expected:String) throws
    func enable(cancelled:@escaping @Sendable ()->Bool) throws -> String
    func recoveredToken() throws -> String
    func referencePresent(_ token:String) throws -> Bool
    func foreignReferences(_ token:String?) throws -> String
    func view(_ policy:GuardPolicy) throws -> PFView
    func removeOwnRules() throws
    func release(_ token:String) throws
}
public protocol RuntimeInspecting: Sendable {
    func node() throws -> NodeConfiguration
    func runtime(settings:Settings) throws -> RuntimeEvidence
    func monitoringRuntime(settings:Settings) throws -> RuntimeEvidence
    func epoch() throws -> UInt64
    func networkEventDiagnostics() -> [String]
}
extension RuntimeInspecting {
    public func monitoringRuntime(settings:Settings) throws -> RuntimeEvidence {try runtime(settings:settings)}
    public func networkEventDiagnostics()->[String] {[]}}
extension Inspector: RuntimeInspecting {
    public func networkEventDiagnostics()->[String] {events.diagnostics()}
    public func epoch() throws -> UInt64 { try events.epoch() }
}

public protocol ControllerStorage: Sendable {
    var root:String {get}
    func exists(_ name:String) -> Bool
    func readJournal() throws -> Journal
    func writeJournal(_ journal:Journal) throws
    func remove(_ name:String) throws
    func appendEvent(_ data:Data) throws
    func writeDiagnostic(_ value:ValidationDiagnostics) throws
    func writeMonitoringDiagnostic(_ value:MonitoringDiagnostics) throws
    func writeInventoryDiagnostic(_ json:String) throws
    func writeSocketDiagnostic(_ report:SocketObservationReport) throws
}
public struct PrivateControllerStorage: ControllerStorage {
    public let root:String
    private let owner:UInt32
    public init(root:String=Paths.root,owner:UInt32=0) {self.root=root;self.owner=owner}
    public func exists(_ name:String) -> Bool {FileManager.default.fileExists(atPath:root+"/"+name)}
    public func readJournal() throws -> Journal {try PrivateFiles.read(root+"/session.json",as:Journal.self,owner:owner)}
    public func writeJournal(_ journal:Journal) throws {try PrivateFiles.write(journal,to:root+"/session.json")}
    public func remove(_ name:String) throws {
        let path=root+"/"+name
        guard unlink(path)==0 || errno==ENOENT else{throw fail("Cannot remove private transaction asset: \(name)")}
        let fd=open(root,O_RDONLY);guard fd>=0 else{throw fail("Transaction directory unavailable")};defer{close(fd)}
        guard fsync(fd)==0 else{throw fail("Transaction directory fsync failed")}
    }
    public func appendEvent(_ data:Data) throws {try PrivateFiles.append(data,to:root+"/events.log",owner:owner)}
    public func writeDiagnostic(_ value:ValidationDiagnostics) throws {try PrivateFiles.write(value,to:root+"/last-validation.json")}
    public func writeInventoryDiagnostic(_ json:String) throws {
        guard json.utf8.count<=65536 else{throw fail("Inventory diagnostic exceeds size bound")}
        let object=try JSONDecoder().decode(InventoryDiagnostic.self,from:Data(json.utf8))
        try PrivateFiles.write(object,to:root+"/last-monitoring-degradation.json")
    }
    public func writeSocketDiagnostic(_ report:SocketObservationReport) throws {
        guard try JSONEncoder().encode(report).count<=65536 else{throw fail("Socket diagnostic exceeds size bound")}
        try PrivateFiles.write(report,to:root+"/last-socket-observation.json")
    }
    public func writeMonitoringDiagnostic(_ value:MonitoringDiagnostics) throws {
        _=try value.encoded()
        try PrivateFiles.write(value,to:root+"/last-monitoring-failure.json")
    }
}

public typealias ControllerCancellation = @Sendable ()->Bool
public typealias ControllerProbeRecord = @Sendable (String)throws->Void
public typealias ControllerProbeRunner = @Sendable (GuardPolicy,LocalSnapshot,UInt64,@escaping ControllerProbeRecord,@escaping ControllerCancellation)throws->ValidationBundle

struct ControllerEffects: Sendable {
    let commands:Commands
    let pf:any PacketFiltering
    let inspector:any RuntimeInspecting
    let storage:any ControllerStorage
    let clock:any GuardClock
    let uiIdentity:@Sendable (Int32)throws->ProcessIdentity
    let uiAlive:@Sendable (ProcessIdentity?)throws->Bool
    let inventory:@Sendable ()->ProcessInventory
    let terminateClaude:@Sendable ()throws->Void
    let observeSockets:@Sendable (GuardPolicy,[ProcessIdentity])throws->SocketObservationReport
    let preflightWorker:@Sendable (@escaping ControllerProbeRecord,@escaping ControllerCancellation)throws->String
    let verifyClaude:@Sendable ()throws->Void
    let launchClaude:@Sendable (@escaping ControllerCancellation)throws->Void
    let runProbes:ControllerProbeRunner
    let healthProbe:@Sendable (@escaping ControllerCancellation)throws->EgressReport
    let assertQuiescent:@Sendable ()throws->Void
    let boot:@Sendable ()->String

    var ipv6:TemporaryIPv6? = nil

    static func live(_ installation:Installation) throws -> ControllerEffects {
        let commands=Commands()
        let pf=PacketFilter(commands:commands)
        let inspector=Inspector(installation,commands:commands,events:try NetworkEvents())
        return .init(commands:commands,pf:pf,inspector:inspector,storage:PrivateControllerStorage(),clock:SystemGuardClock(),
            uiIdentity:{pid in
                let record=try NativeProcesses.record(pid)
                guard record.uid==installation.uid,record.path==Paths.app+"/Contents/MacOS/ClaudeSafeLauncher" else{throw fail("Authenticated UI process identity changed")}
                return record.identity
            },uiAlive:{identity in
                guard let identity,let record=try? NativeProcesses.record(identity.pid) else{return false}
                return record.uid==installation.uid && record.identity==identity
            },inventory:{NativeProcesses.inventory()},terminateClaude:{try NativeProcesses.terminateClaude(uid:installation.uid,known:inspector.trackedClaude)},
            observeSockets:{policy,processes in
                SocketObservationReport.collect(policy:policy,processes:processes)
            },preflightWorker:{record,cancel in try ValidationProbes.preflightWorker(commands:commands,record:record,cancelled:cancel)},verifyClaude:{guard try codeHash(path:"/Applications/Claude.app")==installation.claudeHash else{throw fail("Claude build changed; reinstall registration")}},
            launchClaude:{cancelled in _=try commands.checked("/bin/launchctl",["asuser",String(installation.uid),"/usr/bin/sudo","-u","#"+String(installation.uid),"/usr/bin/open","-a","/Applications/Claude.app"],timeout:5,cancelled:cancelled)},
            runProbes:{policy,baseline,installedAt,record,cancelled in try ValidationProbes(pf:pf,commands:commands,record:record,cancelled:cancelled).run(policy:policy,baseline:baseline,installedAt:installedAt)},
            healthProbe:{cancelled in PeriodicEgress.collect(cancelled:cancelled){service in try ProbeExecutor.egress(service:service,commands:commands,cancelled:cancelled)}},assertQuiescent:{try commands.assertQuiescent()},boot:{bootID()},ipv6:TemporaryIPv6())
    }
}
