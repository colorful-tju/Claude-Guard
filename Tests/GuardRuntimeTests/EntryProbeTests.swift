import Foundation
import Testing
@testable import GuardRuntime

struct EntryProbeTests {
    @Test func littleEndianLengthAndBoundaries() throws {
        let frame=try EntryProbeFrame.encode(["id":"synthetic","result":NSNull()])
        #expect(try EntryProbeFrame.length(frame.prefix(4))==frame.count-4)
        for bytes in [Data(),Data([0,0,0,0]),Data([255,255,255,255]),Data([1,0,4,0])] {
            #expect(throws:(any Error).self){try EntryProbeFrame.length(bytes)}
        }
    }
    @Test func eventsAreNotRepliesAndFailuresCannotBeSuccess() throws {
        let event=try JSONSerialization.data(withJSONObject:["method":"message","arguments":[["type":"loaded","data":"unused"]]])
        #expect(try EntryProbeFrame.response(event,id:"1")==nil)
        let reply=try JSONSerialization.data(withJSONObject:["id":"1","result":NSNull()])
        #expect(try EntryProbeFrame.response(reply,id:"1") != nil)
        for value:[String:Any] in [["id":"2","result":NSNull()], ["id":"1","error":["message":"secret"]], ["id":"1","file":"/tmp/private"], ["method":"unknown","arguments":[]]] {
            let data=try JSONSerialization.data(withJSONObject:value)
            #expect(throws:(any Error).self){try EntryProbeFrame.response(data,id:"1")}
        }
    }
    @Test func echoRequiresNamedProxyAndKnownService() throws {
        let base:[String:Any]=["chains":["GuardEntry"],"url":"https://api.ipify.org/","body":"1.2.3.4\n"]
        #expect(try EntryProbe.echo(base)=="1.2.3.4")
        for (key,value):(String,Any) in [("chains",["DIRECT"]),("chains",["GuardEntry","other"]),("url","http://api.ipify.org/"),("body","127.0.0.1"),("body","1.2.3.4 extra"),("error","timeout")] {
            var altered=base;altered[key]=value
            #expect(throws:(any Error).self){try EntryProbe.echo(altered)}
        }
    }
    @Test func preparationDiagnosticsNeverExposeRawFields() {
        #expect(EntryProbe.preparationMessage("node-field").contains("可选参数"))
        #expect(!EntryProbe.preparationMessage("password=synthetic-secret").contains("synthetic-secret"))
        #expect(EntryProbe.preparationMessage(nil).contains("未通过"))
    }
    @Test func configurationFailureIsSpecificWithoutPrivateCoreMessage() throws {
        for message in ["default nameserver should have at least one nameserver","password=synthetic-secret"] {
            let bytes=try JSONSerialization.data(withJSONObject:["id":"1","result":NSNull(),"error":["code":"config_rejected","message":message]])
            do {_=try EntryProbeFrame.response(bytes,id:"1");Issue.record("must reject")}
            catch {
                let description=String(describing:error)
                #expect(description.contains("隔离配置"))
                #expect(!description.contains("synthetic-secret"))
                if message.hasPrefix("default") {#expect(description.contains("default-nameserver"))}
            }
        }
    }
    @Test func cancellationIsExplicitAndSticky() {
        let c=EntryProbeCancellation();#expect(!c.cancelled);c.cancel();c.cancel();#expect(c.cancelled)
    }
    @Test func offAndRegisteredContextRequiredBeforeCoreOrNetwork() {
        #expect(throws:(any Error).self){try EntryProbe.run(status:Status(),settings:Settings(),resources:"/nonexistent",cancellation:EntryProbeCancellation())}
    }
}

struct EntryProbePipeTests {
    @Test func privateFIFOTransfersWithoutPersistentCredentialFile() throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer{try? FileManager.default.removeItem(at:root)}
        let file=root.appendingPathComponent("config.yaml").path
        let bytes=Data(repeating:65,count:60_000)
        let writer=try EntryProbeConfigPipe(path:file,bytes:bytes)
        try writer.pump() // no reader: must return without hanging or writing a file
        #expect(!writer.completed)
        let process=Process(),output=Pipe()
        process.executableURL=URL(fileURLWithPath:"/bin/cat");process.arguments=[file];process.standardOutput=output
        try process.run()
        // Drain in parallel, otherwise output pipe backpressure could stall the input pipe.
        let received=LockedProbeData()
        let group=DispatchGroup();group.enter()
        DispatchQueue.global().async {received.set(output.fileHandleForReading.readDataToEndOfFile());group.leave()}
        let deadline=ProcessInfo.processInfo.systemUptime+3
        while !writer.completed && ProcessInfo.processInfo.systemUptime<deadline {try writer.pump();Thread.sleep(forTimeInterval:0.001)}
        #expect(writer.completed)
        #expect(!FileManager.default.fileExists(atPath:file))
        if !writer.completed {process.terminate()}
        process.waitUntilExit();#expect(group.wait(timeout:.now()+3) == .success)
        #expect(received.get()==bytes)
    }
}
private final class LockedProbeData:@unchecked Sendable {
    let lock=NSLock();var data=Data()
    func set(_ value:Data){lock.lock();data=value;lock.unlock()}
    func get()->Data{lock.lock();defer{lock.unlock()};return data}
}
