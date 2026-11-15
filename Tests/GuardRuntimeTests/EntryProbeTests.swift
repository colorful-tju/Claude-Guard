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
        let config:[String:Any] = ["path":"/synthetic/path?value=中文", "credential":"quote\"backslash\\end", "padding":String(repeating:"a",count:50_000)]
        let bytes=try JSONSerialization.data(withJSONObject:config)
        let writer=try EntryProbeConfigPipe(path:file,config:config)
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
        #expect(try JSONSerialization.jsonObject(with:received.get()) as? NSDictionary == JSONSerialization.jsonObject(with:bytes) as? NSDictionary)
        #expect(!String(decoding:received.get(),as:UTF8.self).contains("\\/"))
    }
}
private final class LockedProbeData:@unchecked Sendable {
    let lock=NSLock();var data=Data()
    func set(_ value:Data){lock.lock();data=value;lock.unlock()}
    func get()->Data{lock.lock();defer{lock.unlock()};return data}
}

struct EntryCoreOfflineIntegrationTests {
    // Opt-in because this requires the explicitly selected installed Core.
    @Test func productionConfigPipeLoadsInNetworkDeniedCore() throws {
        guard let core=ProcessInfo.processInfo.environment["CG_ENTRY_OFFLINE_CORE"] else{return}
        let project=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer{try? FileManager.default.removeItem(at:root)}
        let node:[String:Any]=["name":"synthetic","type":"vless","server":"entry.example.com","port":443,"network":"ws","tls":true,"servername":"tls.example.com","uuid":"01234567-89ab-cdef-0123-456789abcdef","ws-opts":["path":"/synthetic/path?value=1","headers":["Host":"tls.example.com"]]]
        let yaml=String(data:try JSONSerialization.data(withJSONObject:["proxies":[node]],options:[.withoutEscapingSlashes]),encoding:.utf8)!
        let input=try JSONSerialization.data(withJSONObject:["yaml":yaml,"nodeName":"synthetic","entryIPv4":"1.2.3.4","physical":"en0"])
        let extracted=try Commands().run("/usr/bin/ruby",[project.appendingPathComponent("Resources/prepare-entry-probe.rb").path],timeout:8,input:input)
        #expect(extracted.status==0)
        let envelope=try JSONSerialization.jsonObject(with:Data(extracted.output.utf8)) as! [String:Any]
        let writer=try EntryProbeConfigPipe(path:root.appendingPathComponent("config.yaml").path,config:envelope["config"] as! [String:Any])
        let reader=Process(),output=Pipe()
        reader.executableURL=URL(fileURLWithPath:"/bin/cat");reader.arguments=[writer.path];reader.standardOutput=output
        try reader.run()
        let received=LockedProbeData(),group=DispatchGroup();group.enter()
        DispatchQueue.global().async {received.set(output.fileHandleForReading.readDataToEndOfFile());group.leave()}
        let deadline=ProcessInfo.processInfo.systemUptime+3
        while !writer.completed && ProcessInfo.processInfo.systemUptime<deadline {try writer.pump();Thread.sleep(forTimeInterval:0.001)}
        if !writer.completed {reader.terminate()}
        reader.waitUntilExit()
        #expect(writer.completed)
        #expect(group.wait(timeout:.now()+3) == .success)
        let payload=root.appendingPathComponent("synthetic-wire.json")
        try received.get().write(to:payload)
        let verifier=Process()
        verifier.executableURL=URL(fileURLWithPath:"/usr/bin/env")
        verifier.arguments=["python3",project.appendingPathComponent("scripts/test-entry-core-offline.py").path,"--core",core,"--serialized-config",payload.path]
        try verifier.run();verifier.waitUntilExit()
        #expect(verifier.terminationStatus==0)
    }
}
