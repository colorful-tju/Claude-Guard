import Foundation
import Darwin
import Testing
import GuardCore
import NativeGuard
@testable import GuardRuntime
struct BoundaryTests {
    @Test func journalIsPrivateAndRejectsSymlinkOrWritableFile() throws {
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:dir)}
        let path=dir.appendingPathComponent("journal.json").path
        try PrivateFiles.write(["stage":"protected"],to:path)
        let read=try PrivateFiles.read(path,as:[String:String].self,owner:geteuid());#expect(read["stage"]=="protected")
        chmod(path,0o666);reject{_ = try PrivateFiles.read(path,as:[String:String].self,owner:geteuid())}
        chmod(path,0o600);let link=dir.appendingPathComponent("link").path;symlink(path,link)
        reject{_ = try PrivateFiles.read(link,as:[String:String].self,owner:geteuid())}
    }
    @Test func systemCommandIgnoresAmbientEnvironmentAndEnforcesDeadline() throws {
        let result=try Commands().checked("/usr/bin/env",[])
        #expect(!result.contains("HTTP_PROXY"));#expect(!result.contains("HOME="));#expect(result.contains("LC_ALL=C"))
        reject{_ = try Commands().checked("/bin/sleep",["2"],timeout:0.05)}
    }
    @Test func nativeAuditTokenMatchesActualSocketPeer() throws {
        let path=FileManager.default.temporaryDirectory.appendingPathComponent("csg-"+UUID().uuidString).path
        let server=csg_listen(path,geteuid());#expect(server>=0);guard server>=0 else{return};defer{close(server);unlink(path)}
        let client=csg_connect(path);#expect(client>=0);guard client>=0 else{return};defer{close(client)}
        let accepted=accept(server,nil,nil);#expect(accepted>=0);guard accepted>=0 else{return};defer{close(accepted)}
        var token=[UInt8](repeating:0,count:32),uid:UInt32=0,pid:Int32=0
        #expect(csg_peer(accepted,&token,&uid,&pid)==0);#expect(uid==geteuid());#expect(pid==getpid())
        let own=try NativeProcesses.record(getpid())
        #expect(try guestHash(token:Data(token))==codeHash(path:own.path))
    }
    @Test func realYAMLParserRejectsDuplicateKeysAndUnsafeObjectTags() throws {
        let script=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/read-node.rb").path
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true);defer{try? FileManager.default.removeItem(at:dir)}
        let path=dir.appendingPathComponent("config.yaml").path
        let valid="mode: rule\nproxies:\n  - name: My-HTTP-Node\n    type: http\n    server: 1.1.1.1\n    port: 5376\nrules:\n  - MATCH,PROXY\n"
        try valid.write(toFile:path,atomically:true,encoding:.utf8)
        let node=try NodeConfiguration.parse(Data(Commands().checked("/usr/bin/ruby",[script,path]).utf8));#expect(node.server=="1.1.1.1");#expect(node.port==5376)
        for bad in [valid+"mode: global\n", "--- !ruby/object:Object {}\n",valid.replacingOccurrences(of:"type: http",with:"type: http\n    dialer-proxy: other")] {
            try bad.write(toFile:path,atomically:true,encoding:.utf8);reject{_ = try Commands().checked("/usr/bin/ruby",[script,path])}
        }
    }
    @Test func explicitBoundStateParsingRetainsKnownGatewayOnly() throws {
        let e=try Endpoint(gateway:"23.20.10.8",port:5376,expectedEgress:"1.1.1.1",configurationFingerprint:"x",providerConfirmed:true,confirmedGateway:"23.20.10.8",confirmedPort:5376,confirmedFingerprint:"x",protocolName:"http")
        let p=try GuardPolicy(endpoint:e,physical:.init(name:"en0",index:6,generation:1,ipv4:"172.21.191.84"),tun:.init(name:"utun4",index:20,generation:1,ipv4:"198.18.0.1"))
        let state="en0 tcp 172.21.191.84:50000 -> 23.20.10.8:5376 ESTABLISHED:ESTABLISHED\n   age 00:00:01, expires in 00:01:00, 1:1 pkts, 60:60 bytes\n   id: 0000000000000001 creatorid: 00000000\n"
        let rows=try PFText.states(state,policy:p);#expect(rows.count==1);#expect(rows.first?.id=="0000000000000001:00000000")
        reject{_ = try PFText.states(state.replacingOccurrences(of:"23.20.10.8",with:"1.1.1.1"),policy:p)}
    }
}
