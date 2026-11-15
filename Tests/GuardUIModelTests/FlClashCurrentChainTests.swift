import Foundation
import Darwin
import Testing
import GuardRuntime
@testable import GuardUIModel

private final class CurrentChainFixture {
    let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
    var prefs:URL {root.appendingPathComponent("preferences.plist")}
    var generated:URL {root.appendingPathComponent("config.yaml")}
    let id="368420437123665920"
    let script=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/read-node.rb").path
    init() throws {
        try FileManager.default.createDirectory(at:root,withIntermediateDirectories:true)
        try writePreferences()
        _=try Commands().checked("/usr/bin/sqlite3",[root.appendingPathComponent("database.sqlite").path,"CREATE TABLE profiles(id INTEGER PRIMARY KEY,label TEXT,selected_map TEXT,url TEXT); INSERT INTO profiles VALUES(\(id),'Airport','{\"Front\":\"Region\",\"Region\":\"Entry\"}','PRIVATE_SUBSCRIPTION');"])
        let f:[String:Any] = ["mode":"rule","proxies":[["name":"Entry","type":"vless","server":"entry.example","port":443,"uuid":"PRIVATE_UUID"],["name":"Other","type":"trojan","server":"other.example","port":8443],["name":"ISP","type":"http","server":"8.8.4.4","port":5230,"password":"PRIVATE_PASSWORD","dialer-proxy":"Front"]],"proxy-groups":[["name":"Front","type":"select","proxies":["Region","Other"]],["name":"Region","type":"select","proxies":["Entry"]]],"rules":["MATCH,ISP"]]
        try JSONSerialization.data(withJSONObject:f).write(to:generated)
    }
    deinit {try? FileManager.default.removeItem(at:root)}
    func writePreferences(_ id:Int64=368420437123665920) throws {
        let config=String(data:try JSONSerialization.data(withJSONObject:["currentProfileId":id]),encoding:.utf8)!
        try PropertyListSerialization.data(fromPropertyList:["flutter.config":config],format:.binary,options:0).write(to:prefs)
    }
    func read() throws -> FlClashCurrentChain {try .read(root:root,preferencesURL:prefs,script:script)}
}

struct FlClashCurrentChainTests {
    @Test func currentProfileUsesExactIDAndResolvesNestedSelectionWithoutSecrets() throws {
        let f=try CurrentChainFixture(),before=try Data(contentsOf:f.generated),r=try f.read()
        #expect(r.profileID==f.id && r.entry.name=="Entry" && r.node.server=="8.8.4.4")
        #expect(r.configurationPath==f.generated.path && r.node.chain?.entries.count==2)
        #expect(try Data(contentsOf:f.generated)==before)
        for secret in ["PRIVATE_UUID","PRIVATE_PASSWORD","PRIVATE_SUBSCRIPTION"] {#expect(!String(describing:r).contains(secret))}
    }
    @Test func missingOrWrongSelectedMembershipNeverDefaultsToFirstNode() throws {
        let f=try CurrentChainFixture()
        for map in ["{}", "{\"Front\":\"Entry\"}","{\"Front\":\"Region\",\"Region\":\"Other\"}","{\"Front\":\"DIRECT\"}"] {
            _=try Commands().checked("/usr/bin/sqlite3",[f.root.appendingPathComponent("database.sqlite").path,"UPDATE profiles SET selected_map='\(map)';"])
            #expect(throws:(any Error).self){try f.read()}
        }
    }
    @Test func missingActiveProfileAndSymlinkPreferencesAreRejected() throws {
        let f=try CurrentChainFixture();try f.writePreferences(1)
        #expect(throws:(any Error).self){try f.read()}
        try f.writePreferences();let other=f.root.appendingPathComponent("other.plist")
        try FileManager.default.moveItem(at:f.prefs,to:other)
        try FileManager.default.createSymbolicLink(at:f.prefs,withDestinationURL:other)
        #expect(throws:(any Error).self){try f.read()}
    }
    @Test @MainActor func offReadRegistersGeneratedConfigAndPrefillsWithoutConfirmation() async throws {
        let f=try CurrentChainFixture(),snapshot=try f.read()
        let model=AppModel(autoPoll:false,preferences:nil,transport:{request in
            #expect(request.operation == .registerProxyConfiguration && request.configurationPath==snapshot.configurationPath)
            var status=Status();status.configurationPath=snapshot.configurationPath;status.fingerprint=snapshot.node.fingerprint
            status.gateway="8.8.4.4:5230";status.chainCandidate=snapshot.node.chain
            return .init(ok:true,status:status)
        })
        model.settings.expectedEgress="9.9.9.9";model.settings.entryIPv4="1.2.3.4";model.confirmation=true
        await model.readFlClashCurrentChain(read:{snapshot})?.value
        #expect(model.settings.entryName=="Entry" && model.settings.effectivePathMode == .chain)
        #expect(model.settings.gateway=="8.8.4.4" && model.settings.port==5230)
        #expect(model.settings.entryIPv4==nil && !model.confirmation && !model.state.verified)
        #expect(model.settings.expectedEgress=="9.9.9.9")
        model.state.phase="armed"
        #expect(model.readFlClashCurrentChain(read:{throw fail("must not read")})==nil)
    }
    @Test @MainActor func changedFingerprintDoesNotApplySelection() async throws {
        let f=try CurrentChainFixture(),snapshot=try f.read()
        let model=AppModel(autoPoll:false,preferences:nil,transport:{_ in
            var status=Status();status.fingerprint="changed";status.configurationPath=snapshot.configurationPath
            return .init(ok:true,status:status)
        })
        await model.readFlClashCurrentChain(read:{snapshot})?.value
        #expect(model.settings.entryName==nil && !model.confirmation && !model.failure.isEmpty)
    }
    @Test @MainActor func settingsChangeDuringReadDiscardsResult() async throws {
        let f=try CurrentChainFixture(),snapshot=try f.read(),release=DispatchSemaphore(value:0)
        let model=AppModel(autoPoll:false,preferences:nil,transport:{_ in Issue.record("stale read registered");return .init(ok:false,status:Status())})
        let action=model.readFlClashCurrentChain(read:{
            guard release.wait(timeout:.now()+5) == .success else {throw fail("timeout")};return snapshot
        })
        let task=try #require(action)
        model.settings.expectedEgress="9.9.9.9";release.signal();await task.value
        #expect(model.settings.entryName==nil && model.state.configurationPath==nil)
    }
    @Test func directConfigurationDoesNotPretendToBeAChain() throws {
        let f=try CurrentChainFixture()
        try Data(#"{"mode":"rule","proxies":[{"name":"ISP","type":"http","server":"8.8.4.4","port":5230}],"rules":[]}"#.utf8).write(to:f.generated)
        do {_=try f.read();Issue.record("direct accepted as chain")}catch {#expect(String(describing:error).contains("没有链式"))}
    }
    @Test func cyclicAndUnsupportedSelectionsFailExplicitly() throws {
        let entry=ChainEntry(name:"Entry",type:"vless",server:"entry.example",port:443)
        let chain=ChainConfiguration(dialer:"A",entries:[entry],groups:["A":["B"],"B":["A","UDP"]])
        for map in [["A":"B","B":"A"],["A":"B","B":"UDP"]] {
            #expect(throws:(any Error).self){try FlClashCurrentChain.resolve(chain:chain,selection:map)}
        }
    }
    @Test @MainActor func lifecycleChangeDiscardsReadBeforeRegistration() async throws {
        let f=try CurrentChainFixture(),snapshot=try f.read(),release=DispatchSemaphore(value:0)
        let model=AppModel(autoPoll:false,preferences:nil,transport:{request in
            #expect(request.operation == .stop);return .init(ok:true,status:Status())
        })
        let action=model.readFlClashCurrentChain(read:{
            guard release.wait(timeout:.now()+5) == .success else {throw fail("timeout")};return snapshot
        })
        let task=try #require(action)
        await model.request(.stop)?.value;release.signal();await task.value
        #expect(model.settings.entryName==nil && model.state.configurationPath==nil)
    }
}
