import Foundation
import Darwin
import Testing
import GuardRuntime
@testable import GuardUIModel

private final class CatalogFixture {
    let root=FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("flclash-catalog-"+UUID().uuidString)
    init() throws {try FileManager.default.createDirectory(at:root.appendingPathComponent("profiles"),withIntermediateDirectories:true)}
    deinit {try? FileManager.default.removeItem(at:root)}
    func file(_ name:String,_ content:String="proxies: []") throws {try Data(content.utf8).write(to:root.appendingPathComponent(name))}
    func database() throws {
        _=try Commands().checked("/usr/bin/sqlite3",[root.appendingPathComponent("database.sqlite").path,"CREATE TABLE profiles(id INTEGER PRIMARY KEY,label TEXT,url TEXT); INSERT INTO profiles VALUES(368414562417905664,'Canada HTTP','secret-subscription-token'); INSERT INTO profiles VALUES(2,'Old subscription','another-secret'); INSERT INTO profiles VALUES(3,'Deleted configuration','private-url');"])
    }
}

struct FlClashCatalogTests {
    @Test func numericFilenamesHaveCountsAndProvidersRemainExplicitlyIncomplete() throws {
        let f=try CatalogFixture()
        try f.file("profiles/100.yaml","proxies: [{type: http}]")
        try f.file("profiles/200.yaml","proxies: [{type: http}, {type: socks5}]")
        try f.file("profiles/300.yaml","proxy-providers: {remote: {path: NEVER_EMIT_SECRET}}")
        try f.file("profiles/400.yaml","proxies: [NEVER_EMIT_SECRET")
        let script=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/profile-summaries.rb").path
        let catalog=try FlClashCatalog.discover(root:f.root,summaryScript:script)
        let entries=Dictionary(uniqueKeysWithValues:catalog.entries.map{($0.filename,$0.summary)})
        #expect(entries["100.yaml"]?.nodeCount==1 && entries["100.yaml"]?.httpCount==1)
        #expect(entries["200.yaml"]?.nodeCount==2 && entries["200.yaml"]?.httpCount==1)
        #expect(entries["300.yaml"]?.providerCount==1)
        #expect(entries["400.yaml"]?.nodeCount==nil && entries["400.yaml"]?.errorCode != nil)
        #expect(!String(describing:catalog).contains("NEVER_EMIT_SECRET"))
    }
    @Test func missingSummaryToolStillAllowsListingButNeverClaimsZero() throws {
        let f=try CatalogFixture();try f.file("profiles/1.yaml","proxies: [{type: http}]")
        let entry=try #require(try FlClashCatalog.discover(root:f.root,summaryScript:"/nonexistent/summary.rb").entries.first)
        #expect(entry.summary.nodeCount==nil && entry.summary.errorCode != nil)
    }
    @Test func savedNamesResolveExactLargeIDsAndGeneratedConfigIsSeparate() throws {
        let f=try CatalogFixture();try f.database();try f.file("profiles/368414562417905664.yaml");try f.file("profiles/2.yaml");try f.file("config.yaml")
        let db=try Data(contentsOf:f.root.appendingPathComponent("database.sqlite"))
        let list=try FlClashCatalog.discover(root:f.root)
        #expect(list.entries.count==3 && list.warning.isEmpty)
        let canada=try #require(list.entries.first{$0.name=="Canada HTTP"})
        #expect(canada.path==f.root.appendingPathComponent("profiles/368414562417905664.yaml").path)
        #expect(!canada.generated)
        #expect(list.entries.last?.generated==true)
        #expect(!list.entries.contains{$0.name=="Deleted configuration"})
        #expect(!String(describing:list).contains("secret-subscription-token"))
        #expect(try Data(contentsOf:f.root.appendingPathComponent("database.sqlite"))==db)
    }
    @Test func missingOrCorruptMetadataStillListsYAMLByFilename() throws {
        let f=try CatalogFixture();try f.file("profiles/12.yaml");try f.file("profiles/other.yml")
        for corrupt in [false,true] {
            if corrupt {try f.file("database.sqlite","not a database secret-password")}
            let list=try FlClashCatalog.discover(root:f.root)
            #expect(Set(list.entries.map(\.name))==["12.yaml","other.yml"])
            #expect(!list.warning.isEmpty && !list.warning.contains("secret-password"))
        }
    }
    @Test func ignoresBackupDirectorySymlinkAndOversizedFiles() throws {
        let f=try CatalogFixture();try f.file("profiles/good.yaml");try f.file("profiles/old.yaml.backup")
        try FileManager.default.createDirectory(at:f.root.appendingPathComponent("profiles/directory.yaml"),withIntermediateDirectories:false)
        try FileManager.default.createSymbolicLink(atPath:f.root.appendingPathComponent("profiles/link.yaml").path,withDestinationPath:f.root.appendingPathComponent("profiles/good.yaml").path)
        try Data(repeating:32,count:2_000_001).write(to:f.root.appendingPathComponent("profiles/large.yaml"))
        let list=try FlClashCatalog.discover(root:f.root)
        #expect(list.entries.map(\.name)==["good.yaml"])
    }
    @Test func absentRootHasActionableErrorAndNoDirectoriesAreCreated() throws {
        let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        do {_=try FlClashCatalog.discover(root:root);Issue.record("missing folder accepted")}
        catch {#expect(String(describing:error).contains("手动"))}
        #expect(!FileManager.default.fileExists(atPath:root.path))
    }
    @Test func symlinkedProfilesFolderIsNotFollowed() throws {
        let f=try CatalogFixture(),other=try CatalogFixture();try other.file("profiles/other.yaml")
        try FileManager.default.removeItem(at:f.root.appendingPathComponent("profiles"))
        try FileManager.default.createSymbolicLink(atPath:f.root.appendingPathComponent("profiles").path,withDestinationPath:other.root.appendingPathComponent("profiles").path)
        #expect(try FlClashCatalog.discover(root:f.root).entries.isEmpty)
    }
    @Test @MainActor func readingCatalogNeverRegistersOrConfirmsAndActiveSessionRejectsIt() async throws {
        let f=try CatalogFixture();try f.file("profiles/one.yaml");let root=f.root
        let model=AppModel(autoPoll:false,preferences:nil,transport:{_ in Issue.record("discovery called privileged IPC");return .init(ok:false,status:Status())})
        model.confirmation=true
        await model.readFlClashConfigurations(read:{try FlClashCatalog.discover(root:root)})?.value
        #expect(model.flclashCatalog?.entries.count==1 && model.confirmation && model.state.configurationPath==nil)
        model.state.phase="armed"
        #expect(model.readFlClashConfigurations(read:{throw fail("must not read")})==nil)
    }
    @Test @MainActor func lifecycleChangeDiscardsAnInFlightListWithoutRegistering() async throws {
        let model=AppModel(autoPoll:false,preferences:nil,transport:{request in
            #expect(request.operation == .stop);return .init(ok:true,status:Status())
        })
        let release=DispatchSemaphore(value:0)
        let action=model.readFlClashConfigurations(read:{
            guard release.wait(timeout:.now()+5) == .success else{throw fail("fixture timeout")}
            return .init(entries:[])
        })
        let pending=try #require(action)
        await model.request(.stop)?.value
        release.signal();await pending.value
        #expect(model.flclashCatalog==nil && !model.readingFlClash && model.state.configurationPath==nil)
    }
}
