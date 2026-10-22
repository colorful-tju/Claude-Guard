import Foundation
import Testing
import Darwin
@testable import GuardRuntime
struct NodeCacheTests {
    func node(_ raw:Data) -> NodeConfiguration {.init(name:"test",type:"http",server:"1.2.3.4",port:8080,fingerprint:hash(raw),numeric:true,tunDevice:"utun7")}
    @Test func unchangedContentNeverRestartsBusyParser() throws {
        let cache=VerifiedNodeCache();let raw=Data("config".utf8);var calls=0
        for _ in 0..<100 {
            let n=try cache.read(readBytes:{raw},parse:{ bytes in
                calls += 1
                if calls>1 {throw fail("Command deadline-exceeded: ruby")}
                return node(bytes)
            })
            #expect(n.fingerprint==hash(raw))
        }
        #expect(calls==1)
    }
    @Test func changedBytesRequireNewSuccessfulParse() throws {
        let cache=VerifiedNodeCache();let a=Data("aaaa".utf8),b=Data("bbbb".utf8)
        _=try cache.read(readBytes:{a},parse:node)
        #expect(throws:(any Error).self){try cache.read(readBytes:{b},parse:{_ in throw fail("invalid config")})}
        var parsed=false
        _=try cache.read(readBytes:{b},parse:{parsed=true;return node($0)})
        #expect(parsed)
    }
    @Test func missingUnreadableOrChangedDuringParseNeverUsesOldResult() throws {
        let cache=VerifiedNodeCache();let a=Data("a".utf8),b=Data("b".utf8)
        _=try cache.read(readBytes:{a},parse:node)
        #expect(throws:(any Error).self){try cache.read(readBytes:{throw fail("read failed")},parse:node)}
        var reads=0
        #expect(throws:(any Error).self){try cache.read(readBytes:{reads += 1;return reads==1 ? b:a},parse:node)}
    }
    @Test func wrongParserFingerprintRejected() {
        let cache=VerifiedNodeCache()
        #expect(throws:(any Error).self){try cache.read(readBytes:{Data("a".utf8)},parse:{_ in node(Data("b".utf8))})}
    }
    @Test func descriptorReaderRejectsLinksFifoOversizeAndWrongOwner() throws {
        let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
        defer{try? FileManager.default.removeItem(at:directory)}
        let file=directory.appendingPathComponent("node").path
        try Data("test".utf8).write(to:URL(fileURLWithPath:file))
        #expect(try VerifiedNodeCache.bytes(path:file,owner:getuid())==Data("test".utf8))
        #expect(throws:(any Error).self){try VerifiedNodeCache.bytes(path:file,owner:getuid()+1)}
        let link=directory.appendingPathComponent("link").path
        try FileManager.default.createSymbolicLink(atPath:link,withDestinationPath:file)
        #expect(throws:(any Error).self){try VerifiedNodeCache.bytes(path:link,owner:getuid())}
        let fifo=directory.appendingPathComponent("fifo").path
        #expect(mkfifo(fifo,0o600)==0)
        #expect(throws:(any Error).self){try VerifiedNodeCache.bytes(path:fifo,owner:getuid())}
        try Data(repeating:0,count:2_000_001).write(to:URL(fileURLWithPath:file))
        #expect(throws:(any Error).self){try VerifiedNodeCache.bytes(path:file,owner:getuid())}
    }

}
