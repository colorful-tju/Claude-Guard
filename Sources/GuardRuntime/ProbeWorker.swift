import Foundation
import GuardCore

public struct WorkerSelfTest:Codable,Sendable {
    public let buildID:String
    public let protocolVersion:Int
    public let subprocess:Bool
    public let concurrentResults:Int
    public let networkProbes:Bool
}

/// Library isolation is deliberate: synchronous executable main must not wait on MainActor work.
public enum ProbeWorker {
    private final class Results:@unchecked Sendable {
        let lock=NSLock();var values:[String:EchoResult]=[:];var failed=false
        func put(_ key:String,_ value:String?) {
            lock.lock();defer{lock.unlock()}
            if let value{values[key] = .init(ipv4:value,measuredAt:monotonic())}else{failed=true}
        }
        func read() throws -> [String:EchoResult] {
            lock.lock();defer{lock.unlock()}
            guard !failed,values.count==EgressService.allCases.count else{throw fail("HTTPS echo worker failed")}
            return values
        }
    }
    public static func collectEchoes(timeout:TimeInterval=10,fetch:@escaping @Sendable (EgressService)throws->String) throws -> [String:EchoResult] {
        let box=Results(),group=DispatchGroup()
        for service in EgressService.allCases {
            group.enter()
            DispatchQueue.global().async {defer{group.leave()};box.put(service.rawValue,try? fetch(service))}
        }
        guard group.wait(timeout:.now()+timeout) == .success else{throw fail("Concurrent echo deadline exceeded")}
        return try box.read()
    }
    /// Exercises the actual worker executable and subprocess pipeline; no sockets or public probes.
    public static func selfTest(commands:Commands=Commands()) throws -> WorkerSelfTest {
        diagnostic("self-test-stage=subprocess-start")
        guard try commands.checked("/usr/bin/printf",["worker-subprocess-ok"],timeout:1)=="worker-subprocess-ok" else{throw fail("Worker subprocess self-test failed")}
        diagnostic("self-test-stage=concurrent-start")
        let values=try collectEchoes(timeout:1){_ in "192.0.2.1"}
        diagnostic("self-test-stage=quiescence")
        try commands.assertQuiescent()
        diagnostic("self-test-stage=complete")
        return .init(buildID:BuildIdentity.buildID,protocolVersion:BuildIdentity.protocolVersion,subprocess:true,concurrentResults:values.count,networkProbes:false)
    }
    public static func diagnostic(_ text:String) {
        // Only fixed stage names/numeric native diagnostics enter this stream; never credentials/argv.
        try? FileHandle.standardError.write(contentsOf:Data((text+"\n").utf8))
    }
}
