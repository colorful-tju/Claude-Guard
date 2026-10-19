import Foundation
import GuardCore

/// Only fixed, sanitized diagnostics from ProbeExecutor may enter the worker report.
struct EchoRequestFailure:Error,CustomStringConvertible {
    let description:String
}
public struct StartupEchoSample:Codable,Sendable {
    public var service:EgressService
    public var outcome:String
    public var elapsed:Double
}
public struct StartupEchoFailure:Error,Codable,Sendable,CustomStringConvertible {
    public var schema="startup-echo-v1"
    public var deadlineExceeded:Bool
    public var samples:[StartupEchoSample]
    public var description:String {
        let summary=samples.map{"\($0.service.rawValue)[\($0.outcome); \(String(format:"%.3f",$0.elapsed))s]"}.joined(separator:"; ")
        return (deadlineExceeded ? "HTTPS echo collection deadline exceeded: ":"HTTPS echo worker failed: ")+summary
    }
    /// The signed worker emits a separate JSON error payload on stdout, never a partial success map.
    static func decodedSummary(_ output:String)->String? {
        guard output.utf8.count<=8192,let value=try? JSONDecoder().decode(Self.self,from:Data(output.utf8)),
              value.schema=="startup-echo-v1",value.samples.count==2,
              Set(value.samples.map(\.service))==Set(EgressService.allCases),
              value.samples.allSatisfy({$0.elapsed.isFinite && $0.elapsed>=0 && $0.outcome.utf8.count<=256 && !$0.outcome.isEmpty && !$0.outcome.unicodeScalars.contains(where:CharacterSet.controlCharacters.contains)}) else{return nil}
        return value.description
    }
    static func safeOutcome(_ error:Error)->String {
        if let known=error as? EchoRequestFailure{return known.description}
        if let command=error as? CommandFailure {
            // No argv, raw stderr, response body, or arbitrary Error.description.
            if command.stage=="deadline-exceeded" {return "command-deadline-exceeded"}
            if command.stage.hasPrefix("cancelled") {return "command-cancelled"}
            return "command-execution-failed"
        }
        return "unknown-error"
    }
}
