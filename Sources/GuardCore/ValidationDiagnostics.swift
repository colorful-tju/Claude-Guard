import Foundation

/// Local diagnostic record, never permission to arm and never a replacement baseline.
public struct ValidationDiagnostics:Codable,Sendable {
    public var networkEvents:[String]?
    public var attempt:Int?
    public let sessionID:UUID
    public let capturedAt:String
    public let changedFields:[String]
    public var baseline:LocalSnapshot
    public var final:LocalSnapshot
    public let egress:[EgressObservation]
    public let negative:[NegativeProbe]
    public let routesBefore:String
    public let routesAfter:String
    public init(bundle:ValidationBundle,final:LocalSnapshot,routesBefore:String,routesAfter:String) {
        sessionID=bundle.sessionID;capturedAt=ISO8601DateFormatter().string(from:Date())
        changedFields=bundle.baseline.differingFields(from:final)
        baseline=bundle.baseline;self.final=final
        baseline.ownReference="[redacted]";self.final.ownReference="[redacted]"
        egress=bundle.egress;negative=bundle.negative
        self.routesBefore=routesBefore;self.routesAfter=routesAfter
    }
    public func encoded() throws -> Data {
        let data=try JSONEncoder().encode(self)
        guard data.count<=49152 else{throw GuardFailure.rejected("Validation diagnostic exceeds 48 KiB limit")}
        return data
    }
}
