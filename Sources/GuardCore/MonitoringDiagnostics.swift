import Foundation

/// Evidence for a failed observation, never a replacement baseline or permission to arm.
public struct MonitoringDiagnostics:Codable,Sendable {
    public let kind:String
    public let formatVersion:Int
    public let buildID:String
    public let sessionID:UUID
    public let capturedAt:String
    public let stage:String
    public let reason:String
    public let currentComplete:Bool
    public let changedFields:[String]
    public let rawChangedFields:[String]
    public let acceptedRouteEquivalence:Bool
    public let changedSincePrevious:[String]
    public let baseline:LocalSnapshot
    public let previousHealthy:LocalSnapshot?
    public let current:LocalSnapshot?
    public let baselineRoutes:String
    public let previousRoutes:String?
    public let currentRoutes:String?
    public let previousHealthyAt:String?
    public var networkEvents:[String]? = nil
    public var recoveryPhase:String="pending"

    public init(sessionID:UUID,buildID:String,stage:String,reason:String,baseline:LocalSnapshot,
                previousHealthy:LocalSnapshot?,current:LocalSnapshot?,baselineRoutes:String,
                previousRoutes:String?,currentRoutes:String?,previousHealthyAt:String?,acceptedRouteEquivalence:Bool=false) {
        kind="monitoringFailure";formatVersion=2
        self.sessionID=sessionID;self.buildID=buildID;self.stage=stage
        capturedAt=ISO8601DateFormatter().string(from:Date())
        self.reason=String(reason.prefix(4096));currentComplete=current != nil
        self.acceptedRouteEquivalence=acceptedRouteEquivalence
        // Runtime supplies this only after the hash-bound runtime route equivalence proof; retain raw snapshots below.
        changedFields=current.map{sample in
            var compared=sample;if acceptedRouteEquivalence{compared.routeFingerprint=baseline.routeFingerprint}
            return MonitoringGate.changedPremises(compared,baseline:baseline)
        } ?? []
        rawChangedFields=current.map{baseline.differingFields(from:$0)} ?? []
        changedSincePrevious=current.flatMap{sample in previousHealthy.map{$0.differingFields(from:sample)}} ?? []
        func redacted(_ snapshot:LocalSnapshot)->LocalSnapshot {var copy=snapshot;copy.ownReference="[redacted]";return copy}
        self.baseline=redacted(baseline);self.previousHealthy=previousHealthy.map(redacted);self.current=current.map(redacted)
        self.baselineRoutes=baselineRoutes;self.previousRoutes=previousRoutes;self.currentRoutes=currentRoutes
        self.previousHealthyAt=previousHealthyAt
    }
    public func encoded() throws -> Data {
        let data=try JSONEncoder().encode(self)
        guard data.count<=98304 else{throw GuardFailure.rejected("Monitoring diagnostic exceeds 96 KiB limit")}
        return data
    }
}
