import Foundation
import SystemConfiguration
import Darwin

public enum IPv6Mode:String,Codable,Sendable {case off="Off",automatic="Automatic"}
public struct IPv6Configuration:Codable,Equatable,Sendable {
    public let serviceID:String,interface:String,enabled:Bool,plist:Data
    public init(serviceID:String,interface:String,enabled:Bool,configuration:[String:Any]) throws {
        self.serviceID=serviceID;self.interface=interface;self.enabled=enabled
        var normalized=configuration;normalized.removeValue(forKey:"__INACTIVE__")
        plist=try PropertyListSerialization.data(fromPropertyList:normalized,format:.binary,options:0)
    }
    public var dictionary:[String:Any] { (try? PropertyListSerialization.propertyList(from:plist,format:nil)) as? [String:Any] ?? [:] }
    func validate() throws {
        guard !serviceID.isEmpty,serviceID.utf8.count<=128,interface.range(of:"^en[0-9]{1,3}$",options:.regularExpression) != nil,
              plist.count<=65536,let value=try PropertyListSerialization.propertyList(from:plist,format:nil) as? [String:Any],value["ConfigMethod"] is String else{throw fail("Malformed IPv6 backup; refusing preference changes")}
    }
    public var method:String {enabled ? (dictionary["ConfigMethod"] as? String ?? "unknown") : "Off"}
    public static func ==(a:Self,b:Self)->Bool {
        a.serviceID==b.serviceID && a.interface==b.interface && a.enabled==b.enabled && NSDictionary(dictionary:a.dictionary).isEqual(to:b.dictionary)
    }
    func changing(_ mode:IPv6Mode)throws->Self {
        try .init(serviceID:serviceID,interface:interface,enabled:mode != .off,configuration:mode == .off ? dictionary:["ConfigMethod":"Automatic"])
    }
}
public struct IPv6Override:Codable,Sendable {
    let version:Int
    let original:IPv6Configuration
    var applied:IPv6Configuration
    // A write-ahead intent covers crashes before/after SCPreferences commit/apply.
    var pending:IPv6Configuration?
}
struct IPv6Store:Sendable {
    let read:@Sendable ()throws->IPv6Override?
    let write:@Sendable (IPv6Override)throws->Void
    let remove:@Sendable ()throws->Void
}
struct IPv6Backend:Sendable {
    let read:@Sendable (String)throws->IPv6Configuration
    let compareAndApply:@Sendable (IPv6Configuration,IPv6Configuration)throws->Void
}
/// Used only on the daemon transaction queue. No modification in its initializer.
public final class TemporaryIPv6:@unchecked Sendable {
    private let store:IPv6Store,backend:IPv6Backend
    init(store:IPv6Store,backend:IPv6Backend){self.store=store;self.backend=backend}
    public convenience init(){
        let path=Paths.root+"/ipv6-override.json"
        self.init(store:.init(read:{
            var st=stat();if lstat(path,&st) != 0 {guard errno==ENOENT else{throw fail("IPv6 journal unreadable")};return nil}
            return try PrivateFiles.read(path,as:IPv6Override.self)
        },write:{try PrivateFiles.write($0,to:path)},remove:{try PrivateControllerStorage().remove("ipv6-override.json")}),backend:SystemIPv6.backend)
    }
    private func readRecord() throws -> IPv6Override? {
        guard let record=try store.read() else{return nil}
        guard record.version==1 else{throw fail("Unknown IPv6 backup version")}
        for value in [record.original,record.applied]+(record.pending.map{[$0]} ?? []) {
            try value.validate()
            guard value.serviceID==record.original.serviceID,value.interface==record.original.interface else{throw fail("IPv6 backup service mismatch")}
        }
        return record
    }
    public func summary()throws->String {
        guard let value=try readRecord() else{return "未临时修改"}
        return "\(value.original.interface)：临时 \(value.pending?.method ?? value.applied.method)；原设置 \(value.original.method) 已保存"
    }
    public func hasOverride()throws->Bool {try readRecord() != nil}
    public func verifyStable() throws {
        guard let record=try readRecord() else{return}
        guard record.version==1,record.pending==nil,try backend.read(record.original.interface)==record.applied else{throw fail("IPv6 override incomplete or changed externally; restore before protection")}
    }
    public func set(_ mode:IPv6Mode,interface:String)throws {
        guard interface.range(of:"^en[0-9]{1,3}$",options:.regularExpression) != nil else{throw fail("IPv6 controls require an explicit physical en interface")}
        let current=try backend.read(interface);try current.validate()
        var record=try readRecord() ?? .init(version:1,original:current,applied:current,pending:nil)
        guard record.version==1,record.original.interface==interface,current==record.applied,record.pending==nil else{throw fail("IPv6 settings changed or an unfinished override exists; restore first")}
        let target=try current.changing(mode)
        record.pending=target;try store.write(record)
        try backend.compareAndApply(current,target)
        guard try backend.read(interface)==target else{throw fail("IPv6 preference readback failed; recovery record retained")}
        record.applied=target;record.pending=nil;try store.write(record)
    }
    public func restore()throws {
        guard var record=try readRecord() else{return}
        guard record.version==1 else{throw fail("Unknown IPv6 recovery version")}
        let current=try backend.read(record.original.interface)
        guard current==record.original || current==record.applied || current==record.pending else{throw fail("IPv6 changed outside this app; original backup retained, refusing to overwrite")}
        // Re-apply even if preferences already match: a crash may have happened between commit and apply.
        // The observed value may be the old pending target, not the last completed value.
        // Preserve it before replacing pending so a crash/failed restore can be retried.
        record.applied=current;record.pending=record.original;try store.write(record)
        try backend.compareAndApply(current,record.original)
        guard try backend.read(record.original.interface)==record.original else{throw fail("IPv6 restore readback failed")}
        try store.remove()
    }
}
private enum SystemIPv6 {
    static let backend=IPv6Backend(read:{interface in try withPreferences{prefs in try capture(prefs,interface).0}},compareAndApply:{expected,target in
        try withPreferences{prefs in
            let (current,proto)=try capture(prefs,expected.interface)
            guard current==expected,target.serviceID==current.serviceID,target.interface==current.interface else{throw fail("IPv6 service changed before commit")}
            guard SCNetworkProtocolSetConfiguration(proto,target.dictionary as CFDictionary),SCNetworkProtocolSetEnabled(proto,target.enabled),SCPreferencesCommitChanges(prefs),SCPreferencesApplyChanges(prefs) else{throw fail("IPv6 commit/apply failed (SCError=\(SCError())); recovery record retained")}
        }
    })
    static func withPreferences<T>(_ body:(SCPreferences)throws->T)throws->T {
        guard let prefs=SCPreferencesCreate(nil,"ClaudeSafeLauncher IPv6" as CFString,nil),SCPreferencesLock(prefs,false) else{throw fail("IPv6 preferences busy or administrator access unavailable")}
        defer{SCPreferencesUnlock(prefs)}
        SCPreferencesSynchronize(prefs)
        return try body(prefs)
    }
    static func capture(_ prefs:SCPreferences,_ interface:String)throws->(IPv6Configuration,SCNetworkProtocol) {
        guard let set=SCNetworkSetCopyCurrent(prefs),let all=SCNetworkSetCopyServices(set) as? [SCNetworkService] else{throw fail("Current network services unavailable")}
        let services=all.filter { service in
            guard SCNetworkServiceGetEnabled(service),let i=SCNetworkServiceGetInterface(service) else{return false}
            return (SCNetworkInterfaceGetBSDName(i) as String?)==interface
        }
        guard services.count==1,let service=services.first,let serviceID=SCNetworkServiceGetServiceID(service),let proto=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeIPv6),let config=SCNetworkProtocolGetConfiguration(proto) as? [String:Any] else{throw fail("No unique enabled IPv6 service for physical interface")}
        return (try .init(serviceID:serviceID as String,interface:interface,enabled:SCNetworkProtocolGetEnabled(proto),configuration:config),proto)
    }
}
