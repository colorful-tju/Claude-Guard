import Foundation
import Darwin
import GuardCore
import NativeGuard

/// Passive socket metadata cannot establish packet egress, STUN use or a public IP leak.
/// In particular SOCKINFO_IN describes the union layout, not the IP protocol.
struct SocketObservation: Encodable, Sendable {
    let pid:Int32
    let processStarted:UInt64
    let executable:String
    let fd:Int32
    let family:Int32
    let kind:Int32
    let socketType:Int32
    let protocolNumber:Int32
    let transport:String
    let localAddress:String
    let localPort:UInt16
    let remoteAddress:String
    let remotePort:UInt16
    let localScope:String
    let tcpState:Int32?

    static func transport(type:Int32,number:Int32)->String {
        if type==Int32(SOCK_DGRAM) && number==Int32(IPPROTO_UDP) {return "udp"}
        if type==Int32(SOCK_STREAM) && number==Int32(IPPROTO_TCP) {return "tcp"}
        return "other"
    }
    static func scope(_ address:String,physical:String,tun:String)->String {
        if address=="0.0.0.0" || address=="::" {return "wildcard"}
        var ipv4=in_addr()
        if address=="::1" || (inet_pton(AF_INET,address,&ipv4)==1 && (UInt32(bigEndian:ipv4.s_addr)>>24)==127) {return "loopback"}
        if address==physical {return "physical-source"}
        if address==tun {return "tun-source"}
        return "other"
    }
    init(_ value:CSGSocket,process:ProcessIdentity,policy:GuardPolicy) {
        var value=value
        pid=process.pid;processStarted=process.startTime
        executable=URL(fileURLWithPath:process.executableIdentity).lastPathComponent
        fd=value.fd;family=value.family;kind=value.kind
        socketType=value.socket_type;protocolNumber=value.protocol_number
        transport=Self.transport(type:socketType,number:protocolNumber)
        localAddress=NativeProcesses.text(&value.local);remoteAddress=NativeProcesses.text(&value.remote)
        localPort=value.local_port;remotePort=value.remote_port
        localScope=Self.scope(localAddress,physical:policy.physical.ipv4,tun:policy.tun.ipv4)
        tcpState=transport=="tcp" ? value.state:nil
    }
}

public struct SocketObservationReport: Encodable, Sendable {
    let sessionID:UUID
    let buildID:String = BuildIdentity.buildID
    let capturedAt:String = ISO8601DateFormatter().string(from:Date())
    let meaning:String = "Passive metadata only; no packet egress or public-IP leakage attribution. PF is the preventive boundary."
    var examinedProcesses=0
    var totalInternetSockets=0
    var truncated=false
    var records:[SocketObservation]=[]
    var issues:[String]=[]
    var complete:Bool {issues.isEmpty && !truncated}

    mutating func issue(_ value:String) {
        if issues.count<8 {issues.append(String(value.prefix(256)))}
        else {truncated=true}
    }
    static func collect(policy:GuardPolicy,processes:[ProcessIdentity],
                        readProcess:(Int32)throws->ProcessRecord = NativeProcesses.record,
                        readSockets:(Int32)throws->[CSGSocket] = NativeProcesses.sockets)->Self {
        var result=Self(sessionID:policy.sessionID)
        // The protected runtime snapshot supplies identities; do not attribute a recycled PID.
        result.truncated=processes.count>64
        for identity in processes.prefix(64) {
            do {
                guard try readProcess(identity.pid).identity==identity else{throw fail("Identity changed before socket collection")}
                let sockets=try readSockets(identity.pid)
                guard try readProcess(identity.pid).identity==identity else{throw fail("Identity changed during socket collection")}
                result.examinedProcesses += 1
                for socket in sockets where socket.family==AF_INET || socket.family==AF_INET6 {
                    result.totalInternetSockets += 1
                    if result.records.count<64 {result.records.append(.init(socket,process:identity,policy:policy))}
                    else {result.truncated=true}
                }
            }catch{result.issue("pid=\(identity.pid): \(error)")}
        }
        return result
    }
}
