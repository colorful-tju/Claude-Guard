import Foundation
import Testing
import Darwin
import NativeGuard
import GuardCore
@testable import GuardRuntime

@Suite struct SocketObservationTests {
    @Test func protocolIsNotInferredFromSOCKINFOIN() {
        #expect(SocketObservation.transport(type:Int32(SOCK_DGRAM),number:Int32(IPPROTO_UDP)) == "udp")
        #expect(SocketObservation.transport(type:Int32(SOCK_STREAM),number:Int32(IPPROTO_TCP)) == "tcp")
        #expect(SocketObservation.transport(type:Int32(SOCK_RAW),number:Int32(IPPROTO_ICMP)) == "other")
        #expect(SocketObservation.transport(type:Int32(SOCK_DGRAM),number:0) == "other")
    }
    @Test func localAddressClassifiesScopeNotLeakage() {
        for (address,scope) in [("0.0.0.0","wildcard"),("::","wildcard"),("127.0.0.2","loopback"),("::1","loopback"),("172.21.1.2","physical-source"),("198.18.0.1","tun-source"),("8.8.8.8","other")] {
            #expect(SocketObservation.scope(address,physical:"172.21.1.2",tun:"198.18.0.1") == scope)
        }
    }
    @Test func recycledProcessIdentityAndPartialSocketReadsAreNotAttributed() throws {
        let p=try policy(),identity=ProcessIdentity(pid:42,startTime:100,executableIdentity:"/Applications/Claude.app/Contents/MacOS/Claude")
        var calls=0
        let report=SocketObservationReport.collect(policy:p,processes:[identity],readProcess:{_ in
            calls += 1
            return .init(pid:42,ppid:1,uid:501,started:calls==1 ? 100:200,path:identity.executableIdentity,name:"Claude")
        },readSockets:{_ in [CSGSocket()]})
        #expect(report.records.isEmpty && !report.complete && report.examinedProcesses==0)
        let unreadable=SocketObservationReport.collect(policy:p,processes:[identity],readProcess:{_ in
            .init(pid:42,ppid:1,uid:501,started:100,path:identity.executableIdentity,name:"Claude")
        },readSockets:{_ in throw fail("descriptor disappeared")})
        #expect(unreadable.records.isEmpty && !unreadable.complete)
        #expect(unreadable.issues.first?.contains("descriptor disappeared")==true)
    }
    @Test func reportsAreBoundedAndTruncationIsExplicit() throws {
        let p=try policy(),record=ProcessRecord(pid:42,ppid:1,uid:501,started:100,path:"/Applications/Claude.app/Contents/MacOS/Claude",name:"Claude")
        var socket=CSGSocket();socket.family=AF_INET
        let report=SocketObservationReport.collect(policy:p,processes:[record.identity],readProcess:{_ in record},readSockets:{_ in Array(repeating:socket,count:1000)})
        #expect(report.records.count==64 && report.totalInternetSockets==1000 && report.truncated && !report.complete)
        #expect(try JSONEncoder().encode(report).count<65536)
    }
    private func policy() throws -> GuardPolicy {
        let e=try Endpoint(gateway:"23.20.10.8",port:5376,expectedEgress:"1.1.1.1",configurationFingerprint:"x",providerConfirmed:true,confirmedGateway:"23.20.10.8",confirmedPort:5376,confirmedFingerprint:"x",protocolName:"http")
        return try GuardPolicy(endpoint:e,physical:.init(name:"en0",index:6,generation:1,ipv4:"172.21.191.84"),tun:.init(name:"utun4",index:20,generation:1,ipv4:"198.18.0.1"))
    }
    @Test func nativeUnsentUDPIsReportedWithActualProtocol() throws {
        let fd=socket(AF_INET,SOCK_DGRAM,0);#expect(fd>=0);guard fd>=0 else{return};defer{close(fd)}
        var address=sockaddr_in();address.sin_len=UInt8(MemoryLayout<sockaddr_in>.size);address.sin_family=sa_family_t(AF_INET)
        let bound=withUnsafePointer(to:&address){$0.withMemoryRebound(to:sockaddr.self,capacity:1){Darwin.bind(fd,$0,socklen_t(MemoryLayout<sockaddr_in>.size))}}
        #expect(bound==0)
        let found=try NativeProcesses.sockets(getpid()).first{$0.fd==fd}
        let row=try #require(found)
        #expect(row.socket_type==Int32(SOCK_DGRAM) && row.protocol_number==Int32(IPPROTO_UDP))
        #expect(row.local_port>0 && row.remote_port==0)
    }
}
