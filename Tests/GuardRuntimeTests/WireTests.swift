import Foundation
import Darwin
import Testing
@testable import GuardRuntime
private final class SocketPair:@unchecked Sendable {
    var fds=[Int32](repeating:-1,count:2)
    init() throws {guard socketpair(AF_UNIX,SOCK_STREAM,0,&fds)==0 else{throw fail("socketpair")}}
    deinit {for fd in fds{close(fd)}}
}
struct WireTests {
    @Test func OFFInvalidatesAlreadyQueuedStarts() {
        let gate=RequestAdmission(),old=gate.ticket()
        gate.cancelPendingStarts()
        #expect(!gate.accepts(old));#expect(gate.accepts(gate.ticket()))
    }
    @Test func actualSocketFramesRoundTripAndRejectOversizedWrites() throws {
        let pair=try SocketPair();let data=Data("{\"ok\":true}".utf8)
        try Wire.write(data,pair.fds[0]);#expect(try Wire.read(pair.fds[1])==data)
        #expect(throws:(any Error).self){try Wire.write(Data(repeating:65,count:65536),pair.fds[0])}
    }
    @Test func slowPartialFrameCannotResetAbsoluteDeadline() throws {
        let pair=try SocketPair(),done=DispatchSemaphore(value:0)
        DispatchQueue.global().async {
            defer{done.signal()}
            for _ in 0..<10 {var b:UInt8=65;_=send(pair.fds[0],&b,1,MSG_DONTWAIT);Thread.sleep(forTimeInterval:0.02)}
        }
        let start=DispatchTime.now().uptimeNanoseconds
        #expect(throws:(any Error).self){try Wire.read(pair.fds[1],timeout:0.06)}
        #expect(Double(DispatchTime.now().uptimeNanoseconds-start)/1e9<0.18)
        #expect(done.wait(timeout:.now()+1) == .success)
    }
    @Test func correlatedReplyRequiresSameRequestProtocolAndBuild() throws {
        let request=Request(.status);var reply=Reply(ok:true,status:Status());reply.requestID=request.id
        #expect(try Wire.validate(reply,for:request).ok)
        reply.requestID=UUID().uuidString
        #expect(throws:(any Error).self){try Wire.validate(reply,for:request)}
        reply.requestID=request.id;reply.status.daemonBuildID="old"
        #expect(throws:(any Error).self){try Wire.validate(reply,for:request)}
    }
}
