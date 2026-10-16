import Foundation
import Darwin
import GuardCore
import GuardRuntime
// Production work is implemented in a non-MainActor library, including concurrent echo collection.
do {
    let args=Array(CommandLine.arguments.dropFirst())
    ProbeWorker.diagnostic("worker-enter build=\(BuildIdentity.buildID)")
    if args==["--self-test"] {
        print(String(decoding:try JSONEncoder().encode(ProbeWorker.selfTest(commands:Commands(workerLeafTools:true))),as:UTF8.self))
    } else if args==["--egress"] {
        let commands=Commands(workerLeafTools:true)
        let values=try ProbeWorker.collectEchoes {service in try ProbeExecutor.egress(service:service,commands:commands)}
        try commands.assertQuiescent()
        print(String(decoding:try JSONEncoder().encode(values),as:UTF8.self))
    } else if args.count==5,args[0]=="--negative",let kind=ProbeKind(rawValue:args[1]),let index=UInt32(args[4]),index>0,IPv4.octets(args[3]) != nil,if_nametoindex(args[2])==index {
        let result=try ProbeExecutor.negative(kind:kind,physical:.init(name:args[2],index:index,generation:1,ipv4:args[3]))
        print(String(decoding:try JSONEncoder().encode(result),as:UTF8.self))
        if result.setupError{exit(2)}
    } else {
        print("guard-probe --self-test (offline) | --egress | --negative boundTCP|boundUDP|boundSTUN <interface> <localIPv4> <ifindex>\n除 self-test 外显式运行会发送网络探针。")
        if !args.isEmpty{exit(2)}
    }
} catch {ProbeWorker.diagnostic("worker-failed \(error)");exit(1)}
