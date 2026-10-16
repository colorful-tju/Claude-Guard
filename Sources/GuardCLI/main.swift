import Foundation
import Darwin
import GuardRuntime
// Local inspection can run before installation, and never invokes PF, probes or a proxy control API.
do {
    let args=Array(CommandLine.arguments.dropFirst())
    if args==["doctor"] {
        let cmds=Commands()
        let os=try cmds.checked("/usr/bin/sw_vers",["-productVersion"])
        let interfaces=try cmds.checked("/sbin/ifconfig",["-l"])
        print("readOnly=true macOS=\(os.trimmingCharacters(in:.whitespacesAndNewlines))\ninterfaces=\(interfaces.trimmingCharacters(in:.whitespacesAndNewlines))\nCore registration is held by the administrator helper. No PF changes or network probes performed")
    } else if let op=args.first.flatMap(GuardOperation.init(rawValue:)),args.count==1,![GuardOperation.selfTest,.start,.verify,.heartbeat,.ipv6Off,.ipv6Automatic,.ipv6Restore].contains(op) {
        let reply=try Wire.client(.init(op));let enc=JSONEncoder();enc.outputFormatting=[.prettyPrinted,.sortedKeys];print(String(decoding:try enc.encode(reply),as:UTF8.self));if !reply.ok{exit(2)}
    } else {print("guardctl doctor | status | inspect | stop | export\n启动与防护验收请使用桌面应用，在确认服务商 endpoint 后执行。");if !args.isEmpty{exit(2)}}
} catch {fputs("guardctl: \(error)\n",stderr);exit(1)}
