import Foundation

public struct ProxyConfigurationFailure:Error,CustomStringConvertible,Sendable {
    public let code:String
    public let count:Int?
    public var description:String {
        let reasons=["unregistered":"尚未登记代理配置，请在网络设置选择当前使用的配置文件", "path":"配置必须是绝对路径的普通 YAML 文件", "node-count":"读取到 \(count ?? 0) 个节点；本版要求恰好一个 HTTP 节点，请核对是否选中了旧订阅", "proxies-shape":"proxies 缺失或不是节点数组", "providers":"包含外部 proxy-providers，当前版本不支持", "node-type":"节点名称为空或类型不是 HTTP", "node-shape":"节点格式无效", "transport":"节点启用了不支持的 TLS/UDP/链式代理或接口绑定", "endpoint":"网关须为服务商支持的数字 IPv4", "port":"端口必须为 1–65535 的整数", "mode":"配置 mode 必须为 rule/global", "rules":"rules 格式无效", "oversized":"配置超过 2 MB", "yaml-invalid":"YAML 语法、编码或 alias 不受支持", "yaml-documents":"不支持多个 YAML 文档", "yaml-key":"YAML 键格式无效", "yaml-duplicate":"YAML 存在重复键", "root-shape":"配置顶层格式无效", "reader-error":"解析组件失败，请导出反馈", "unreadable":"配置无法读取或文件所有者/类型发生变化"]
        return "Proxy configuration: "+(reasons[code] ?? "解析组件失败，请导出反馈")
    }
}
public enum ProxyConfiguration {
    static func validatePath(_ path:String) throws {
        guard !path.isEmpty else{throw ProxyConfigurationFailure(code:"unregistered",count:nil)}
        guard path.hasPrefix("/"),path.utf8.count<=4096,!path.contains("\n"),!path.contains("\r"),!path.utf8.contains(0) else{throw ProxyConfigurationFailure(code:"path",count:nil)}
    }
    static func parse(_ bytes:Data,commands:Commands,script:String=Paths.root+"/read-node.rb") throws -> NodeConfiguration {
        let result=try commands.run("/usr/bin/ruby",[script,"--stdin"],input:bytes)
        return try decode(result)
    }
    static func decode(_ result:CommandResult) throws -> NodeConfiguration {
        if result.status != 0 {
            struct Diagnostic:Decodable {let errorCode:String;let nodeCount:Int?}
            let value=try? JSONDecoder().decode(Diagnostic.self,from:Data(result.output.utf8))
            throw ProxyConfigurationFailure(code:value?.errorCode ?? "reader-error",count:value?.nodeCount.flatMap{$0>=0 && $0<=2_000_000 ? $0:nil})
        }
        return try NodeConfiguration.parse(Data(result.output.utf8))
    }
    static func bytes(path:String,uid:UInt32) throws -> Data {
        try validatePath(path)
        do{return try VerifiedNodeCache.bytes(path:path,owner:uid)}
        catch{throw ProxyConfigurationFailure(code:"unreadable",count:nil)}
    }
    public static func candidate(path:String,uid:UInt32,commands:Commands,script:String=Paths.root+"/read-node.rb") throws -> NodeConfiguration {
        try VerifiedNodeCache().read(readBytes:{try bytes(path:path,uid:uid)},parse:{try parse($0,commands:commands,script:script)})
    }
}
