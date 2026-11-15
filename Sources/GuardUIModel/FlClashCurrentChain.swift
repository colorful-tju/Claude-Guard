import Foundation
import Darwin
import CryptoKit
import GuardRuntime

/// Persisted UI selection is a hint. Never grants provider confirmation or proves Core routing.
public struct FlClashCurrentChain:Sendable {
    public let profileID:String
    public let profileLabel:String
    public let configurationPath:String
    public let node:NodeConfiguration
    public let entry:ChainEntry

    private struct Selection:Equatable {
        let id:String;let label:String;let map:[String:String]
    }
    private static func bytes(_ url:URL,limit:Int) throws -> Data {
        let fd=open(url.path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK)
        guard fd>=0 else{throw fail("FLClash 当前链路：本地文件不可读取，请确认 FLClash 已保存配置。")}
        let file=FileHandle(fileDescriptor:fd,closeOnDealloc:true)
        var info=stat()
        guard fstat(fd,&info)==0,info.st_uid==getuid(),info.st_mode&S_IFMT==S_IFREG,
              info.st_size>=0,info.st_size<=limit else{throw fail("FLClash 当前链路：文件类型、所有者或大小不符合要求。")}
        let data=try file.read(upToCount:limit+1) ?? Data()
        guard data.count<=limit else{throw fail("FLClash 当前链路：文件过大。")}
        return data
    }
    private static func selection(root:URL,preferencesURL:URL) throws -> Selection {
        let data=try bytes(preferencesURL,limit:2_000_000)
        guard let plist=try? PropertyListSerialization.propertyList(from:data,format:nil) as? [String:Any],
              let raw=plist["flutter.config"] as? String,
              let json=raw.data(using:.utf8),let config=try? JSONSerialization.jsonObject(with:json) as? [String:Any],
              let number=config["currentProfileId"] as? NSNumber else {
            throw fail("FLClash 当前链路：未找到当前配置记录，请先在 FLClash 选择并应用配置。")
        }
        // NSNumber.stringValue preserves 64-bit profile IDs; never convert through Double.
        let id=number.stringValue
        guard let integer=Int64(id),integer>0,String(integer)==id else{throw fail("FLClash 当前链路：当前配置 ID 无效。")}
        let database=root.appendingPathComponent("database.sqlite")
        _=try bytes(database,limit:16_000_000)
        let result=try Commands().run("/usr/bin/sqlite3",["-readonly","-json",database.path,
            "SELECT substr(label,1,80) AS label, substr(selected_map,1,262145) AS selection FROM profiles WHERE id=\(id) LIMIT 2;"],timeout:3)
        struct Row:Decodable {let label:String;let selection:String}
        guard result.status==0,let rows=try? JSONDecoder().decode([Row].self,from:Data(result.output.utf8)),rows.count==1,
              let row=rows.first,row.selection.utf8.count<=262144,
              let map=try? JSONDecoder().decode([String:String].self,from:Data(row.selection.utf8)),map.count<=1024,
              map.allSatisfy({$0.key.utf8.count<=512 && $0.value.utf8.count<=512}) else {
            throw fail("FLClash 当前链路：当前订阅的选择记录缺失或格式不支持；请在 FLClash 重新选择前置节点。")
        }
        let label=String(row.label.unicodeScalars.filter{!CharacterSet.controlCharacters.contains($0)})
        return .init(id:id,label:label,map:map)
    }
    public static func resolve(chain:ChainConfiguration,selection:[String:String]) throws -> ChainEntry {
        var name=chain.dialer,seen=Set<String>()
        for _ in 0..<9 {
            guard seen.insert(name).inserted else{break}
            if let entry=chain.entries.first(where:{$0.name==name}) {return entry}
            guard let members=chain.groups?[name],let selected=selection[name],members.contains(selected) else{break}
            name=selected
        }
        throw fail("FLClash 当前链路：保存的前置选择无法对应生成配置中的 TCP 节点。请确认使用手动选择组并重新应用拓展脚本；不会默认选择其他节点。")
    }
    public static func read(root:URL=FlClashCatalog.defaultRoot,
                            preferencesURL:URL=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Preferences/com.follow.clash.plist"),
                            script:String=Bundle.main.resourceURL?.appendingPathComponent("read-node.rb").path ?? "") throws -> Self {
        var info=stat()
        guard lstat(root.path,&info)==0,info.st_uid==getuid(),info.st_mode&S_IFMT==S_IFDIR else{throw fail("未找到可读取的 FLClash 配置目录。")}
        let first=try selection(root:root,preferencesURL:preferencesURL)
        let generated=root.appendingPathComponent("config.yaml")
        let node=try ProxyConfiguration.candidate(path:generated.path,uid:getuid(),commands:Commands(),script:script)
        guard let chain=node.chain else{throw fail("FLClash 当前生成配置没有链式 HTTP ISP 落地；请先在 FLClash 应用链式拓展脚本。直连配置可使用配置列表登记。")}
        let entry=try resolve(chain:chain,selection:first.map)
        let after=try selection(root:root,preferencesURL:preferencesURL)
        let fingerprint=SHA256.hash(data:try bytes(generated,limit:2_000_000)).map{String(format:"%02x",$0)}.joined()
        guard first==after,node.fingerprint==fingerprint else{throw fail("FLClash 配置或节点在读取期间改变，请待稳定后重新读取。")}
        return .init(profileID:first.id,profileLabel:first.label,configurationPath:generated.path,node:node,entry:entry)
    }
}
