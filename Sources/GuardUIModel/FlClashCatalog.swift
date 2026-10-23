import Foundation
import Darwin
import GuardRuntime

public struct FlClashConfiguration:Identifiable,Sendable {
    public var id:String {path}
    public let path:String
    public let name:String
    public let modifiedAt:Date
    public let generated:Bool
    public init(path:String,name:String,modifiedAt:Date,generated:Bool) {self.path=path;self.name=name;self.modifiedAt=modifiedAt;self.generated=generated}
    public var filename:String {URL(fileURLWithPath:path).lastPathComponent}
}

/// An unprivileged, read-only picker. Discovery never proves which profile the core loaded.
public struct FlClashCatalog:Sendable {
    public let entries:[FlClashConfiguration]
    public let warning:String
    public init(entries:[FlClashConfiguration],warning:String="") {self.entries=entries;self.warning=warning}
    public static var defaultRoot:URL {FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/com.follow.clash")}
    private static func metadata(_ url:URL,type:mode_t,maxSize:Int64=Int64.max)->stat? {
        var value=stat()
        guard lstat(url.path,&value)==0,(value.st_mode&S_IFMT)==type,value.st_uid==getuid(),value.st_size>=0,value.st_size<=maxSize else{return nil}
        return value
    }
    public static func discover(root:URL=defaultRoot) throws -> FlClashCatalog {
        guard metadata(root,type:S_IFDIR) != nil else{throw fail("未找到可读取的 FLClash 配置目录；请先在 FLClash 导入配置，或使用手动选择文件。")}
        var names:[String:String]=[:],warnings:[String]=[]
        let database=root.appendingPathComponent("database.sqlite")
        if metadata(database,type:S_IFREG,maxSize:16_000_000) != nil {
            // Only display labels. Do not read subscription URLs, selected_map, passwords or YAML.
            let sql="SELECT CAST(id AS TEXT) AS id, substr(label,1,80) AS label FROM profiles LIMIT 501;"
            do {
                let result=try Commands().run("/usr/bin/sqlite3",["-readonly","-json",database.path,sql],timeout:3)
                struct Row:Decodable {let id:String;let label:String}
                guard result.status==0,let rows=try? JSONDecoder().decode([Row].self,from:Data(result.output.utf8)) else{throw fail("metadata unavailable")}
                for row in rows {
                    let label=row.label.unicodeScalars.filter{!CharacterSet.controlCharacters.contains($0)}.map(String.init).joined().trimmingCharacters(in:.whitespacesAndNewlines)
                    if !label.isEmpty {names[row.id]=label}
                }
                if rows.count>500 {warnings.append("订阅名称超过读取上限，部分项目显示文件名。")}
            }catch {warnings.append("订阅名称暂不可读取，已按文件名列出；可刷新或手动选择文件。")}
        } else {warnings.append("未读取到订阅名称，已按文件名列出。")}
        var entries:[FlClashConfiguration]=[]
        let profiles=root.appendingPathComponent("profiles")
        if metadata(profiles,type:S_IFDIR) != nil {
            let files: [URL]
            do {files=try FileManager.default.contentsOfDirectory(at:profiles,includingPropertiesForKeys:nil).sorted{$0.lastPathComponent<$1.lastPathComponent}}
            catch {throw fail("FLClash 配置目录无法列出；请检查文件访问权限，或手动选择文件。")}
            for file in files where ["yaml","yml"].contains(file.pathExtension.lowercased()) {
                guard let value=metadata(file,type:S_IFREG,maxSize:2_000_000) else{continue}
                let name=names[file.deletingPathExtension().lastPathComponent] ?? file.lastPathComponent
                entries.append(.init(path:profiles.appendingPathComponent(file.lastPathComponent).path,name:name,modifiedAt:Date(timeIntervalSince1970:TimeInterval(value.st_mtimespec.tv_sec)),generated:false))
                if entries.count>=500 {warnings.append("最多显示 500 个配置；未找到时请手动选择文件。");break}
            }
        }
        entries.sort{if $0.name==$1.name {return $0.path<$1.path};return $0.name.localizedStandardCompare($1.name) == .orderedAscending}
        let generated=root.appendingPathComponent("config.yaml")
        if let value=metadata(generated,type:S_IFREG,maxSize:2_000_000) {
            entries.append(.init(path:generated.path,name:"生成配置（不保证是当前订阅）",modifiedAt:Date(timeIntervalSince1970:TimeInterval(value.st_mtimespec.tv_sec)),generated:true))
        }
        return .init(entries:entries,warning:warnings.joined(separator:"\n"))
    }
}
