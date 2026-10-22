import Foundation
import Darwin

public struct ClaudeBuildChanged:Error,CustomStringConvertible,Sendable {
    public init(){}
    public var description:String {"Claude build changed; reinstall registration"}
}

/// Fixed identity, never a path, requirement or hash supplied by the UI.
public enum ClaudeRegistration {
    public static let appPath="/Applications/Claude.app"
    public static let requirement="identifier \"com.anthropic.claudefordesktop\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"Q6L2SF6YDW\""
    public static func verifiedHash(commands:Commands,cancelled:@escaping @Sendable ()->Bool) throws -> String {
        var before=stat()
        guard lstat(appPath,&before)==0,(before.st_mode&S_IFMT)==S_IFDIR else {
            throw fail("Claude registration: Claude.app 缺失或不是普通应用目录，请安装官方版本")
        }
        return try validate(readHash:{try codeHash(path:appPath)},verifyOfficial:{
            let result=try commands.run("/usr/bin/codesign",["--verify","--deep","--strict","--all-architectures","-R","="+requirement,appPath],timeout:20,cancelled:cancelled)
            guard result.status==0 else{throw fail("Claude registration: 官方签名核验未通过，请从官方来源重新安装 Claude")}
        },checkUnchanged:{
            var after=stat()
            guard lstat(appPath,&after)==0,(after.st_mode&S_IFMT)==S_IFDIR,
                  before.st_dev==after.st_dev,before.st_ino==after.st_ino else {
                throw fail("Claude registration: 验证期间应用已被替换，请等待更新完成后重试")
            }
            guard !cancelled() else{throw fail("Claude registration cancelled")}
        })
    }
    static func validate(readHash:()throws->String,verifyOfficial:()throws->Void,checkUnchanged:()throws->Void) throws -> String {
        let before=try readHash()
        try verifyOfficial();try checkUnchanged()
        let after=try readHash()
        guard before==after,!after.isEmpty else{throw fail("Claude registration: 验证期间构建发生变化，请等待更新完成后重试")}
        return after
    }
}
