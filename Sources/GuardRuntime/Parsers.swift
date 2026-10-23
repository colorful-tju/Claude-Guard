import Foundation
import GuardCore
public struct PFAnchorContents:Sendable {
    public var filter:String;public var nat:String;public var children:String
    public init(filter:String,nat:String,children:String){self.filter=filter;self.nat=nat;self.children=children}
}
public enum PFText {
    public static func referenceSignature(_ text:String,excluding token:String?) throws -> String {
        if let token,UInt64(token)==nil{throw fail("Invalid owned PF reference token")}
        let rows=try references(text).filter{$0.token != token}
        guard !rows.isEmpty else{return ""}
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
        return String(decoding:try encoder.encode(rows),as:UTF8.self)
    }
    public static func references(_ text:String) throws -> [PFReference] {
        let lines=text.components(separatedBy:.newlines).filter{!$0.trimmingCharacters(in:.whitespaces).isEmpty}
        if lines.count==1,["No pf starter references held","No pf_enabled references"].contains(lines[0].trimmingCharacters(in:.whitespaces)){return []}
        guard lines.count>=3,lines[0]=="TOKENS:",
              lines[1].split(whereSeparator:{$0.isWhitespace}).map(String.init)==["PID","Process","Name","TOKEN","TIMESTAMP"] else{throw fail("Unknown PF reference format")}
        var rows:[PFReference]=[];var tokens=Set<String>()
        for line in lines.dropFirst(2) {
            let bytes=Array(line.utf8)
            // pfctl's fixed minimum widths: PID 8, process name 28, token 24.
            guard bytes.count>63,bytes.allSatisfy({$0>=32 && $0<127}),bytes[8]==32,bytes[37]==32,bytes[62]==32 else{throw fail("Unknown PF reference row layout")}
            func field(_ range:Range<Int>)->String {String(decoding:bytes[range],as:UTF8.self).trimmingCharacters(in:.whitespaces)}
            let pidText=field(0..<8),name=field(9..<37),tokenText=field(38..<62),stamp=field(63..<bytes.count)
            guard !pidText.isEmpty,pidText.allSatisfy(\.isNumber),let pid=Int32(pidText),pid>0,
                  !name.isEmpty,!tokenText.isEmpty,tokenText.allSatisfy(\.isNumber),let token=UInt64(tokenText),
                  stamp.range(of:#"^[0-9]+ days [0-9]{2}:[0-9]{2}:[0-9]{2}$"#,options:.regularExpression) != nil else{throw fail("Unknown PF reference identity/timestamp")}
            let clock=stamp.split(separator:" ").last!.split(separator:":").compactMap{Int($0)}
            guard clock.count==3,clock[0]<24,clock[1]<60,clock[2]<60,tokens.insert(String(token)).inserted else{throw fail("Ambiguous PF reference identity")}
            rows.append(.init(pid:pid,name:name,token:String(token)))
        }
        return rows.sorted{$0.token<$1.token}
    }
    public static func foreignImage(main:String,nat:String,parent:String,children:[String],sharing:String?=nil) -> String {
        let foreign=children.filter{$0 != "000.local.claudesafelauncher"}.sorted().joined(separator:"\n")
        return main+"\n-- NAT --\n"+nat+"\n-- Apple parent --\n"+parent+"\n-- Apple children --\n"+foreign+(sharing.map{"\n-- Empty sharing tree --\n"+$0} ?? "")
    }
    public static func anchorNames(_ text:String,parent:String) throws -> [String] {
        var names:[String]=[]
        for row in text.components(separatedBy:.newlines) {
            let raw=row.trimmingCharacters(in:.whitespaces);if raw.isEmpty{continue}
            let prefix=parent+"/"
            let name = !parent.isEmpty && raw.hasPrefix(prefix) ? String(raw.dropFirst(prefix.count)) : raw
            guard !name.isEmpty,name != ".",name != "..",name.utf8.allSatisfy({
                (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45,46,95].contains($0)
            }),!names.contains(name) else{throw fail("Unknown/ambiguous PF anchor inventory")}
            names.append(name)
        }
        return names.sorted()
    }
    public static func displayResult(_ result:CommandResult) throws -> String {
        let diagnostics=result.error.components(separatedBy:.newlines).map{$0.trimmingCharacters(in:.whitespaces)}.filter{!$0.isEmpty}
        guard result.status==0,diagnostics.allSatisfy({$0=="No ALTQ support in kernel" || $0=="ALTQ related functions disabled"}),
              !result.output.components(separatedBy:.newlines).contains(where:{$0.trimmingCharacters(in:.whitespaces).hasPrefix("pfctl:")}) else{
            throw fail("PF display failed or reported an error; required evidence unavailable")
        }
        return result.output
    }
    public static func token(_ text: String) throws -> String {
        let rows = text.components(separatedBy: .newlines).filter { $0.trimmingCharacters(in:.whitespaces).hasPrefix("Token") }
        guard rows.count == 1, let value = rows[0].split(separator:":").last?.trimmingCharacters(in:.whitespaces),
              UInt64(value) != nil else { throw GuardFailure.rejected("PF enable token missing or ambiguous") }
        return value
    }
    public static func counter(_ text: String, label: String) throws -> UInt64 {
        let rows = text.components(separatedBy:.newlines).map { $0.split(whereSeparator: { $0.isWhitespace }).map(String.init) }.filter { $0.first == label }
        guard rows.count == 1, rows[0].count == 8, rows[0].dropFirst().allSatisfy({ UInt64($0) != nil }),
              let packets = UInt64(rows[0][2]) else { throw GuardFailure.rejected("Unsupported/missing PF label counters") }
        return packets
    }
    public static func environment(main: String, siblings: String, skipped: String,
                                   appleRules:String="",appleNAT:String="",appleChildren:[String:PFAnchorContents]=[:],sharingEmpty:Bool=false) throws {
        let lines = main.components(separatedBy:.newlines).map { $0.trimmingCharacters(in:.whitespaces) }.filter { !$0.isEmpty }
        let names=try anchorNames(siblings,parent:"com.apple")
        let placeholders:Set<String>=["200.AirDrop","250.ApplicationFirewall"]
        let own="000.local.claudesafelauncher"
        let parentLines=appleRules.components(separatedBy:.newlines).map{$0.trimmingCharacters(in:.whitespaces)}.filter{!$0.isEmpty}
        let permittedParent:Set<String>=["anchor \"200.AirDrop/*\" all","anchor \"250.ApplicationFirewall/*\" all"]
        let needed=Set(names).intersection(placeholders)
        let sharingMain:Set<String> = sharingEmpty ? ["anchor \"com.apple.internet-sharing\" all","scrub-anchor \"com.apple.internet-sharing\" all fragment reassemble"]:[]
        guard lines.filter({ $0 == "anchor \"com.apple/*\" all" }).count == 1,
              lines.allSatisfy({ $0 == "anchor \"com.apple/*\" all" || $0.hasPrefix("scrub-anchor \"com.apple/*\" ") || sharingMain.contains($0) }),
              Set(names).isSubset(of:placeholders.union([own])),
              Set(appleChildren.keys)==needed,
              parentLines.allSatisfy({permittedParent.contains($0)}),Set(parentLines).count==parentLines.count,
              appleNAT.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,
              appleChildren.values.allSatisfy({[$0.filter,$0.nat,$0.children].allSatisfy({$0.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty})}),
              skipped.components(separatedBy:.newlines).allSatisfy({ !$0.contains("skip") || $0.trimmingCharacters(in:.whitespaces).hasPrefix("lo0 ") }) else {
            throw GuardFailure.unsupported("PF has conflicting/unknown rules, foreign Apple anchors, or non-loopback skip")
        }
    }
    public static func states(_ text: String, policy: GuardPolicy) throws -> [ExistingState] {
        guard !text.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else { return [] }
        // Version-specific PF state metadata must be explicit; never infer a floating interface.
        let rows = text.components(separatedBy:.newlines)
        var result: [ExistingState] = []; var index = 0
        while index < rows.count {
            if rows[index].trimmingCharacters(in:.whitespaces).isEmpty { index += 1; continue }
            let head = rows[index].split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard head.count == 6, head[0] == policy.physical.name, head[1] == "tcp",
                  head[3] == "->", head[5] == "ESTABLISHED:ESTABLISHED" else {
                throw GuardFailure.unsupported("Unrecognized, floating, NAT or unsupported PF state header")
            }
            func address(_ token: String) throws -> (String, UInt16) {
                let parts = token.split(separator:":")
                guard parts.count == 2, IPv4.octets(String(parts[0])) != nil, let port = UInt16(parts[1]), port > 0 else {
                    throw GuardFailure.rejected("Invalid PF state tuple")
                }
                return (String(parts[0]),port)
            }
            let local = try address(head[2]); let remote = try address(head[4])
            index += 1; var identifier: String?
            while index < rows.count && (rows[index].first?.isWhitespace ?? true) {
                let row = rows[index].trimmingCharacters(in:.whitespaces)
                if row.hasPrefix("id:") {
                    let fields = row.split(whereSeparator: { $0.isWhitespace })
                    guard fields.count >= 4, fields[2] == "creatorid:", fields[1].allSatisfy({ $0.isHexDigit }), fields[3].allSatisfy({ $0.isHexDigit }) else {
                        throw GuardFailure.unsupported("Invalid PF state ID metadata")
                    }
                    identifier = String(fields[1]) + ":" + String(fields[3])
                } else if !row.isEmpty && !row.hasPrefix("age ") && !row.hasPrefix("expires ") && !row.hasPrefix("[lo=") {
                    throw GuardFailure.unsupported("Unknown PF state metadata")
                }
                index += 1
            }
            guard let id = identifier else { throw GuardFailure.unsupported("PF state ID missing") }
            result.append(.init(id:id,boundInterface:head[0],localAddress:local.0,remoteAddress:remote.0,localPort:local.1,remotePort:remote.1))
        }
        try StateClassifier.validate(result, policy:policy)
        return result.sorted { $0.id < $1.id }
    }
}
public struct PFReference:Sendable,Codable {public var pid:Int32;public var name:String;public var token:String}
public struct NodeConfiguration: Codable, Sendable {
    public var name: String; public var type: String; public var server: String; public var port: UInt16
    public var fingerprint: String; public var numeric: Bool; public var tunDevice: String
    public static func parse(_ data: Data) throws -> NodeConfiguration {
        let n = try JSONDecoder().decode(NodeConfiguration.self,from:data)
        guard !n.name.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty, n.type == "http", n.numeric, IPv4.isPublic(n.server), n.port > 0,
              !n.fingerprint.isEmpty else { throw GuardFailure.unsupported("Only a verified numeric HTTP node is supported") }
        return n
    }
}
