import Foundation
import Darwin
import GuardCore
public struct PFView:Sendable { public var enabled:Bool;public var main:String;public var references:String;public var states:[ExistingState];public var canonical:String;public var labels:String }
typealias PFCommandExecution = @Sendable ([String],Int32?,@escaping ControllerCancellation)throws->CommandResult
public final class PacketFilter: PacketFiltering, @unchecked Sendable {
    public let commands:Commands
    private let root:String
    private let execute:PFCommandExecution
    public convenience init(commands:Commands,root:String=Paths.root) {
        self.init(commands:commands,root:root,execute:{args,recording,cancelled in
            try commands.run("/sbin/pfctl",args,timeout:8,cancelled:cancelled,recordingTo:recording)
        })
    }
    init(commands:Commands,root:String,execute:@escaping PFCommandExecution) {self.commands=commands;self.root=root;self.execute=execute}
    public func pf(_ args:[String]) throws -> String {
        let result=try execute(args,nil,{false})
        if args.contains("-s") || args.contains("-sr") || args.contains("-sn") || args.contains("-ss") {
            return try PFText.displayResult(result)
        }
        guard result.status==0 else{throw fail("pfctl failed (\(result.status)); required evidence unavailable")}
        return result.output
    }
    private func inventories() throws -> ([String],[String]) {
        let roots=try PFText.anchorNames(pf(["-s","Anchors"]),parent:"")
        let children = roots.contains("com.apple") ? try PFText.anchorNames(pf(["-a","com.apple","-s","Anchors"]),parent:"com.apple") : []
        return(roots,children)
    }
    private func ownPresent() throws -> Bool {try inventories().1.contains("000.local.claudesafelauncher")}
    private func emptySharingImage() throws -> String {
        let path="com.apple.internet-sharing"
        let filter=try pf(["-a",path,"-sr"]),nat=try pf(["-a",path,"-sn"])
        let names=try PFText.anchorNames(pf(["-a",path,"-s","Anchors"]),parent:path)
        guard [filter,nat].allSatisfy({$0.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty}),
              Set(names).isSubset(of:["host_v4","host_v6"]) else{throw fail("PF Internet Sharing is not empty or has unknown children; observed=\(names.prefix(16).joined(separator:","))")}
        for name in names {
            let child=path+"/"+name
            let contents=[try pf(["-a",child,"-sr"]),try pf(["-a",child,"-sn"]),try pf(["-a",child,"-s","Anchors"])]
            guard contents.allSatisfy({$0.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty}) else{
                throw fail("PF Internet Sharing is not empty; observed=\(child)")
            }
        }
        guard try PFText.anchorNames(pf(["-a",path,"-s","Anchors"]),parent:path)==names else{throw fail("PF Internet Sharing inventory changed during inspection")}
        return path+"\n"+names.joined(separator:"\n")+"\nall-filter-nat-and-leaf-bodies-empty"
    }
    private func capture(_ policy:GuardPolicy?) throws -> PFView {
        let inventory=try inventories()
        guard Set(inventory.0).isSubset(of:["com.apple","com.apple.internet-sharing"]) else{throw fail("Unknown PF root anchor; observed=\(inventory.0.prefix(16).joined(separator:",")); count=\(inventory.0.count)")}
        // macOS can retain these names after Parallels/shared networking exits.
        // Accept only positively read empty bodies, never active sharing rules.
        let sharing=try inventory.0.contains("com.apple.internet-sharing") ? emptySharingImage():nil
        let main=try pf(["-sr"]),interfaces=try pf(["-s","Interfaces","-v"])
        let parent=inventory.0.contains("com.apple") ? try pf(["-a","com.apple","-sr"]) : ""
        let parentNAT=inventory.0.contains("com.apple") ? try pf(["-a","com.apple","-sn"]) : ""
        var children:[String:PFAnchorContents]=[:];var ownRules=""
        for name in inventory.1 {
            guard ["200.AirDrop","250.ApplicationFirewall","000.local.claudesafelauncher"].contains(name) else{throw fail("Unknown PF Apple child anchor; observed=\(name)")}
            let path="com.apple/"+name
            let nat=try pf(["-a",path,"-sn"]),nested=try pf(["-a",path,"-s","Anchors"])
            if name=="000.local.claudesafelauncher" {
                // Own filter rules are checked against the durable canonical rules by view/snapshot.
                guard [nat,nested].allSatisfy({$0.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty}) else{throw fail("Own PF anchor has foreign NAT or descendants")}
                if policy != nil {ownRules=try pf(["-a",path,"-sr"])}
            } else {children[name] = .init(filter:try pf(["-a",path,"-sr"]),nat:nat,children:nested)}
        }
        try PFText.environment(main:main,siblings:inventory.1.joined(separator:"\n"),skipped:interfaces,
                               appleRules:parent,appleNAT:parentNAT,appleChildren:children,sharingEmpty:sharing != nil)
        let nat=try pf(["-sn"])
        let sharingNAT:Set<String> = sharing == nil ? []:["nat-anchor \"com.apple.internet-sharing\" all","rdr-anchor \"com.apple.internet-sharing\" all"]
        guard nat.components(separatedBy:.newlines).allSatisfy({$0.isEmpty || $0.hasPrefix("nat-anchor \"com.apple/*\"") || $0.hasPrefix("rdr-anchor \"com.apple/*\"") || $0.hasPrefix("binat-anchor \"com.apple/*\"") || sharingNAT.contains($0)}) else{throw fail("Unknown PF NAT environment")}
        let refs=try pf(["-s","References"]);let info=try pf(["-s","info"])
        guard info.hasPrefix("Status: Enabled") || info.hasPrefix("Status: Disabled") else{throw fail("Unknown PF status format")}
        let observedStates=try policy.map{try states($0)} ?? []
        let labelText=policy == nil ? "" : ((try? pf(["-a",GuardPolicy.anchor,"-s","labels"])) ?? "")
        let after=try inventories()
        guard inventory.0==after.0,inventory.1==after.1 else{throw fail("PF anchor inventory changed during inspection")}
        // This foreign-environment image is fingerprinted and journalled. Exclude
        // our own child's existence: loading/removing our rules is an expected change.
        let image=PFText.foreignImage(main:main,nat:nat,parent:parent,children:inventory.1,sharing:sharing)
        return .init(enabled:info.hasPrefix("Status: Enabled"),main:image,references:refs,states:observedStates,canonical:ownRules,labels:labelText)
    }
    public func environment() throws -> (String,String,Bool) {let v=try capture(nil);return(v.main,v.references,v.enabled)}
    public func states(_ policy:GuardPolicy) throws -> [ExistingState] {try PFText.states(pf(["-ss","-vv"]),policy:policy)}
    public func canonical() throws -> String {try ownPresent() ? pf(["-a",GuardPolicy.anchor,"-sr"]) : ""}
    public func labels() throws -> String {try ownPresent() ? pf(["-a",GuardPolicy.anchor,"-s","labels"]) : ""}
    public func view(_ policy:GuardPolicy) throws -> PFView {
        // Statistics are observational; unreadable labels do not weaken mandatory rule/state verification.
        try capture(policy)
    }
    public func prepareRules(_ policy:GuardPolicy) throws -> String {
        let file=root+"/rules.conf"
        // Generated only, no UI-supplied rule text. Atomic root-owned journal file format here is raw PF.
        let fd=open(file,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0o600);guard fd>=0 else{throw fail("Rule file create failed")}
        let h=FileHandle(fileDescriptor:fd,closeOnDealloc:true);try h.write(contentsOf:Data(policy.rules.utf8));guard fsync(fd)==0 else{throw fail("Rule file fsync failed")};try h.close()
        let dry=try pf(["-n","-v","-o","none","-a",GuardPolicy.anchor,"-f",file])
        let expected=dry.components(separatedBy:.newlines).filter{$0.hasPrefix("pass ") || $0.hasPrefix("block ")}.joined(separator:"\n")+"\n"
        guard expected.components(separatedBy:.newlines).filter({$0.hasPrefix("pass ")}).allSatisfy({$0.contains("no state")}),
              expected.components(separatedBy:.newlines).filter({!$0.isEmpty}).count==policy.rules.components(separatedBy:.newlines).filter({!$0.isEmpty}).count else{throw fail("PF dry parse omitted or changed safety rules")}
        let last = expected.split(separator:"\n").last.map(String.init) ?? ""
        let required = policy.rules.split(separator:"\n").last.map(String.init) ?? ""
        guard last == required, last.hasPrefix("block drop out quick all label ") else {
            throw fail("PF dry parse lost final unconditional outbound deny")
        }
        return expected
    }
    public func activateRules(_ policy:GuardPolicy,expected:String) throws {
        let file=root+"/rules.conf"
        guard try String(contentsOfFile:file,encoding:.utf8)==policy.rules else{throw fail("Prepared private rule file changed")}
        _=try pf(["-o","none","-a",GuardPolicy.anchor,"-f",file])
        guard try canonical()==expected else{throw fail("Loaded PF rules differ from durable canonical rules")}
    }
    public func enable(cancelled:@escaping @Sendable ()->Bool={false}) throws -> String {
        // Persist pfctl output before interpreting its token; crash recovery reads the same private file.
        let path=root+"/enable-result.txt"
        let fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0o600);guard fd>=0 else{throw fail("Previous PF enable transaction requires recovery")}
        defer{close(fd)}
        // The output marker is durable before interpreting the result, including an ambiguous timeout/cancellation.
        // The shared runner accounts for the worker and its complete output lifetime before OFF can proceed.
        do {
            let result=try execute(["-E"],fd,cancelled)
            guard fsync(fd)==0 else{throw fail("PF token output fsync failed")}
            guard result.status==0 else{throw fail("PF enable failed; transaction retained")}
        } catch {
            let original=error
            guard fsync(fd)==0 else{throw fail("PF enable outcome and token persistence uncertain; transaction retained")}
            throw original
        }
        return try PFText.token(String(contentsOfFile:path,encoding:.utf8))
    }
    public func recoveredToken() throws -> String {try PFText.token(String(contentsOfFile:root+"/enable-result.txt",encoding:.utf8))}
    public func referencePresent(_ token:String) throws -> Bool {
        guard UInt64(token) != nil else{throw fail("Invalid owned PF reference token")}
        return try PFText.references(pf(["-s","References"])).contains{$0.token==token}
    }
    public func foreignReferences(_ token:String?) throws -> String {
        try PFText.referenceSignature(pf(["-s","References"]),excluding:token)
    }
    public func removeOwnRules() throws {_=try pf(["-a",GuardPolicy.anchor,"-F","rules"]);guard try canonical().trimmingCharacters(in:.whitespacesAndNewlines).isEmpty else{throw fail("Own anchor still has rules")}}
    public func release(_ token:String) throws {guard UInt64(token) != nil else{throw fail("Invalid owned token")};_=try pf(["-X",token]);guard try !referencePresent(token) else{throw fail("Owned token remains")}}
}
