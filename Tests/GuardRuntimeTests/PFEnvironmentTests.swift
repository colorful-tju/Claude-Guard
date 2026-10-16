import Foundation
import Testing
import GuardCore
@testable import GuardRuntime

struct PFEnvironmentTests {
    let main = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
    let parent = "anchor \"200.AirDrop/*\" all\nanchor \"250.ApplicationFirewall/*\" all\n"
    let siblings = "  com.apple/200.AirDrop\n  com.apple/250.ApplicationFirewall\n"
    var emptyChildren: [String:PFAnchorContents] {
        ["200.AirDrop":.init(filter:"",nat:"",children:""),
         "250.ApplicationFirewall":.init(filter:"",nat:"",children:"")]
    }

    @Test func observedApplePlaceholdersRequirePositiveEmptyBodyEvidence() throws {
        try PFText.environment(main:main,siblings:siblings,skipped:"ALL\nen0\nlo0\n",
                               appleRules:parent,appleNAT:"",appleChildren:emptyChildren)
        reject {try PFText.environment(main:main,siblings:siblings,skipped:"",
                                       appleRules:parent,appleNAT:"",appleChildren:[:])}
        var missing=emptyChildren;missing.removeValue(forKey:"250.ApplicationFirewall")
        reject {try PFText.environment(main:main,siblings:siblings,skipped:"",
                                       appleRules:parent,appleNAT:"",appleChildren:missing)}
    }

    @Test func populatedOrNestedApplePlaceholderIsNeverAccepted() throws {
        for body in [PFAnchorContents(filter:"pass out quick all",nat:"",children:""),
                     .init(filter:"",nat:"nat on en0 from any to any -> (en0)",children:""),
                     .init(filter:"",nat:"",children:"com.apple/200.AirDrop/foreign")] {
            var evidence=emptyChildren;evidence["200.AirDrop"]=body
            reject {try PFText.environment(main:main,siblings:siblings,skipped:"",
                                           appleRules:parent,appleNAT:"",appleChildren:evidence)}
        }
        reject {try PFText.environment(main:main,siblings:siblings,skipped:"",
                                       appleRules:parent+"pass out quick all\n",appleNAT:"",appleChildren:emptyChildren)}
        reject {try PFText.environment(main:main,siblings:siblings,skipped:"",
                                       appleRules:parent,appleNAT:"rdr pass on en0 all",appleChildren:emptyChildren)}
        reject {try PFText.environment(main:main,siblings:siblings+"com.apple/200.AirDropEvil\n",skipped:"",
                                       appleRules:parent,appleNAT:"",appleChildren:emptyChildren)}
        reject {try PFText.environment(main:main,siblings:siblings,skipped:"en0 (skip)",
                                       appleRules:parent,appleNAT:"",appleChildren:emptyChildren)}
    }

    @Test func exactOwnAnchorPathAcceptedButDescendantAndAliasRejected() throws {
        try PFText.environment(main:main,siblings:siblings+GuardPolicy.anchor+"\n",skipped:"",
                               appleRules:parent,appleNAT:"",appleChildren:emptyChildren)
        for extra in [GuardPolicy.anchor+"/child", "com.apple/000.local.claudesafelauncher.other"] {
            reject {try PFText.environment(main:main,siblings:siblings+extra+"\n",skipped:"",
                                           appleRules:parent,appleNAT:"",appleChildren:emptyChildren)}
        }
    }

    @Test func anchorInventoryNormalizesOnlyImmediateNamesAndRejectsAmbiguity() throws {
        #expect(try PFText.anchorNames(siblings,parent:"com.apple") == ["200.AirDrop","250.ApplicationFirewall"])
        #expect(try PFText.anchorNames("200.AirDrop\n250.ApplicationFirewall",parent:"com.apple") == ["200.AirDrop","250.ApplicationFirewall"])
        #expect(try PFText.anchorNames("com.apple\n",parent:"") == ["com.apple"])
        for invalid in ["200.AirDrop\ncom.apple/200.AirDrop", "com.apple/200.AirDrop/child",
                        "pfctl: DIOCGETRULES: Invalid argument", "../200.AirDrop", "foreign/200.AirDrop"] {
            reject {_ = try PFText.anchorNames(invalid,parent:"com.apple")}
        }
    }

    @Test func displayReadRejectsZeroExitErrorsInsteadOfClaimingEmptyRules() throws {
        let benign="No ALTQ support in kernel\nALTQ related functions disabled\n"
        #expect(try PFText.displayResult(.init(output:"",error:benign,status:0)) == "")
        for result in [CommandResult(output:"",error:benign+"pfctl: DIOCGETRULES: Invalid argument\n",status:0),
                       .init(output:"",error:"Anchor 'com.apple/missing' not found.\n",status:0),
                       .init(output:"pfctl: DIOCGETRULES: Invalid argument\n",error:benign,status:0),
                       .init(output:"",error:benign,status:1),
                       .init(output:"",error:"Unknown warning\n",status:0)] {
            reject {_ = try PFText.displayResult(result)}
        }
    }

    @Test func foreignImageIsStableAcrossOwnAnchorLifecycleButTracksForeignInputs() {
        let names=["200.AirDrop","250.ApplicationFirewall"]
        let nat="nat-anchor \"com.apple/*\" all\n"
        let before=PFText.foreignImage(main:main,nat:nat,parent:parent,children:names)
        let active=PFText.foreignImage(main:main,nat:nat,parent:parent,children:["000.local.claudesafelauncher"]+names)
        #expect(before==active)
        #expect(active==PFText.foreignImage(main:main,nat:nat,parent:parent,children:names))
        #expect(before != PFText.foreignImage(main:main+"changed",nat:nat,parent:parent,children:names))
        #expect(before != PFText.foreignImage(main:main,nat:nat+"changed",parent:parent,children:names))
        #expect(before != PFText.foreignImage(main:main,nat:nat,parent:parent+"changed",children:names))
        #expect(before != PFText.foreignImage(main:main,nat:nat,parent:parent,children:["200.AirDrop"]))
    }
}
