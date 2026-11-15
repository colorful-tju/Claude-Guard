import Foundation
/// Existing PF states bypass new filter rules. Only positively parsed TCP states
/// may coexist with UDP-only protection; never flush another application's state.
public enum UDPStateEvidence {
    public static func validate(_ text:String) throws {
        var header=false
        for row in text.components(separatedBy:.newlines) where !row.trimmingCharacters(in:.whitespaces).isEmpty {
            let s=row.trimmingCharacters(in:.whitespaces)
            if row.first?.isWhitespace == true {
                guard header,["age ","expires ","id:","[lo="].contains(where:s.hasPrefix) else{throw fail("UDP protection: unknown PF state metadata")}
            } else {
                let f=s.split(whereSeparator:{$0.isWhitespace})
                guard f.count==6,f[1]=="tcp",["->","<-"].contains(f[3]),f[5].contains(":") else {
                    throw fail("UDP protection: existing UDP/non-TCP or unknown PF state; close UDP applications and retry; states were not cleared")
                }
                header=true
            }
        }
    }
}
