import Testing
@testable import GuardRuntime

struct ReferenceTests {
    // Columns independently reconstructed from this macOS pfctl binary's
    // documented PID/Process Name/TOKEN/TIMESTAMP printf formats, not the parser.
    let header="TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n"
    let own="123      pfctl                        999                      0 days 00:00:01\n"
    let foreign="456      socketfilterfw               888                      1 days 01:02:03\n"

    @Test func ownOnlyTokenTableHasSameForeignReferencesAsEmptyBaseline() throws {
        let baseline=try PFText.referenceSignature("No pf starter references held\n",excluding:nil)
        #expect(baseline.isEmpty)
        #expect(try PFText.referenceSignature(header+own,excluding:"999")==baseline)
        #expect(try PFText.referenceSignature("No pf_enabled references\n",excluding:nil)==baseline)
    }
    @Test func foreignReferenceAgesDoNotChangeIdentityButNewTokensDo() throws {
        let original=try PFText.referenceSignature(header+foreign,excluding:nil)
        let later=foreign.replacingOccurrences(of:"1 days 01:02:03",with:"1 days 01:03:04")
        #expect(try PFText.referenceSignature(header+own+later,excluding:"999")==original)
        #expect(try PFText.referenceSignature(header+foreign.replacingOccurrences(of:"888",with:"887"),excluding:nil) != original)
        #expect(try PFText.referenceSignature(header+foreign.replacingOccurrences(of:"456",with:"457"),excluding:nil) != original)
    }
    @Test func unknownReferenceDataNeverLooksAbsent() {
        for bad in ["", "unknown output", "TOKENS:\n", header,
                    header+own+own, header+own.replacingOccurrences(of:"999",with:"not-a-token"),
                    header+own.replacingOccurrences(of:"00:00:01",with:"00:99:01")] {
            reject {_ = try PFText.referenceSignature(bad,excluding:nil)}
        }
    }
    @Test func exactOwnedTokenMembershipComesFromParsedRecords() throws {
        let rows=try PFText.references(header+own+foreign)
        #expect(rows.map(\.token)==["888","999"])
        #expect(rows.first?.pid==456)
        #expect(rows.first?.name=="socketfilterfw")
    }
}
