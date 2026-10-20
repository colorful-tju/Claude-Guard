import Foundation
import Testing
import Darwin
@testable import GuardRuntime

struct InventoryTests {
    @Test func advisoryPartialReadDoesNotRevokeKernelProtectionOrClaimAbsence() throws {
        var status=Status();status.phase="armed";status.verified=true;status.claude=true
        try status.applyPreview(.init(records:[],issues:["transient"]),uid:501,allowPartial:true)
        #expect(status.verified && status.claude)
        #expect(!status.processInventoryComplete)
    }

    @Test func realInventoryRetainsOwnReadableProcessAndRejectsAnyCollectedIssue() throws {
        let inventory=NativeProcesses.inventory()
        #expect(inventory.records.contains{$0.pid==getpid()})
        if inventory.complete { _ = try inventory.requireComplete() }
        else { reject { _ = try inventory.requireComplete() } }
    }
    @Test func incompletePreviewPreservesConfigurationButCannotAuthorizeLaunch() throws {
        var status=Status();status.gateway="1.1.1.1:5376";status.fingerprint="configuration-proof"
        let inventory=ProcessInventory(records:[],issues:["pid=123 stage=path errno=1"])
        try status.applyPreview(inventory,uid:501,allowPartial:true)
        #expect(status.gateway == "1.1.1.1:5376")
        #expect(status.fingerprint == "configuration-proof")
        #expect(!status.processInventoryComplete)
        #expect(status.processWarning.contains("pid=123"))
        #expect(!status.verified)
        reject { _ = try inventory.requireComplete() }
    }
    @Test func completeInventoryCanShowConfirmedAbsenceWithoutVerifyingNetwork() throws {
        var status=Status()
        let inventory=ProcessInventory(records:[],issues:[])
        try status.applyPreview(inventory,uid:501,allowPartial:true)
        #expect(status.processInventoryComplete)
        #expect(!status.flclash && !status.claude && !status.verified)
        #expect(try inventory.requireComplete().isEmpty)
    }
    @Test func observedClaudeIsReportedEvenWhenOtherProcessesAreUnreadable() throws {
        let claude=ProcessRecord(pid:42,ppid:1,uid:501,started:123,path:"/Applications/Claude.app/Contents/MacOS/Claude",name:"Claude")
        var status=Status()
        try status.applyPreview(.init(records:[claude],issues:["pid=99 unreadable"]),uid:501,allowPartial:true)
        #expect(status.claude)
        #expect(!status.processInventoryComplete)
    }
    @Test func activeInventoryIsCheckedBeforeAnyPreviewMutation() {
        var status=Status();status.phase="armed";status.verified=true;status.flclash=true
        let partial=ProcessInventory(records:[],issues:["pid=99 unreadable"])
        reject { try status.applyPreview(partial,uid:501,allowPartial:false) }
        #expect(status.flclash && status.verified)
        #expect(status.phase == "armed")
        // Controller handles this rejection by stopping the active session; it never
        // returns a successful armed reply based on this partial observation.
    }
}
