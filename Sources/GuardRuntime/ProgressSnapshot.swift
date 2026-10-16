import Foundation
/// Read-only progress channel. It never exposes mutable Controller status or a safety verdict.
public final class ProgressSnapshot:@unchecked Sendable {
    private let lock=NSLock()
    private var message="等待助手开始处理",report=""
    public init(){}
    public func update(message:String,report:String){lock.lock();defer{lock.unlock()};self.message=String(message.prefix(4096));self.report=String(report.suffix(32768))}
    public func read()->Status {
        lock.lock();defer{lock.unlock()}
        var value=Status();value.phase="progressOnly";value.message=message;value.report=report
        return value
    }
}
