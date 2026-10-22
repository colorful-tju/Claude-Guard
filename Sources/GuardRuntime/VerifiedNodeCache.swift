import Foundation
import Darwin

/// Used only on the controller's serial transaction queue. Cache parsed evidence,
/// never permission to skip reading the current file or validating runtime/PF.
final class VerifiedNodeCache {
    private var cached:NodeConfiguration?
    func read(readBytes:() throws -> Data,parse:(Data) throws -> NodeConfiguration) throws -> NodeConfiguration {
        let bytes=try readBytes()
        let fingerprint=hash(bytes)
        if let cached,cached.fingerprint==fingerprint {return cached}
        cached=nil
        let node=try parse(bytes)
        guard node.fingerprint==fingerprint,try readBytes()==bytes else {
            throw fail("Registered proxy config changed during parsing")
        }
        cached=node
        return node
    }
    /// Bounded descriptor read avoids FIFO blocking, symlink replacement and
    /// unchecked whole-file allocation. Ownership is checked even on cache hits.
    static func bytes(path:String,owner:uid_t) throws -> Data {
        let fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard fd>=0 else{throw fail("Registered proxy config unreadable")}
        defer{close(fd)}
        var st=stat()
        guard fstat(fd,&st)==0,(st.st_mode&S_IFMT)==S_IFREG,st.st_uid==owner,
              st.st_size>=0,st.st_size<=2_000_000 else{throw fail("Registered proxy config ownership, type or size invalid")}
        var data=Data();var buffer=[UInt8](repeating:0,count:16384)
        while true {
            let count=Darwin.read(fd,&buffer,buffer.count)
            if count<0 {if errno==EINTR {continue};throw fail("Registered proxy config read failed")}
            if count==0 {break}
            guard data.count+count<=2_000_000 else{throw fail("Registered proxy config oversized")}
            data.append(contentsOf:buffer.prefix(count))
        }
        var end=stat(),pathStat=stat()
        guard fstat(fd,&end)==0,lstat(path,&pathStat)==0,
              end.st_dev==pathStat.st_dev,end.st_ino==pathStat.st_ino,
              (pathStat.st_mode&S_IFMT)==S_IFREG,end.st_uid==owner,
              st.st_size==end.st_size,Int64(data.count)==end.st_size,
              st.st_mtimespec.tv_sec==end.st_mtimespec.tv_sec,st.st_mtimespec.tv_nsec==end.st_mtimespec.tv_nsec,
              st.st_ctimespec.tv_sec==end.st_ctimespec.tv_sec,st.st_ctimespec.tv_nsec==end.st_ctimespec.tv_nsec
        else{throw fail("Registered proxy config changed while reading")}
        return data
    }
}
