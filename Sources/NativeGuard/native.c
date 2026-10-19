#include "NativeGuard.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>
#include <limits.h>
#include <mach/vm_prot.h>
static int confirmed_inactive(int32_t pid) {
    struct kinfo_proc info={0};size_t size=sizeof(info);
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,pid};
    if(sysctl(mib,4,&info,&size,NULL,0)!=0) return 0;
    if(size==0) return CSG_PROCESS_GONE;
    if(size==sizeof(info) && info.kp_proc.p_pid==pid && info.kp_proc.p_stat==SZOMB) return CSG_PROCESS_ZOMBIE;
    return 0;
}
static int confirmed_zombie(int32_t pid) { return confirmed_inactive(pid)==CSG_PROCESS_ZOMBIE; }
/* A deleted text vnode can fail proc_pidpath while VM retains its kernel path.
 * Never use argv/ps strings, and never turn a path error into process absence.
 * Require one unique unlinked executable vnode, a matching kernel process name,
 * a complete bounded walk, and stable BSD identity before accepting the path. */
static int deleted_executable_path(int32_t pid,const struct proc_bsdinfo *before,char *path,size_t capacity) {
    uint64_t address=0,inode=0;uint32_t device=0;int found=0,complete=0;
    char candidate[4096]={0};
    for(int i=0;i<1024;i++) {
        struct proc_regionwithpathinfo region={0};errno=0;
        int n=proc_pidinfo(pid,PROC_PIDREGIONPATHINFO,address,&region,sizeof(region));
        if(n!=sizeof(region)){complete=n==0 && errno==EINVAL;break;}
        const struct vinfo_stat *v=&region.prp_vip.vip_vi.vi_stat;
        if((region.prp_prinfo.pri_protection&VM_PROT_EXECUTE) &&
           (v->vst_mode&S_IFMT)==S_IFREG && v->vst_nlink==0) {
            const char *p=region.prp_vip.vip_path;
            size_t length=strnlen(p,sizeof(region.prp_vip.vip_path));
            if(length==0 || length>=sizeof(region.prp_vip.vip_path) || p[0]!='/' || length>=capacity)return 0;
            if(found && (inode!=v->vst_ino || device!=v->vst_dev || strcmp(candidate,p)))return 0;
            inode=v->vst_ino;device=v->vst_dev;strlcpy(candidate,p,sizeof(candidate));found=1;
        }
        uint64_t start=region.prp_prinfo.pri_address,size=region.prp_prinfo.pri_size;
        if(!size || start>UINT64_MAX-size || start+size<=address)return 0;
        address=start+size;
    }
    if(!complete || !found)return 0;
    const char *base=strrchr(candidate,'/');if(!base || !base[1])return 0;base++;
    const char *name=before->pbi_name[0]?before->pbi_name:before->pbi_comm;
    size_t limit=before->pbi_name[0]?sizeof(before->pbi_name):sizeof(before->pbi_comm);
    size_t length=strnlen(name,limit);
    if(!length || length==limit || strncmp(base,name,length) || (length<limit-1 && base[length]))return 0;
    struct proc_bsdinfo after={0};
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&after,sizeof(after))!=sizeof(after) || after.pbi_status==SZOMB ||
       after.pbi_pid!=before->pbi_pid || after.pbi_uid!=before->pbi_uid || after.pbi_ppid!=before->pbi_ppid ||
       after.pbi_start_tvsec!=before->pbi_start_tvsec || after.pbi_start_tvusec!=before->pbi_start_tvusec ||
       memcmp(after.pbi_name,before->pbi_name,sizeof(after.pbi_name)) || memcmp(after.pbi_comm,before->pbi_comm,sizeof(after.pbi_comm)))return 0;
    strlcpy(path,candidate,capacity);return 1;
}
int csg_process(int32_t pid, CSGProcess *out) {
    memset(out,0,sizeof(*out));
    struct proc_bsdinfo b;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof(b)) != sizeof(b)) {
        int error=errno;
        /* ESRCH alone does not prove disappearance: macOS libproc returns it for zombies. */
        if(error==ESRCH || error==ENOENT) {int inactive=confirmed_inactive(pid);if(inactive) return inactive;}
        errno=error;return -1;
    }
    if(b.pbi_status==SZOMB) return CSG_PROCESS_ZOMBIE;
    out->pid=pid; out->ppid=b.pbi_ppid; out->uid=b.pbi_uid; out->status=b.pbi_status;
    out->started=b.pbi_start_tvsec*1000000+b.pbi_start_tvusec;
    strlcpy(out->name,b.pbi_name,sizeof(out->name));
    if (proc_pidpath(pid,out->path,sizeof(out->path)) <= 0) {
        int error=errno;
        if(error==ESRCH || error==ENOENT) {int inactive=confirmed_inactive(pid);if(inactive) return inactive;}
        if(error==ENOENT && deleted_executable_path(pid,&b,out->path,sizeof(out->path)))return 0;
        errno=error;return -2;
    }
    return 0;
}
int csg_pids(int32_t *pids, int capacity) { return proc_listallpids(pids,capacity*sizeof(int32_t)); }
int csg_sockets(int32_t pid, CSGSocket *out, int capacity) {
    int bytes=proc_pidinfo(pid,PROC_PIDLISTFDS,0,NULL,0);
    if (bytes <= 0) {if(!errno)errno=EIO;return -1;}
    if(bytes>16*1024*1024){errno=EOVERFLOW;return -1;}
    bytes += 64*sizeof(struct proc_fdinfo);
    struct proc_fdinfo *fds=calloc(1,bytes); if(!fds) return -1;
    int got=proc_pidinfo(pid,PROC_PIDLISTFDS,0,fds,bytes);
    if(got <= 0 || got >= bytes || got % (int)sizeof(*fds)) {int error=errno?errno:EOVERFLOW;free(fds);errno=error;return -1;}
    int count=0;
    for(int i=0;i<got/(int)sizeof(*fds);i++) {
        if(fds[i].proc_fdtype!=PROX_FDTYPE_SOCKET) continue;
        struct socket_fdinfo s;
        errno=0;
        if(proc_pidfdinfo(pid,fds[i].proc_fd,PROC_PIDFDSOCKETINFO,&s,sizeof(s)) != sizeof(s)) {int error=errno?errno:EIO;free(fds);errno=error;return -1;}
        if(count>=capacity){free(fds);errno=EOVERFLOW;return -1;}
        CSGSocket *v=&out[count++];memset(v,0,sizeof(*v));v->fd=fds[i].proc_fd;
        v->kind=s.psi.soi_kind;v->family=s.psi.soi_family;
        v->socket_type=s.psi.soi_type;v->protocol_number=s.psi.soi_protocol;
        if(s.psi.soi_kind==SOCKINFO_KERN_CTL && !strcmp(s.psi.soi_proto.pri_kern_ctl.kcsi_name,"com.apple.net.utun_control")) {
            uint32_t u=s.psi.soi_proto.pri_kern_ctl.kcsi_unit;
            if(u) snprintf(v->tun,sizeof(v->tun),"utun%u",u-1);
        }
        if(s.psi.soi_kind==SOCKINFO_TCP || s.psi.soi_kind==SOCKINFO_IN) {
            struct in_sockinfo *in=s.psi.soi_kind==SOCKINFO_TCP?&s.psi.soi_proto.pri_tcp.tcpsi_ini:&s.psi.soi_proto.pri_in;
            v->local_port=ntohs(in->insi_lport);v->remote_port=ntohs(in->insi_fport);
            if(s.psi.soi_kind==SOCKINFO_TCP)v->state=s.psi.soi_proto.pri_tcp.tcpsi_state;
            if(in->insi_vflag&INI_IPV4) {
                inet_ntop(AF_INET,&in->insi_laddr.ina_46.i46a_addr4,v->local,sizeof(v->local));
                inet_ntop(AF_INET,&in->insi_faddr.ina_46.i46a_addr4,v->remote,sizeof(v->remote));
            } else if(in->insi_vflag&INI_IPV6) {
                inet_ntop(AF_INET6,&in->insi_laddr.ina_6,v->local,sizeof(v->local));
                inet_ntop(AF_INET6,&in->insi_faddr.ina_6,v->remote,sizeof(v->remote));
            }
        }
    }
    free(fds);return count;
}
static int unix_socket(const char *path,int server,uint32_t owner) {
    if(strlen(path)>=sizeof(((struct sockaddr_un*)0)->sun_path)){errno=ENAMETOOLONG;return -1;}
    int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return -1;
    int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    struct timeval t={.tv_sec=40,.tv_usec=0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t));
    struct sockaddr_un a={0};a.sun_family=AF_UNIX;strlcpy(a.sun_path,path,sizeof(a.sun_path));a.sun_len=SUN_LEN(&a);
    if(server) {
        struct stat st;
        if(lstat(path,&st)==0) { if(!S_ISSOCK(st.st_mode)||st.st_uid!=owner){close(fd);errno=EPERM;return -1;} if(unlink(path)){close(fd);return -1;} }
        mode_t old=umask(077);int r=bind(fd,(struct sockaddr*)&a,a.sun_len);umask(old);
        if(r || chmod(path,0600) || chown(path,owner,-1) || listen(fd,16)){close(fd);return -1;}
    } else if(connect(fd,(struct sockaddr*)&a,a.sun_len)){close(fd);return -1;}
    return fd;
}
int csg_listen(const char *path,uint32_t owner){return unix_socket(path,1,owner);}
int csg_connect(const char *path){return unix_socket(path,0,0);}
int csg_peer(int fd,unsigned char bytes[32],uint32_t *uid,int32_t *pid){
    audit_token_t t; socklen_t size=sizeof(t);
    if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&t,&size)||size!=sizeof(t))return -1;
    memcpy(bytes,&t,sizeof(t));*uid=audit_token_to_euid(t);*pid=audit_token_to_pid(t);return 0;
}
static int command_spawn(const char *path,char *const argv[],CSGCommand *out,int inherit_group){
    int fds[6]={-1,-1,-1,-1,-1,-1},error=0;pid_t pid=0;
    memset(out,0,sizeof(*out));out->input=out->output=out->error=-1;
    for(int i=0;i<6;i+=2){if(pipe(&fds[i]))goto failed;}
    for(int i=0;i<6;i++){if(fcntl(fds[i],F_SETFD,FD_CLOEXEC)<0)goto failed;}
    if(fcntl(fds[1],F_SETNOSIGPIPE,1)<0)goto failed;
    for(int i=0;i<3;i++){int fd=fds[i==0?1:(i==1?2:4)],flags=fcntl(fd,F_GETFL);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)goto failed;}
    posix_spawn_file_actions_t actions;posix_spawnattr_t attributes;
    error=posix_spawn_file_actions_init(&actions);if(error){errno=error;goto failed;}
    error=posix_spawnattr_init(&attributes);if(error){posix_spawn_file_actions_destroy(&actions);errno=error;goto failed;}
    sigset_t mask,defaults;sigemptyset(&mask);sigemptyset(&defaults);sigaddset(&defaults,SIGPIPE);sigaddset(&defaults,SIGTERM);sigaddset(&defaults,SIGINT);
    short flags=(inherit_group?0:POSIX_SPAWN_SETPGROUP)|POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETSIGDEF;
    if((error=posix_spawnattr_setflags(&attributes,flags)) ||
       (!inherit_group&&(error=posix_spawnattr_setpgroup(&attributes,0))) ||
       (error=posix_spawnattr_setsigmask(&attributes,&mask)) ||
       (error=posix_spawnattr_setsigdefault(&attributes,&defaults)) ||
       (error=posix_spawn_file_actions_adddup2(&actions,fds[0],STDIN_FILENO)) ||
       (error=posix_spawn_file_actions_adddup2(&actions,fds[3],STDOUT_FILENO)) ||
       (error=posix_spawn_file_actions_adddup2(&actions,fds[5],STDERR_FILENO))){}
    else {
        char *env[]={"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C","LANG=C",NULL};
        error=posix_spawn(&pid,path,&actions,&attributes,argv,env);
    }
    posix_spawnattr_destroy(&attributes);posix_spawn_file_actions_destroy(&actions);
    if(error){errno=error;goto failed;}
    close(fds[0]);close(fds[3]);close(fds[5]);out->pid=pid;out->input=fds[1];out->output=fds[2];out->error=fds[4];return 0;
failed:
    error=errno;for(int i=0;i<6;i++)if(fds[i]>=0)close(fds[i]);errno=error;return -1;
}
int csg_command_spawn(const char *path,char *const argv[],CSGCommand *out){return command_spawn(path,argv,out,0);}
int csg_command_spawn_inherited(const char *path,char *const argv[],CSGCommand *out){return command_spawn(path,argv,out,1);}
int csg_command_exited(int32_t pid,int32_t *status){
    siginfo_t info={0};
    if(waitid(P_PID,(id_t)pid,&info,WEXITED|WNOHANG|WNOWAIT)<0)return -1;
    if(!info.si_pid)return 0;
    *status=info.si_code==CLD_EXITED?info.si_status:128+info.si_status;return 1;
}
int csg_command_group_active(int32_t leader){
    int32_t ids[32768];int bytes=proc_listpids(PROC_PGRP_ONLY,(uint32_t)leader,ids,sizeof(ids));
    if(bytes<0||bytes==(int)sizeof(ids)){errno=EIO;return -1;}
    for(int i=0;i<bytes/(int)sizeof(ids[0]);i++){
        int32_t pid=ids[i];if(pid<=0||pid==leader)continue;
        struct proc_bsdinfo info;
        if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&info,sizeof(info))==sizeof(info)){if(info.pbi_status!=SZOMB)return 1;}
        else if(!confirmed_zombie(pid) && !(kill(pid,0)<0&&errno==ESRCH)){errno=EIO;return -1;}
    }
    return 0;
}
// Result: 0 timeout/blocked, 1 peer reply or TCP connected, -1 local/setup failure.
static int64_t probe_milliseconds(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static int probe_close_error(int fd){int error=errno;close(fd);errno=error;return -1;}
static int probe_poll(int fd,short events,int64_t deadline){
    for(;;){
        int64_t now=probe_milliseconds();if(now<0)return -1;
        int64_t left=deadline-now;if(left<=0)return 0;
        struct pollfd p={fd,events,0};int result=poll(&p,1,left>INT_MAX?INT_MAX:(int)left);
        if(result<0){if(errno==EINTR)continue;return -1;}
        if(!result)return 0;
        if(p.revents&POLLNVAL){errno=EBADF;return -1;}
        if(!(p.revents&(events|POLLERR|POLLHUP))){errno=EIO;return -1;}
        return 1;
    }
}
static int probe_execute(int family,int tcp,uint32_t index,const char *source,const char *target,uint16_t sport,uint16_t dport,int timeout,int stun,int *sent,CSGProbeDiagnostics *diagnostics){
    *sent=0;if((family!=4&&family!=6)||timeout<=0){errno=EINVAL;return -1;}
    int64_t started=probe_milliseconds();if(started<0)return -1;int64_t deadline=started+timeout;
    int af=family==6?AF_INET6:AF_INET;
    diagnostics->stage=CSG_PROBE_SOCKET;int fd=socket(af,tcp?SOCK_STREAM:SOCK_DGRAM,0);if(fd<0)return -1;
    int one=1;if(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one)))return probe_close_error(fd);
    diagnostics->stage=CSG_PROBE_BOUND_IF;if(setsockopt(fd,af==AF_INET?IPPROTO_IP:IPPROTO_IPV6,af==AF_INET?IP_BOUND_IF:IPV6_BOUND_IF,&index,sizeof(index)))return probe_close_error(fd);
    struct sockaddr_storage local={0},remote={0};socklen_t len;
    diagnostics->stage=CSG_PROBE_ADDRESS;
    if(af==AF_INET){struct sockaddr_in *l=(void*)&local,*r=(void*)&remote;len=sizeof(*l);l->sin_len=r->sin_len=len;l->sin_family=r->sin_family=af;l->sin_port=htons(sport);r->sin_port=htons(dport);if(inet_pton(af,source,&l->sin_addr)!=1||inet_pton(af,target,&r->sin_addr)!=1){close(fd);errno=EINVAL;return -1;}}
    else {struct sockaddr_in6 *l=(void*)&local,*r=(void*)&remote;len=sizeof(*l);l->sin6_len=r->sin6_len=len;l->sin6_family=r->sin6_family=af;l->sin6_port=htons(sport);r->sin6_port=htons(dport);if(inet_pton(af,source,&l->sin6_addr)!=1||inet_pton(af,target,&r->sin6_addr)!=1){close(fd);errno=EINVAL;return -1;}}
    diagnostics->stage=CSG_PROBE_BIND;if(bind(fd,(void*)&local,len))return probe_close_error(fd);
    diagnostics->stage=CSG_PROBE_NONBLOCKING;int flags=fcntl(fd,F_GETFL);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)return probe_close_error(fd);
    int result=0;
    if(tcp){diagnostics->stage=CSG_PROBE_CONNECT;int r=connect(fd,(void*)&remote,len);if(r==0){*sent=1;result=1;}else if(errno==EINPROGRESS){*sent=1;diagnostics->stage=CSG_PROBE_POLL;int ready=probe_poll(fd,POLLOUT,deadline);if(ready<0)result=-1;else if(ready>0){int e=0;socklen_t n=sizeof(e);diagnostics->stage=CSG_PROBE_SOCKET_ERROR;if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&e,&n)){result=-1;}else if(n!=sizeof(e)){errno=EIO;result=-1;}else if(e==0)result=1;else if(e!=EACCES&&e!=EPERM){errno=e;result=-1;}}}else if(errno==EACCES||errno==EPERM){*sent=1;}else result=-1;}
    else {unsigned char b[64]={0};int n;
        if(stun){b[1]=1;b[4]=0x21;b[5]=0x12;b[6]=0xa4;b[7]=0x42;arc4random_buf(b+8,12);n=20;}
        else {b[0]=0x43;b[1]=0x53;b[2]=1;b[5]=1;b[12]=3;memcpy(b+13,"csg",3);b[16]=4;memcpy(b+17,"test",4);b[21]=0;b[23]=1;b[25]=1;n=26;}
        diagnostics->stage=CSG_PROBE_SEND;ssize_t wrote=sendto(fd,b,n,0,(void*)&remote,len);
        if(wrote==n){*sent=1;diagnostics->stage=CSG_PROBE_POLL;int ready=probe_poll(fd,POLLIN,deadline);if(ready<0)result=-1;else if(ready>0){unsigned char reply[2048];diagnostics->stage=CSG_PROBE_RECEIVE;ssize_t got=recv(fd,reply,sizeof(reply),0);result=got>=0?1:-1;}}
        else if(wrote<0&&(errno==EACCES||errno==EPERM)){*sent=1;}else{if(wrote>=0)errno=EIO;result=-1;}
    }
    int error=errno;close(fd);errno=error;return result;
}
int csg_probe_detailed(int family,int tcp,uint32_t index,const char *source,const char *target,uint16_t sport,uint16_t dport,int timeout,int stun,int *sent,CSGProbeDiagnostics *diagnostics){
    CSGProbeDiagnostics local={0};if(!diagnostics)diagnostics=&local;memset(diagnostics,0,sizeof(*diagnostics));
    int64_t start=probe_milliseconds();int result=probe_execute(family,tcp,index,source,target,sport,dport,timeout,stun,sent,diagnostics);int error=errno;
    int64_t end=probe_milliseconds();diagnostics->error=result<0?error:0;diagnostics->elapsed_ms=start>=0&&end>=start?(uint64_t)(end-start):0;errno=error;return result;
}
int csg_probe(int family,int tcp,uint32_t index,const char *source,const char *target,uint16_t sport,uint16_t dport,int timeout,int stun,int *sent){return csg_probe_detailed(family,tcp,index,source,target,sport,dport,timeout,stun,sent,NULL);}
int csg_route_open(void){int fd=socket(PF_ROUTE,SOCK_RAW,0);if(fd>=0&&fcntl(fd,F_SETFL,O_NONBLOCK)<0){int error=errno;close(fd);errno=error;return -1;}return fd;}
/* IFINFO counters are not interface lifetimes. Preserve ALL non-statistical
 * if_data fields (including last administrative change), flags and index.
 * Only this exact, seeded signature is eligible for duplicate suppression. */
int csg_route_decode(const void *data,size_t n,CSGRouteEvent *event){
    memset(event,0,sizeof(*event));if(n<4)return -1;const unsigned char *b=data;uint16_t length;memcpy(&length,b,2);
    if(length!=n||b[2]!=RTM_VERSION)return -1;
    event->type=b[3];
    if(event->type==RTM_IFINFO){
        struct if_msghdr r;if(n<sizeof(r))return -1;memcpy(&r,b,sizeof(r));event->index=r.ifm_index;
        _Static_assert(2*sizeof(struct if_data)+16<512,"route signature capacity");
        struct if_data stable=r.ifm_data;
        memset((char *)&stable+offsetof(struct if_data,ifi_ipackets),0,
               offsetof(struct if_data,ifi_lastchange)-offsetof(struct if_data,ifi_ipackets));
        int used=snprintf(event->signature,sizeof(event->signature),"%u:",(unsigned)r.ifm_flags);
        const unsigned char *bytes=(const unsigned char *)&stable;
        for(size_t i=0;i<sizeof(stable);i++)used+=snprintf(event->signature+used,sizeof(event->signature)-(size_t)used,"%02x",bytes[i]);
        return event->index?1:-1;
    }
    if(event->type==RTM_NEWADDR||event->type==RTM_DELADDR){struct ifa_msghdr r;if(n<sizeof(r))return -1;memcpy(&r,b,sizeof(r));event->index=r.ifam_index;return event->index?1:-1;}
    if(event->type==RTM_ADD||event->type==RTM_DELETE||event->type==RTM_CHANGE||event->type==RTM_REDIRECT){
        struct rt_msghdr r;if(n<sizeof(r))return -1;memcpy(&r,b,sizeof(r));event->index=r.rtm_index;
        if(event->type!=RTM_REDIRECT&&(r.rtm_flags&(RTF_LLINFO|RTF_WASCLONED)))return 2;
        return 1;
    }
    /* Read-only replies and multicast membership do not alter unicast policy.
     * Every other message is conservative, including IFINFO2/unknown types. */
    if(event->type==RTM_GET||event->type==RTM_GET2||event->type==RTM_MISS||event->type==RTM_RESOLVE||
       event->type==RTM_NEWMADDR||event->type==RTM_DELMADDR||event->type==RTM_NEWMADDR2)return 2;
    return 1;
}
int csg_route_next(int fd,CSGRouteEvent *event){
    unsigned char b[8192];memset(event,0,sizeof(*event));ssize_t n=read(fd,b,sizeof(b));
    if(n<0)return errno==EAGAIN?0:-1;if(n==(ssize_t)sizeof(b))return -1;
    return csg_route_decode(b,(size_t)n,event);
}
/* Socket is opened BEFORE this snapshot so intervening changes stay queued.
 * Seed failure disables suppression, never disables the event monitor. */
int csg_route_seed(CSGRouteEvent *events,int capacity){
    int mib[]={CTL_NET,PF_ROUTE,0,0,NET_RT_IFLIST,0};size_t size=0;
    if(sysctl(mib,6,NULL,&size,NULL,0)<0||size==0||size>4*1024*1024)return -1;
    unsigned char *data=malloc(size);if(!data)return -1;
    if(sysctl(mib,6,data,&size,NULL,0)<0){free(data);return -1;}
    size_t offset=0;int count=0;
    while(offset<size){
        uint16_t length;if(size-offset<4){count=-1;break;}memcpy(&length,data+offset,2);
        if(length<4||length>size-offset){count=-1;break;}
        CSGRouteEvent e;int result=csg_route_decode(data+offset,length,&e);
        if(result<0){count=-1;break;}
        if(e.type==RTM_IFINFO){if(count>=capacity){count=-1;break;}events[count++]=e;}
        offset+=length;
    }
    free(data);return count;
}
int csg_route_message(const void *data,size_t n,uint32_t *index){CSGRouteEvent e;int r=csg_route_decode(data,n,&e);*index=e.index;return r;}
int csg_route_read_event(int fd,uint32_t *index){CSGRouteEvent e;int r=csg_route_next(fd,&e);*index=e.index;return r;}
int csg_route_read(int fd){uint32_t index;return csg_route_read_event(fd,&index);}
