#include <libproc.h>
#include <sys/proc_info.h>
#include <assert.h>
static int fake_info(int,int,uint64_t,void *,int);
static int fake_path(int,void *,uint32_t);
#define proc_pidinfo fake_info
#define proc_pidpath fake_path
#include "../Sources/NativeGuard/native.c"
#undef proc_pidinfo
#undef proc_pidpath
static int scenario=0,bsd_reads=0,region_reads=0;
static int fake_path(int pid,void *out,uint32_t size){(void)pid;(void)out;(void)size;errno=scenario==6?EACCES:ENOENT;return 0;}
static int fake_info(int pid,int flavor,uint64_t address,void *out,int size){
    if(flavor==PROC_PIDTBSDINFO){
        assert(size==sizeof(struct proc_bsdinfo));struct proc_bsdinfo b={0};bsd_reads++;
        b.pbi_pid=pid;b.pbi_uid=getuid();b.pbi_start_tvsec=100+(scenario==5 && bsd_reads>1);b.pbi_status=SRUN;
        strcpy(b.pbi_name,"Claude");memcpy(out,&b,sizeof b);return sizeof b;
    }
    assert(flavor==PROC_PIDREGIONPATHINFO);region_reads++;
    if(scenario==4){errno=EACCES;return 0;}
    int count=scenario==2?2:1;
    if(address>=(uint64_t)count*4096){errno=EINVAL;return 0;}
    struct proc_regionwithpathinfo r={0};r.prp_prinfo.pri_protection=VM_PROT_EXECUTE;
    r.prp_prinfo.pri_address=address;r.prp_prinfo.pri_size=scenario==7?0:4096;
    r.prp_vip.vip_vi.vi_stat.vst_mode=S_IFREG|0700;r.prp_vip.vip_vi.vi_stat.vst_nlink=scenario==8?1:0;
    r.prp_vip.vip_vi.vi_stat.vst_dev=1;r.prp_vip.vip_vi.vi_stat.vst_ino=address+1;
    strcpy(r.prp_vip.vip_path,scenario==3?"/example/Other":"/example/Claude.app/Contents/MacOS/Claude");
    memcpy(out,&r,sizeof r);return sizeof r;
}
int main(void){
    for(scenario=0;scenario<=8;scenario++){
        bsd_reads=region_reads=0;CSGProcess p={0};int result=csg_process(getpid(),&p);
        if(scenario<=1){assert(result==0 && strstr(p.path,"/Claude.app/Contents/")!=NULL);}
        else assert(result==-2);
        if(scenario==6)assert(region_reads==0 && errno==EACCES);
    }
    puts("PASS deleted-path boundaries: ambiguity, name mismatch, permission, identity race, malformed walk and linked vnode rejected");return 0;
}
