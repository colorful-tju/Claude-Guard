#include "NativeGuard.h"
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
static int scenario=0,calls=0;
int csg_test_sysctl(int *name,u_int count,void *old,size_t *size,void *newp,size_t newlen) {
    if(!scenario)return sysctl(name,count,old,size,newp,newlen);
    calls++;
    if(scenario==1){errno=EPERM;return -1;}
    if(scenario==2){*size=0;return 0;}
    struct kinfo_proc k={0};k.kp_proc.p_pid=getpid();k.kp_proc.p_stat=SRUN;
    k.kp_proc.p_starttime.tv_sec=100;k.kp_proc.p_starttime.tv_usec=23;k.kp_eproc.e_ucred.cr_uid=getuid();
    if(scenario==3){*size=1;return 0;}
    if(scenario==4)k.kp_proc.p_pid++;
    if(scenario==5 && calls==2)k.kp_proc.p_starttime.tv_sec++;
    if(scenario==6 && calls==2)k.kp_eproc.e_ucred.cr_uid++;
    if(scenario==7)k.kp_proc.p_stat=SZOMB;
    if(scenario==8)k.kp_proc.p_starttime.tv_sec=0;
    if(scenario==9)k.kp_proc.p_stat=SIDL;
    if(scenario==12 && calls==2)strcpy(k.kp_proc.p_comm,"changed");
    if(scenario==10)k.kp_proc.p_starttime.tv_usec=1000000;
    memcpy(old,&k,sizeof(k));*size=sizeof(k);return 0;
}
int main(void) {
    CSGProcess full,lifetime;
    assert(csg_process(getpid(),&full)==0);
    assert(csg_process_lifetime(getpid(),&lifetime)==0);
    assert(full.pid==lifetime.pid && full.uid==lifetime.uid && full.started==lifetime.started);
    assert(!lifetime.path[0] && lifetime.name[0]);
    for(scenario=1;scenario<=10;scenario++) {
        calls=0;int result=csg_process_lifetime(getpid(),&lifetime);
        if(scenario==2)assert(result==CSG_PROCESS_GONE);
        else if(scenario==7)assert(result==CSG_PROCESS_ZOMBIE);
        else assert(result<0);
        assert(lifetime.started==0 && !lifetime.path[0]);
    }
    scenario=12;calls=0;assert(csg_process_lifetime(getpid(),&lifetime)<0);
    scenario=11;calls=0;assert(csg_process_lifetime(getpid(),&lifetime)==0 && calls==2);
    assert(lifetime.started==100000023);
    assert(csg_process_lifetime(0,&lifetime)<0);
    puts("PASS native termination lifetime: stable identity, reuse/UID/size/status/error rejection; no signals/network");
}
