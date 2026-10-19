#include "NativeGuard.h"
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <unistd.h>
#include <net/if.h>
#include <net/route.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Creates and reaps ONLY its own child. No network, PF, or existing-process signals. */
int main(void) {
    uint32_t index=0;
    struct ifa_msghdr address={0};address.ifam_msglen=sizeof(address);address.ifam_version=RTM_VERSION;address.ifam_type=RTM_NEWADDR;address.ifam_index=13;
    assert(csg_route_message(&address,sizeof(address),&index)==1 && index==13);
    address.ifam_type=RTM_DELADDR;address.ifam_index=19;
    assert(csg_route_message(&address,sizeof(address),&index)==1 && index==19);
    address.ifam_version=0;assert(csg_route_message(&address,sizeof(address),&index)==-1);
    struct if_msghdr interface={0};interface.ifm_msglen=sizeof(interface);interface.ifm_version=RTM_VERSION;interface.ifm_type=RTM_IFINFO;interface.ifm_index=12;
    assert(csg_route_message(&interface,sizeof(interface),&index)==1 && index==12);
    assert(csg_route_message(&interface,3,&index)==-1);
    struct rt_msghdr route={0};route.rtm_msglen=sizeof(route);route.rtm_version=RTM_VERSION;route.rtm_type=RTM_CHANGE;route.rtm_index=14;
    assert(csg_route_message(&route,sizeof(route),&index)==1 && index==14);
    route.rtm_flags=RTF_WASCLONED;assert(csg_route_message(&route,sizeof(route),&index)==2);
    route.rtm_type=RTM_REDIRECT;route.rtm_flags=0;
    assert(csg_route_message(&route,sizeof(route),&index)==1 && index==14);
    CSGRouteEvent first,second;
    route.rtm_type=RTM_ADD;route.rtm_errno=EEXIST;route.rtm_index=0;
    assert(csg_route_decode(&route,sizeof(route),&first)==1 && first.error==EEXIST);
    assert(strstr(first.signature,"errno=17") && strstr(first.signature,"flags="));
    route.rtm_errno=-1;assert(csg_route_decode(&route,sizeof(route),&first)==-1);
    route.rtm_errno=0;route.rtm_flags=0;
    assert(csg_route_decode(&route,sizeof(route),&first)==1 && first.error==0);

    interface.ifm_flags=IFF_UP;interface.ifm_data.ifi_mtu=1500;
    assert(csg_route_decode(&interface,sizeof(interface),&first)==1);
    interface.ifm_data.ifi_ipackets=123;interface.ifm_data.ifi_obytes=9000;
    assert(csg_route_decode(&interface,sizeof(interface),&second)==1);
    assert(strcmp(first.signature,second.signature)==0);
    interface.ifm_data.ifi_mtu=1400;csg_route_decode(&interface,sizeof(interface),&second);
    assert(strcmp(first.signature,second.signature)!=0);
    interface.ifm_data.ifi_mtu=1500;interface.ifm_data.ifi_lastchange.tv_sec=1;
    csg_route_decode(&interface,sizeof(interface),&second);assert(strcmp(first.signature,second.signature)!=0);
    interface.ifm_data.ifi_lastchange.tv_sec=0;interface.ifm_flags=0;
    csg_route_decode(&interface,sizeof(interface),&second);assert(strcmp(first.signature,second.signature)!=0);
    interface.ifm_type=255;assert(csg_route_decode(&interface,sizeof(interface),&second)==1);
    CSGRouteEvent seed[512];int seed_count=csg_route_seed(seed,512);
    assert(seed_count>0 && seed_count<=512);
    for(int i=0;i<seed_count;i++)assert(seed[i].type==RTM_IFINFO && seed[i].index>0 && seed[i].signature[0]);
    CSGProcess self={0};
    if(csg_process(getpid(),&self)!=0 || self.pid!=getpid() || !self.path[0]) {
        fprintf(stderr,"Live self process identity missing\n");return 1;
    }
    pid_t child=fork();
    if(child<0) {perror("fork");return 1;}
    if(child==0) _exit(0);
    int confirmed=0;
    for(int i=0;i<1000;i++) {
        struct kinfo_proc info={0};size_t size=sizeof(info);
        int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,child};
        if(sysctl(mib,4,&info,&size,NULL,0)==0 && size==sizeof(info) &&
           info.kp_proc.p_pid==child && info.kp_proc.p_stat==SZOMB) {confirmed=1;break;}
        usleep(1000);
    }
    CSGProcess zombie={0};errno=0;
    int result=csg_process(child,&zombie);int error=errno;
    int reaped=waitpid(child,NULL,0)==child;
    /* The new native contract uses positive 1 for a kernel-confirmed non-live zombie. */
    if(!confirmed || !reaped || result!=1) {
        fprintf(stderr,"Zombie classification failed: confirmed=%d result=%d errno=%d reaped=%d\n",confirmed,result,error,reaped);
        return 1;
    }
    if(csg_process(child,&zombie)!=CSG_PROCESS_GONE) {fprintf(stderr,"Reaped child became a live identity\n");return 1;}
    for(int round=0;round<32;round++) {
        pid_t transient=fork();if(transient<0){perror("fork churn");return 1;}
        if(transient==0) _exit(0);
        CSGProcess observed={0};(void)csg_process(transient,&observed);
        if(waitpid(transient,NULL,0)!=transient || csg_process(transient,&observed)!=CSG_PROCESS_GONE) {
            fprintf(stderr,"Reaped transient child not independently classified absent\n");return 1;
        }
    }
    puts("Native process test passed: 32 transient child lifecycles; live identity, kernel-confirmed zombie, reaped child");
    return 0;
}
