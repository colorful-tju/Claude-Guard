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

/* Replay the route payload that stopped 0.5.12 at 06:03:50Z. No route socket writes. */
static void scoped_route_tests(void) {
    const char *hex="1c1e000000000000fe80000d0000000010609dfffe40f9ef0d00000014120d000600060012609d40f9ef000000000000";
    unsigned char bytes[512]={0};struct rt_msghdr r={0};
    r.rtm_msglen=sizeof(r)+strlen(hex)/2;r.rtm_version=RTM_VERSION;r.rtm_type=RTM_ADD;r.rtm_flags=0x844;r.rtm_addrs=3;
    memcpy(bytes,&r,sizeof(r));
    for(size_t i=0;i<strlen(hex)/2;i++){unsigned value;assert(sscanf(hex+2*i,"%2x",&value)==1);bytes[sizeof(r)+i]=(unsigned char)value;}
    CSGRouteEvent e;
    assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==13);
    /* Address rotation carries DST/GATEWAY/NETMASK/IFP/IFA, not just a host. */
    const char *prefix="1c1e000000000000fe80000d0000000000000000000000000000000014120d00060000000000000000000000000000001cffffffffffffffffffffffffffffff00000000000000000000000014120d00060506006177646c301a8b74ade506001c1e000000000000fe80000d00000000188b74fffeade50600000000";
    unsigned char network[512]={0};struct rt_msghdr nr=r;nr.rtm_addrs=0x37;nr.rtm_flags=0x1000141;nr.rtm_msglen=sizeof(nr)+strlen(prefix)/2;
    memcpy(network,&nr,sizeof(nr));for(size_t i=0;i<strlen(prefix)/2;i++){unsigned value;assert(sscanf(prefix+2*i,"%2x",&value)==1);network[sizeof(nr)+i]=(unsigned char)value;}
    assert(csg_route_decode(network,nr.rtm_msglen,&e)==1 && e.index==13);
    network[sizeof(nr)+48+8]=0;assert(csg_route_decode(network,nr.rtm_msglen,&e)==1 && e.index==0);network[sizeof(nr)+48+8]=0xff;
    network[sizeof(nr)+76+2]=14;assert(csg_route_decode(network,nr.rtm_msglen,&e)==1 && e.index==0);
    r.rtm_flags=0;memcpy(bytes,&r,sizeof(r));assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);r.rtm_flags=0x844;memcpy(bytes,&r,sizeof(r));
    /* The same form on llw0 index 14 is attributed, never blanket utun*. */
    bytes[sizeof(r)+11]=14;bytes[sizeof(r)+24]=14;bytes[sizeof(r)+30]=14;
    assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==14);
    bytes[sizeof(r)+11]=13;bytes[sizeof(r)+24]=13;bytes[sizeof(r)+30]=13;
    for(size_t cut=sizeof(r);cut<sizeof(r)+strlen(hex)/2;cut++) {
        struct rt_msghdr shortHeader=r;shortHeader.rtm_msglen=cut;memcpy(bytes,&shortHeader,sizeof(shortHeader));
        assert(csg_route_decode(bytes,cut,&e)==1 && e.index==0);
    }
    memcpy(bytes,&r,sizeof(r));
    /* A global destination, mismatched scope, redirect or malformed payload must
     * never acquire an auxiliary interface attribution. */
    bytes[sizeof(r)+8]=0x20;assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);bytes[sizeof(r)+8]=0xfe;
    bytes[sizeof(r)+30]=14;assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);bytes[sizeof(r)+30]=13;
    bytes[sizeof(r)+24]=14;assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);bytes[sizeof(r)+24]=13;
    r.rtm_type=RTM_REDIRECT;memcpy(bytes,&r,sizeof(r));assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);
    r.rtm_type=RTM_ADD;r.rtm_msglen--;memcpy(bytes,&r,sizeof(r));assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);
    r.rtm_msglen++;memcpy(bytes,&r,sizeof(r));bytes[sizeof(r)+28]=255;assert(csg_route_decode(bytes,r.rtm_msglen,&e)==1 && e.index==0);
}

/* Creates and reaps ONLY its own child. No network, PF, or existing-process signals. */
int main(void) {
    scoped_route_tests();
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
