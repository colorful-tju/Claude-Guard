#include "NativeGuard.h"
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Creates and reaps ONLY its own child. No network, PF, or existing-process signals. */
int main(void) {
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
