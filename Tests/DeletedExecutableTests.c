#include "NativeGuard.h"
#include <libproc.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Only the disposable child owned by this test is signalled or unlinked. */
int main(int argc,char **argv){
    if(argc==2 && !strcmp(argv[1],"--child")){write(STDOUT_FILENO,"R",1);for(;;)pause();}
    if(argc!=2)return 2;
    int pipefd[2];if(pipe(pipefd))return 2;
    pid_t child=fork();if(child<0)return 2;
    if(child==0){dup2(pipefd[1],STDOUT_FILENO);close(pipefd[0]);close(pipefd[1]);execl(argv[1],argv[1],"--child",NULL);_exit(127);}
    close(pipefd[1]);char ready=0;int ok=read(pipefd[0],&ready,1)==1 && ready=='R';close(pipefd[0]);
    CSGProcess before={0},after={0};
    ok=ok && csg_process(child,&before)==0;
    ok=ok && unlink(argv[1])==0;
    char path[4096]={0};errno=0;int raw=proc_pidpath(child,path,sizeof path),rawError=errno;
    int result=csg_process(child,&after),error=errno;
    ok=ok && raw==0 && rawError==ENOENT && (result==0 && before.started==after.started && before.uid==after.uid && !strcmp(before.path,after.path));
    kill(child,SIGTERM);waitpid(child,NULL,0);
    if(!ok){fprintf(stderr,"Deleted executable regression: raw=%d errno=%d recovered=%d errno=%d\n",raw,rawError,result,error);return 1;}
    puts("PASS deleted executable: live identity and exact kernel mapping path retained");return 0;
}
