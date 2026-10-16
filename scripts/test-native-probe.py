#!/usr/bin/env python3
"""Inject native syscall failures without opening a socket or sending traffic."""
from pathlib import Path
import subprocess, tempfile
root=Path(__file__).resolve().parents[1]
src=(root/'Sources/NativeGuard/native.c').read_text()
prefix=src[:src.index('static int confirmed_zombie')]
probe=src[src.index('// Result: 0 timeout/blocked'):src.index('int csg_route_open')]
stubs=r'''
static int mode,calls,last_timeout;static long long fake_ms;
static int fake_socket(int a,int b,int c){return 42;}
static int fake_setsockopt(int a,int b,int c,const void*d,socklen_t e){return 0;}
static int fake_bind(int a,const struct sockaddr*b,socklen_t c){return 0;}
static int fake_fcntl(int a,int b,...){if(mode==6){errno=EIO;return -1;}return 0;}
static int fake_close(int fd){return 0;}
static int fake_connect(int a,const struct sockaddr*b,socklen_t c){errno=EINPROGRESS;return -1;}
static int fake_clock_gettime(clockid_t id,struct timespec*out){out->tv_sec=fake_ms/1000;out->tv_nsec=(fake_ms%1000)*1000000;return 0;}
static int fake_poll(struct pollfd*a,nfds_t n,int t){calls++;if(mode==5){if(last_timeout && t>=last_timeout){fprintf(stderr,"budget restarted\n");exit(3);}last_timeout=t;if(calls<3){fake_ms+=10;errno=EINTR;return -1;}fake_ms+=t;return 0;}if(mode==1||mode==3){errno=EIO;return -1;}a->revents=(mode<=2?POLLOUT:POLLIN);return 1;}
static int fake_getsockopt(int a,int b,int c,void*d,socklen_t*e){errno=EIO;return -1;}
static ssize_t fake_sendto(int a,const void*b,size_t c,int d,const struct sockaddr*e,socklen_t f){return c;}
static ssize_t fake_recv(int a,void*b,size_t c,int d){errno=EIO;return -1;}
#define socket fake_socket
#define setsockopt fake_setsockopt
#define bind fake_bind
#define fcntl fake_fcntl
#define close fake_close
#define connect fake_connect
#define poll fake_poll
#define getsockopt fake_getsockopt
#define sendto fake_sendto
#define recv fake_recv
#define clock_gettime fake_clock_gettime
'''
main=r'''
int main(void){int failures=0;for(mode=1;mode<=6;mode++){int sent=0;calls=0;last_timeout=0;fake_ms=0;CSGProbeDiagnostics d;int result=csg_probe_detailed(4,(mode<=2||mode==6),1,"127.0.0.1","127.0.0.1",0,12345,80,0,&sent,&d);int stages[]={0,CSG_PROBE_POLL,CSG_PROBE_SOCKET_ERROR,CSG_PROBE_POLL,CSG_PROBE_RECEIVE,CSG_PROBE_POLL,CSG_PROBE_NONBLOCKING};if(d.stage!=stages[mode]){fprintf(stderr,"FAIL diagnostic stage mode=%d stage=%d\n",mode,d.stage);failures++;}if(mode==5){if(result!=0||calls!=3||fake_ms>80||d.error){fprintf(stderr,"FAIL EINTR absolute budget result=%d calls=%d ms=%lld\n",result,calls,fake_ms);failures++;}}else if(result!=-1||d.error!=EIO){fprintf(stderr,"FAIL native local failure mode=%d result=%d errno=%d\n",mode,result,d.error);failures++;}}if(!failures)puts("PASS six native local-error and EINTR budget cases; no sockets");return failures?1:0;}
'''
with tempfile.TemporaryDirectory(prefix='csg-probe-test-') as temp:
 p=Path(temp);(p/'test.c').write_text(prefix+stubs+probe+main)
 subprocess.run(['clang','-I',str(root/'Sources/NativeGuard/include'),str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True,timeout=5)
