// A contention harness for binder's poll wakeup path.
//
// Not a regression test -- it passes both with and without the deferred-wakeup
// fix, and that fact is the finding it exists to record. It is the rig used to
// establish, with an instrumented poll_wakeup_trylock, that binder's wakeups
// really are discarded under contention (see docs/android-bringup.md).
//
// SHAPE. Three processes sharing one epoll instance:
//   - a receiver, driven only by epoll_wait, never a blocking binder read
//   - a scanner, spinning epoll_wait(timeout=0) on the INHERITED epfd, which
//     is what actually holds poll->lock often enough to make the trylock fail
//   - a sender, flooding oneway transactions
//
// USING IT. On its own it only reports delivery. To see the drops, instrument
// fs/poll.c's poll_wakeup_trylock with counters on each trylock failure and
// print them from binder_show_state; then:
//
//     gcc -m32 -static -O1 -w -o $ROOT/probe binder_poll_wakeup_probe.c
//     ish -r $ROOT /bin/sh -c "mount -t binder binder /dev/binderfs && \
//                              /probe /dev/binderfs/vndbinder; \
//                              grep TRYLOCK /proc/ish/binder"
//
// WHAT IT SHOWED. ~3,100 of ~12,000 wakeups discarded per run, and yet every
// transaction still arrived. The scanner that creates the contention is also
// what rescues the receiver: epoll here is level-triggered, so the next scan
// recomputes readiness from binder_poll and finds the queued work regardless
// of the lost poke. Removing the scanner removes the contention along with it
// (0 failures), which is the awkward part -- see the doc.



#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>

typedef uint64_t bsz;
struct bwr { bsz ws, wc, wb, rs, rc, rb; };
struct btd {
    union { uint32_t handle; bsz ptr; } target;
    bsz cookie; uint32_t code, flags; int32_t spid; uint32_t seuid;
    bsz data_size, offsets_size;
    union { struct { bsz buffer, offsets; } ptr; uint8_t buf[8]; } data;
};
#define BWR _IOWR('b',1,struct bwr)
#define SETMGR _IOW('b',7,int32_t)
#define BC_TRANSACTION _IOW('c',0,struct btd)
#define BC_FREE_BUFFER _IOW('c',3,bsz)
#define BC_ENTER_LOOPER _IO('c',12)
#define BR_TRANSACTION _IOR('r',2,struct btd)
#define MAPSZ (128*1024)
#define N 4000

static int wr(int fd, void *w, size_t wn, void *r, size_t rn, size_t *got) {
    struct bwr b; memset(&b,0,sizeof b);
    b.ws=wn; b.wb=(bsz)(uintptr_t)w; b.rs=rn; b.rb=(bsz)(uintptr_t)r;
    if (ioctl(fd,BWR,&b)<0) return -1;
    if (got) *got=(size_t)b.rc;
    return 0;
}
static int openb(const char *p, void **m) {
    int fd=open(p,O_RDWR|O_CLOEXEC); if(fd<0) return -1;
    *m=mmap(NULL,MAPSZ,PROT_READ,MAP_PRIVATE,fd,0);
    if(*m==MAP_FAILED){close(fd);return -1;}
    return fd;
}

int main(int argc,char**argv){
    const char *dev = argc>1?argv[1]:"/dev/binderfs/vndbinder";
    void *m; int sv=openb(dev,&m);
    if(sv<0){printf("open %s failed\n",dev);return 1;}
    int32_t z=0;
    if(ioctl(sv,SETMGR,&z)<0){printf("setmgr failed\n");return 1;}
    uint32_t el=BC_ENTER_LOOPER; wr(sv,&el,sizeof el,NULL,0,NULL);

    int ep=epoll_create1(0);
    struct epoll_event ev={.events=EPOLLIN,.data={.fd=sv}};
    epoll_ctl(ep,EPOLL_CTL_ADD,sv,&ev);

    pid_t scanner=fork();
    if(scanner==0){
        struct epoll_event sev;
        for(;;) epoll_wait(ep,&sev,1,0);   // tight scan: holds poll->lock
        _exit(0);
    }

    int p[2]; if(pipe(p)) return 1;
    pid_t c=fork();
    if(c==0){
        close(p[0]); void *m2; int cf=openb(dev,&m2);
        if(cf<0) _exit(70);
        static uint64_t payload; payload=0x1234;
        struct { uint32_t cmd; struct btd t; } __attribute__((packed)) o;
        for(int i=0;i<N;i++){
            memset(&o,0,sizeof o); o.cmd=BC_TRANSACTION; o.t.target.handle=0;
            o.t.code=0x2a; o.t.flags=0x01 /*ONE_WAY*/;
            o.t.data_size=sizeof payload;
            o.t.data.ptr.buffer=(bsz)(uintptr_t)&payload;
            uint8_t rb[256]; size_t n=0;
            if(wr(cf,&o,sizeof o,rb,sizeof rb,&n)<0) break;
        }
        (void)!write(p[1],"d",1); close(p[1]);
        _exit(0);
    }
    close(p[1]);

    // Receiver driven ONLY by epoll -- never a blocking binder read.
    int seen=0, idle=0;
    uint8_t rb[8192];
    while(seen<N && idle<400){
        int n=epoll_wait(ep,&ev,1,25);
        if(n<=0){ idle++; continue; }
        idle=0;
        size_t got=0;
        if(wr(sv,NULL,0,rb,sizeof rb,&got)<0) break;
        size_t i=0;
        while(i+4<=got){
            uint32_t cmd; memcpy(&cmd,rb+i,4); i+=4;
            if(cmd==BR_TRANSACTION){
                struct btd t; memcpy(&t,rb+i,sizeof t); i+=sizeof t;
                seen++;
                struct { uint32_t cmd; bsz b; } __attribute__((packed)) fb;
                fb.cmd=BC_FREE_BUFFER; fb.b=t.data.ptr.buffer;
                wr(sv,&fb,sizeof fb,NULL,0,NULL);
            } else if(cmd==(uint32_t)_IOR('r',7,uint64_t[2])||
                      cmd==(uint32_t)_IOR('r',8,uint64_t[2])) i+=16;
        }
    }
    int st=0; waitpid(c,&st,0);
    kill(scanner,9); waitpid(scanner,NULL,0);
    printf("received %d/%d oneway transactions via epoll%s\n", seen, N,
           seen<N ? "   *** STALLED ***" : "");
    return seen<N?1:0;
}
