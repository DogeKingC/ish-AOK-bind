// A behavioural fingerprint of a binder driver's object-offset alignment rule.
//
// Not part of the regression suite -- tests/manual/binder_ipc.c's `align4`
// phase is what guards the fix. This is the diagnostic that answers a
// different question: "which rule is the driver I am talking to RIGHT NOW
// actually implementing?" It exists because a device build cannot tell you
// which commit it came from (the version string is `iSH-AOK 1.3 (547)` with a
// zeroed build date) and reasoning about who had time to install what gets it
// wrong.
//
// It is deliberately standalone -- no test_common.h -- so it can be gzipped,
// base64'd and pasted through /AOK/tools/ish-remote.sh in a single message,
// compiled on the device with the gcc that is already there, and run.
//
//     gcc -O1 -w -o /tmp/probe binder_object_align_probe.c
//     /tmp/probe /dev/vndbinder          # or a binderfs path
//
// Reading it: offset 2 must be REJECTed under either the 4- or the 8-byte
// rule, so it proves offset validation is running at all rather than the
// driver accepting everything. Offset 4 is the discriminator -- ACCEPT means
// the 4-byte rule Linux uses (and that libbinder's checkService reply needs),
// REJECT means the 8-byte rule that broke it. Run it against a known-good and
// a known-bad local build before trusting it against anything else.
//
// Expected on a correct driver:  2 REJECT, 4 ACCEPT, 8 ACCEPT, 12 ACCEPT.
//
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>

typedef uint64_t bsz;
struct fbo { uint32_t type; uint32_t flags; union { bsz binder; uint32_t handle; }; bsz cookie; };
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
#define BC_REPLY _IOW('c',1,struct btd)
#define BC_FREE_BUFFER _IOW('c',3,bsz)
#define BC_ENTER_LOOPER _IO('c',12)
#define BR_TRANSACTION _IOR('r',2,struct btd)
#define BR_REPLY _IOR('r',3,struct btd)
#define BR_DEAD_REPLY _IO('r',5)
#define BR_FAILED_REPLY _IO('r',17)
#define T_BINDER 0x73622a85
#define T_HANDLE 0x73682a85
#define MAPSZ (128*1024)

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

// server replies with one object at byte offset `off` inside the parcel
static int run_case(const char *dev, size_t off, int *why) {
    void *m1,*m2; int sv=openb(dev,&m1);
    if(sv<0){*why=1;return -1;}
    int32_t z=0;
    if(ioctl(sv,SETMGR,&z)<0){*why=2;close(sv);return -1;}
    int pfd[2]; if(pipe(pfd)){*why=3;close(sv);return -1;}
    pid_t c=fork();
    if(c==0){
        close(pfd[0]); char g; (void)!read(pfd[1],&g,0); close(pfd[1]);
        int cf=openb(dev,&m2); if(cf<0) _exit(70);
        static uint64_t ask; ask=0x1111;
        struct { uint32_t cmd; struct btd t; } __attribute__((packed)) o;
        memset(&o,0,sizeof o); o.cmd=BC_TRANSACTION; o.t.target.handle=0;
        o.t.code=0x2a; o.t.data_size=sizeof ask;
        o.t.data.ptr.buffer=(bsz)(uintptr_t)&ask;
        uint8_t rb[512]; size_t n=0; int rc=99;
        if(wr(cf,&o,sizeof o,rb,sizeof rb,&n)<0) _exit(71);
        for(int pass=0;pass<40;pass++){
            size_t i=0;
            while(i+4<=n){
                uint32_t cmd; memcpy(&cmd,rb+i,4); i+=4;
                if(cmd==BR_REPLY){ rc=0; break; }
                if(cmd==BR_FAILED_REPLY||cmd==BR_DEAD_REPLY){ rc=1; break; }
                if(cmd==BR_TRANSACTION||cmd==(uint32_t)_IOR('r',2,struct btd)) i+=sizeof(struct btd);
                else if(cmd==(uint32_t)_IOR('r',7,uint64_t[2])||cmd==(uint32_t)_IOR('r',8,uint64_t[2])) i+=16;
            }
            if(rc!=99) break;
            n=0; if(wr(cf,NULL,0,rb,sizeof rb,&n)<0) break;
        }
        _exit(rc==0?0:(rc==1?1:2));
    }
    close(pfd[1]);
    // serve one transaction, reply with the object at `off`
    uint32_t el=BC_ENTER_LOOPER; (void)wr(sv,&el,sizeof el,NULL,0,NULL);
    uint8_t rb[1024]; size_t n=0; int served=0;
    for(int pass=0; pass<60 && !served; pass++){
        n=0; if(wr(sv,NULL,0,rb,sizeof rb,&n)<0) break;
        size_t i=0;
        while(i+4<=n){
            uint32_t cmd; memcpy(&cmd,rb+i,4); i+=4;
            if(cmd==BR_TRANSACTION){
                struct btd t; memcpy(&t,rb+i,sizeof t); i+=sizeof t;
                static uint8_t parcel[64]; static bsz offs[1];
                memset(parcel,0,sizeof parcel);
                struct fbo ob; memset(&ob,0,sizeof ob);
                ob.type=T_BINDER; ob.flags=0x100;
                ob.binder=0xbeef4000; ob.cookie=0xbeef5000;
                memcpy(parcel+off,&ob,sizeof ob);
                offs[0]=off;
                struct { uint32_t cmd; struct btd t; } __attribute__((packed)) o;
                memset(&o,0,sizeof o); o.cmd=BC_REPLY;
                o.t.data_size=off+sizeof ob; o.t.offsets_size=sizeof offs;
                o.t.data.ptr.buffer=(bsz)(uintptr_t)parcel;
                o.t.data.ptr.offsets=(bsz)(uintptr_t)offs;
                struct { uint32_t cmd; bsz b; } __attribute__((packed)) fb;
                fb.cmd=BC_FREE_BUFFER; fb.b=t.data.ptr.buffer;
                uint8_t wbuf[sizeof o+sizeof fb];
                memcpy(wbuf,&fb,sizeof fb); memcpy(wbuf+sizeof fb,&o,sizeof o);
                (void)wr(sv,wbuf,sizeof wbuf,NULL,0,NULL);
                served=1; break;
            } else if(cmd==(uint32_t)_IOR('r',7,uint64_t[2])||cmd==(uint32_t)_IOR('r',8,uint64_t[2])) i+=16;
        }
    }
    int st=0; waitpid(c,&st,0);
    munmap(m1,MAPSZ); close(sv);
    *why=0;
    return WIFEXITED(st)?WEXITSTATUS(st):-2;
}

int main(int argc,char**argv){
    const char *dev = argc>1?argv[1]:"/dev/vndbinder";
    size_t offs_list[4]={2,4,8,12};
    for(int k=0;k<4;k++){ size_t off=offs_list[k];
        int why=0;
        pid_t p=fork();
        if(p==0){ int r=run_case(dev,off,&why); _exit(r<0?(50+why):r); }
        int st=0; waitpid(p,&st,0);
        int r=WIFEXITED(st)?WEXITSTATUS(st):-1;
        const char *verdict = r==0?"ACCEPT (BR_REPLY)":
                              r==1?"REJECT (BR_FAILED_REPLY)":"inconclusive";
        printf("object at offset %zu: %s   [raw=%d]%s\n", off, verdict, r,
               off==9999?"  (out of range: MUST reject if validation exists)":
               off==2?"  (MUST reject under any alignment rule)":"");
        fflush(stdout);
    }
    return 0;
}
