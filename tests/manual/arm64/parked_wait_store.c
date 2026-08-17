// A store in the parent, after children were killed out of a BLOCKING SOCKET
// WAIT rather than out of pause().
//
// WHY THIS EXISTS. Five tests SIGSEGV on a device -- socket_kill, accept_kill,
// clone_error_cleanup, fifo_open_creat_deadlock, concurrent_exec_tlb -- and
// reading all five fault blocks shows one bug, not five: identical pc
// (musl+0x609f0, `stp x29, x30, [sp, #-32]!`), identical lr (musl+0x48b3c,
// inside fork), fault address sp-0x20 every time, and every one reporting
//
//     keeps resolving and re-faulting (16 times) ... the access cannot
//     complete even though the page is there
//
// Two repros already failed to reproduce it on that same device, and each
// eliminated something worth eliminating:
//
//   cow_store_restart.c   every store form -- str, stp, stp with pre-index
//                         writeback, real prologues -- completes correctly on
//                         copy-on-write stack AND heap. Not the store, not COW.
//   fork_parent_store.c   the parent pushing new frames below the pre-clone sp,
//                         200+ forks across five shapes including children
//                         SIGKILLed mid-push. Not the fork window either.
//
// What fork_parent_store parked its children in was pause(). That is the gap
// this file closes. The failing tests park children in a BLOCKING SOCKET WAIT,
// and in iSH that is a different machine entirely: socket_wait_ready() and
// socket_blocking_syscall_begin() block SIGUSR1, arm the sigunwind_start()
// point, re-check for a pending guest signal, then sleep in a HOST wait. Killing
// a task parked there does not simply return from a syscall -- it pokes the
// host thread with SIGUSR1 and unwinds it out of the host wait, restoring guest
// context on the way. socket_kill.c's own header is about that machinery.
//
// A path that leaves a host wait and restores guest context is exactly the kind
// that can come back with a stale software TLB while mem_ptr_fault still
// reports the page present and writable -- which is the contradiction the log
// states outright.
//
// So: park children in recv(), kill them, and have the PARENT store afterwards.
//
//   parked_recv   children blocked in recv() on AF_UNIX, SIGKILLed, parent
//                 pushes frames immediately after each fork and after the kill
//   parked_tcp    the same over TCP, since the two take different paths in
//                 fs/sock.c
//   parked_accept children blocked in accept(2) -- the case accept_kill covers,
//                 and the one whose wait used to call host poll() bare
//   control_pause the same shape with pause() instead of a socket wait. It is
//                 the phase that already passes, kept here so a failure above
//                 can be attributed to the socket wait rather than to killing
//                 children in general.
//
// A failure here is the device bug, reproduced, with the ingredient named.

#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

#define KIDS 8
#define ROUNDS 12

enum park { PARK_RECV_UNIX, PARK_RECV_TCP, PARK_ACCEPT, PARK_PAUSE };

static uint64_t sink;

__attribute__((noinline)) static uint64_t push_frames(int depth) {
    volatile uint64_t frame[40];
    frame[0] = (uint64_t) depth;
    frame[39] = (uint64_t) depth;
    if (depth <= 0)
        return frame[0] + frame[39];
    return frame[39] + push_frames(depth - 1);
}

static void check(int cond, const char *what) {
    if (!cond)
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
    else
        test_logf("ok %s\n", what);
    if (!cond)
        failures_total++;
}

// A socket the child will block on. Returns -1 if this kind cannot be set up,
// which is a skip rather than a failure: the point is the wait, not the socket.
static int make_parked_fd(enum park kind) {
    if (kind == PARK_RECV_UNIX) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
            return -1;
        // The child recv()s on sv[0]; nothing is ever sent, so it parks.
        close(sv[1]);
        return sv[0];
    }
    if (kind == PARK_RECV_TCP || kind == PARK_ACCEPT) {
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        if (ls < 0)
            return -1;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (bind(ls, (struct sockaddr *) &a, sizeof(a)) != 0 || listen(ls, 8) != 0) {
            close(ls);
            return -1;
        }
        if (kind == PARK_ACCEPT)
            return ls; // the child blocks in accept() on it
        socklen_t alen = sizeof(a);
        if (getsockname(ls, (struct sockaddr *) &a, &alen) != 0) {
            close(ls);
            return -1;
        }
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (c < 0 || connect(c, (struct sockaddr *) &a, sizeof(a)) != 0) {
            if (c >= 0) close(c);
            close(ls);
            return -1;
        }
        close(ls);
        return c; // the child recv()s on a connected TCP socket that stays idle
    }
    return -2; // PARK_PAUSE needs no fd
}

static void child_park(enum park kind, int fd) {
    char buf[64];
    switch (kind) {
        case PARK_ACCEPT: {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            accept(fd, (struct sockaddr *) &peer, &plen);
            break;
        }
        case PARK_PAUSE:
            pause();
            break;
        default:
            recv(fd, buf, sizeof(buf), 0);
            break;
    }
    _exit(0);
}

static int run_phase(enum park kind) {
    for (int r = 0; r < ROUNDS; r++) {
        pid_t kids[KIDS];
        int fds[KIDS];
        int n = 0;
        for (int i = 0; i < KIDS; i++) {
            int fd = make_parked_fd(kind);
            if (fd == -1)
                return -2; // cannot set this kind up at all
            pid_t pid = fork();
            if (pid < 0) {
                if (fd >= 0) close(fd);
                break;
            }
            if (pid == 0) {
                child_park(kind, fd);
                _exit(0);
            }
            fds[n] = fd;
            kids[n] = pid;
            n++;
            // Store in the parent between clones, as the failing case does.
            sink += push_frames(40);
        }
        // Give the children time to actually reach the wait; killing one that
        // has not parked yet tests nothing.
        usleep(30000);
        for (int i = 0; i < n; i++)
            kill(kids[i], SIGKILL);
        // THE STORE UNDER TEST: the parent pushes frames while eight tasks are
        // being unwound out of host waits.
        sink += push_frames(60);
        for (int i = 0; i < n; i++) {
            int status = 0;
            waitpid(kids[i], &status, 0);
            if (fds[i] >= 0)
                close(fds[i]);
            sink += push_frames(20);
        }
    }
    return 0;
}

static void phase(const char *what, enum park kind) {
    int rc = run_phase(kind);
    if (rc == -2) {
        printf("SKIP %s: could not set up the socket\n", what);
        return;
    }
    check(rc == 0, what);
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(test_watchdog_secs(300));
    signal(SIGPIPE, SIG_IGN);

    sink = push_frames(60); // warm the depth: the page must be present

    // The control first. It is the shape fork_parent_store already proved good,
    // so if it fails here the run says nothing about socket waits.
    phase("control: children killed out of pause()", PARK_PAUSE);

    phase("children killed out of recv() on AF_UNIX", PARK_RECV_UNIX);
    phase("children killed out of recv() on TCP", PARK_RECV_TCP);
    phase("children killed out of accept()", PARK_ACCEPT);

    test_logf("sink=%llu\n", (unsigned long long) sink);
    return finish_suite("parked_wait_store");
}
