// The PARENT's own stack, in the window just after clone() returns.
//
// WHY THIS EXISTS. On a device, socket_kill and proc_stat_monotonic both die at
// the same instruction, and the full register block (via
// /proc/ish/arm64_faultdump) says exactly where:
//
//   ERROR: 1888(socket_kill) [arm64] fault on 0xffffe9b0 at ...+0x609f0 keeps
//     resolving and re-faulting (16 times); delivering SIGSEGV rather than
//     spinning -- the access cannot complete even though the page is there
//     x8=0x87  x22=0x775  x29=0xffffe9d0  x30=...+0x48b3c  sp=0xffffe9d0
//
//   ...+0x609f0:  stp x29, x30, [sp, #-32]!
//   ...+0x48b3c:  tbnz w22, #31            (inside musl's fork)
//
// The fault address is sp-0x20 -- the prologue push itself. x22 is 1909, a
// plausible pid, and the return address lands on the `tbnz w22, #31` that
// checks for a negative clone() return. So this is the PARENT, just back from
// clone with the child's pid, pushing a NEW frame below sp. x8 still holds 135
// (rt_sigprocmask) from musl's signal juggling around the fork.
//
// tests/manual/arm64/cow_store_restart.c already ruled out the obvious reading:
// a child writing copy-on-write pages completes every store form correctly,
// stack and heap, including stp with pre-index writeback and real prologues.
// It passes on the device. So the trigger is not COW and not the store form.
//
// What this file varies instead is the PARENT's situation around the fork,
// because that is what the register block points at and what socket_kill (8
// forks, 12 kills) actually does:
//
//   plain      fork, and in the parent immediately push new frames below the
//              pre-clone sp. The baseline: if this alone reproduces, nothing
//              about signals matters.
//   reaped     the same, but the child is SIGKILLed at once, so SIGCHLD lands
//              on the parent while it is pushing. This is socket_kill's shape.
//   blocked    signals blocked across the fork and restored after, the way
//              musl's fork does it -- the state x8=rt_sigprocmask records.
//   handler    a real SIGCHLD handler installed, so the arriving signal runs
//              guest code on that same stack rather than being ignored.
//   many       eight live children killed together, which is the count
//              socket_kill uses and the point where several deaths race one
//              parent.
//
// Every phase pushes below the sp that was current when clone returned, in a
// loop, on the initial stack near 0xffffe000 -- all three properties the
// failing case has.
//
// A failure here reproduces the device bug locally, and the search then belongs
// in the fork path's handling of the parent's memory (kernel/fork.c,
// mem_ptr_fault's writable resolution) rather than in the store gadgets, which
// are now known good. A pass narrows it further: it would mean the parent-side
// fork window is fine on its own and something socket_kill does BEFORE forking
// (it is a socket test -- blocking waits in accept/recv) is part of the setup.

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

#define ROUNDS 40
#define KIDS 8

static volatile sig_atomic_t sigchld_seen;
static void on_sigchld(int sig) { (void) sig; sigchld_seen++; }

// Pushes frames below the caller's sp. noinline and a live volatile frame so
// the prologue really is `stp x29, x30, [sp, #-N]!` plus a frame, and the
// compiler cannot turn it into a leaf.
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

// One round: fork, and in the PARENT push new frames immediately, before doing
// anything else. `kill_at_once` makes the child die while the parent pushes.
static int fork_round(int kill_at_once, int depth) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        // The child does nothing interesting; it exists to make the parent's
        // pages shared and to be a corpse for the parent to reap.
        _exit(0);
    }
    if (kill_at_once)
        kill(pid, SIGKILL);
    // THE WINDOW. Straight back from clone, push below the sp that was live
    // when it returned.
    sink += push_frames(depth);
    int status = 0;
    waitpid(pid, &status, 0);
    return 0;
}

static int phase_plain(void) {
    for (int i = 0; i < ROUNDS; i++)
        if (fork_round(0, 60) != 0)
            return -1;
    return 0;
}

static int phase_reaped(void) {
    for (int i = 0; i < ROUNDS; i++)
        if (fork_round(1, 60) != 0)
            return -1;
    return 0;
}

static int phase_blocked(void) {
    for (int i = 0; i < ROUNDS; i++) {
        sigset_t all, old;
        sigfillset(&all);
        // musl blocks everything across the fork and restores after; the
        // restore is the call whose prologue faulted on device.
        sigprocmask(SIG_BLOCK, &all, &old);
        int rc = fork_round(1, 60);
        sigprocmask(SIG_SETMASK, &old, NULL);
        if (rc != 0)
            return -1;
    }
    return 0;
}

static int phase_handler(void) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, &old);
    int rc = 0;
    for (int i = 0; i < ROUNDS && rc == 0; i++)
        rc = fork_round(1, 60);
    sigaction(SIGCHLD, &old, NULL);
    return rc;
}

// socket_kill's shape: several live children, killed together, while the parent
// is pushing frames.
static int phase_many(void) {
    for (int round = 0; round < ROUNDS / 4; round++) {
        pid_t kids[KIDS];
        int n = 0;
        for (int i = 0; i < KIDS; i++) {
            pid_t pid = fork();
            if (pid < 0)
                break;
            if (pid == 0) {
                pause();      // stay alive until killed
                _exit(0);
            }
            kids[n++] = pid;
            // Push in the parent between every clone, not just after the last.
            sink += push_frames(40);
        }
        for (int i = 0; i < n; i++)
            kill(kids[i], SIGKILL);
        sink += push_frames(60);
        for (int i = 0; i < n; i++) {
            int status = 0;
            waitpid(kids[i], &status, 0);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(180));

    // Warm the depth once so the pages exist and are dirty: the device's case
    // is a page that is PRESENT, not one that is missing.
    sink = push_frames(60);

    check(phase_plain() == 0, "fork, then push new frames in the parent");
    check(phase_reaped() == 0, "...with the child SIGKILLed while pushing");
    check(phase_blocked() == 0, "...with signals blocked across the fork, musl-style");
    check(phase_handler() == 0, "...with a real SIGCHLD handler running on that stack");
    check(phase_many() == 0, "...eight children killed together, socket_kill's shape");

    test_logf("sigchld_seen=%d sink=%llu\n", (int) sigchld_seen,
              (unsigned long long) sink);
    return finish_suite("fork_parent_store");
}
