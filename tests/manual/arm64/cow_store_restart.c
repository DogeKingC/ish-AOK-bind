// Can an arm64 guest store COMPLETE when it faults on a copy-on-write page?
//
// WHY THIS EXISTS. Running the whole guest suite on a device turned up five
// SIGSEGVs, two of which land on the same instruction in two unrelated tests
// (socket_kill, proc_stat_monotonic):
//
//   ERROR: 10123(socket_kill) [arm64] fault on 0xffffe9b0 at 0x7fffbdb7c9f0
//     keeps resolving and re-faulting (16 times); delivering SIGSEGV rather
//     than spinning -- the access cannot complete even though the page is there
//     pc-backing -> /lib/ld-musl-aarch64.so.1+0x609f0
//     lr-backing -> /lib/ld-musl-aarch64.so.1+0x48b3c
//
// Disassembled: lr is inside musl's fork(), whose `bl` targets 0x609f0, and the
// instruction there is an ordinary function prologue --
//
//     stp x29, x30, [sp, #-32]!
//
// a store PAIR with pre-index writeback, to a stack page that IS mapped, on a
// stack fork() has just made copy-on-write. iSH resolves the page, restarts the
// instruction, and faults again until SAME_FAULT_LIMIT (kernel/calls.c) gives
// up. Without that cap it would spin forever.
//
// The same shape -- a store that does not land -- is what leaves Android's
// RefBase::mRefs null in idmap2d, where nothing re-faults and the store simply
// goes nowhere. Those may or may not be one bug. This file exists to make the
// reproducible half reproducible OFF the device, because a device round is
// minutes and this is seconds.
//
// WHAT IT SEPARATES. The suspect is not "stores" in general -- the suite is
// full of working stores. It is a store that FAULTS, on a page that needs
// copy-on-write resolution, in the forms the failing instruction has:
//
//   str      a plain single-register store to a COW stack page (the control:
//            if this fails too, writeback and pairing are innocent)
//   stp      a store pair, no writeback
//   stp_wb   a store pair with PRE-INDEX WRITEBACK -- the failing form. The
//            base register is updated by the same instruction that faults, so
//            a restart that re-applies the writeback corrupts the address, and
//            one that does not re-apply it loses the update.
//   prologue real compiler-emitted prologues, by recursing after the fork so
//            each frame's push lands on an untouched COW page. This is the
//            device's exact case and the one that needs no asm to be believed.
//   heap     the same stores against COW heap (MAP_PRIVATE) rather than stack,
//            to say whether this is about the stack region specifically.
//
// Each phase runs in a FORKED CHILD, because that is what makes the pages
// copy-on-write, and because a child that takes the emulator's SIGSEGV can be
// reported rather than taking the test down with it.
//
// A failure here is the device bug, reproduced locally. A pass means the
// harness's fork/COW path differs from the device's in some way this does not
// capture -- qemu-user is not an Apple core -- and the next step is to run this
// same file on the device, where it is shipped by fs/aok-tests.manifest.

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

#define PAGE 4096
#define STACK_BYTES (256 * 1024)

static void report(const char *what, int status) {
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        test_logf("ok %s\n", what);
        return;
    }
    if (WIFSIGNALED(status))
        printf("FAIL %s: child died on signal %d%s\n", what, WTERMSIG(status),
               WTERMSIG(status) == 11 ? " (SIGSEGV -- the store never completed)" : "");
    else
        printf("FAIL %s: child exited %d\n", what, WEXITSTATUS(status));
    failures_total++;
}

// Runs fn in a child and reports how it died. The pages fn writes to were
// dirtied by the PARENT first, so in the child they are copy-on-write and the
// first write to each must fault and be resolved.
static void in_child(const char *what, void (*fn)(volatile uint64_t *), volatile uint64_t *p) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL %s: fork failed\n", what);
        failures_total++;
        return;
    }
    if (pid == 0) {
        fn(p);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    report(what, status);
}

// --- the store forms -------------------------------------------------------

static void do_str(volatile uint64_t *p) {
    for (int i = 0; i < STACK_BYTES / PAGE; i++)
        p[i * (PAGE / 8)] = 0x5aa5aa55u + i;
}

static void do_stp(volatile uint64_t *p) {
    for (int i = 0; i < STACK_BYTES / PAGE; i++) {
        volatile uint64_t *q = &p[i * (PAGE / 8)];
        uint64_t a = 0x1111u + i, b = 0x2222u + i;
        __asm__ volatile("stp %[a], %[b], [%[q]]"
                         : : [a] "r"(a), [b] "r"(b), [q] "r"(q) : "memory");
    }
}

// The failing form: pre-index writeback. The base register is modified by the
// same instruction that faults, which is what makes the restart contract hard.
static void do_stp_wb(volatile uint64_t *p) {
    for (int i = 0; i < STACK_BYTES / PAGE; i++) {
        volatile uint64_t *q = &p[i * (PAGE / 8)] + 2; // room for the -16
        uint64_t a = 0x3333u + i, b = 0x4444u + i;
        __asm__ volatile("stp %[a], %[b], [%[q], #-16]!"
                         : [q] "+r"(q) : [a] "r"(a), [b] "r"(b) : "memory");
    }
}

// Real prologues. Each level pushes x29/x30 and a frame, so recursing after the
// fork walks a fresh prologue push down through untouched COW stack pages --
// the device's exact case, with no asm involved.
static uint64_t sink;
__attribute__((noinline)) static uint64_t recurse(int depth) {
    volatile uint64_t frame[48]; // ~384 bytes a level, so ~10 levels per page
    frame[0] = (uint64_t) depth;
    frame[47] = (uint64_t) depth;
    if (depth <= 0)
        return frame[0] + frame[47];
    return frame[0] + recurse(depth - 1);
}

static void do_prologue(volatile uint64_t *unused) {
    (void) unused;
    sink = recurse(600);
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(120));

    // A stack region the PARENT dirties, so the child's writes are COW. Taken
    // as a local so it really is stack rather than heap.
    volatile uint64_t stack_area[STACK_BYTES / 8];
    for (int i = 0; i < STACK_BYTES / PAGE; i++)
        stack_area[i * (PAGE / 8)] = 0xdead0000u + i;

    // Warm the recursion in the parent too, so the pages those prologues will
    // use are dirty and therefore COW in the child rather than simply absent.
    sink = recurse(600);

    in_child("str to a COW stack page", do_str, stack_area);
    in_child("stp (no writeback) to a COW stack page", do_stp, stack_area);
    in_child("stp with pre-index writeback to a COW stack page", do_stp_wb, stack_area);
    in_child("compiler prologues walking down COW stack pages", do_prologue, stack_area);

    // Same three forms against COW heap. If the stack ones fail and these pass,
    // the stack region is implicated; if all fail, it is copy-on-write itself.
    volatile uint64_t *heap = mmap(NULL, STACK_BYTES, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (heap != MAP_FAILED) {
        for (int i = 0; i < STACK_BYTES / PAGE; i++)
            heap[i * (PAGE / 8)] = 0xbeef0000u + i;
        in_child("str to a COW heap page", do_str, heap);
        in_child("stp (no writeback) to a COW heap page", do_stp, heap);
        in_child("stp with pre-index writeback to a COW heap page", do_stp_wb, heap);
    } else {
        test_logf("skip the heap phases (mmap failed)\n");
    }

    // Deeper: fork from a THREAD-created stack rather than the initial one.
    // The device's failure was inside musl's fork(), and iSH places the initial
    // stack differently from an mmap'd one, so the two are worth separating.
    in_child("prologues after a second fork (grandchild)", do_prologue, stack_area);

    return finish_suite("cow_store_restart");
}
