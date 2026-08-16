// Does every arm64 guest thread get its OWN stack and its OWN TLS?
//
// WHY THIS EXISTS. Android's idmap2d and installd both die on device with a
// null dereference that cannot happen in correct code:
//
//   ERROR: 2981(binder:2981_2) [arm64] page fault on 0x4 at ... (write)
//     x19=0 x20=0x7ffd33224ba8 ... sp=0xffffe7f0 tpidr=0x7fffbcd11d40
//     pc-backing ...: /system/lib64/libutils.so
//
// Disassembling libutils.so at the faulting offset names the function exactly:
// android::RefBase::incStrong(), doing `x19 = this->mRefs; x1 = x19 + 4;
// ldadd w0, w0, [x1]` -- an atomic increment of mRefs->mWeak. `mRefs` is a
// `weakref_impl* const` assigned in RefBase's constructor, so a constructed
// object can never have it null. `this` (x20) was a perfectly plausible
// pointer; only the field read back as zero.
//
// A field of a live object reading zero is memory corruption, and in a fresh
// binder POOL thread the two cheapest ways to corrupt everything at once are
// for threads to share a stack or to share a thread pointer. Two things in
// that register block point that way: sp was ~0xffffe800 (the region iSH puts
// the INITIAL stack in, not an mmap'd pthread stack), and tpidr was byte
// identical -- 0x7fffbcd11d40 -- across three separate runs of two different
// programs, while every other address was randomized.
//
// That is suggestive, not conclusive, which is the whole point of this file.
// Nothing above proves the emulator is at fault; a wrong guess here costs a
// device round trip, and this costs none. So it asserts the invariants
// directly, on the arm64 engine, under the local harness:
//
//   distinct    every thread's stack, thread pointer, and __thread storage
//               are its own -- no two threads share any of them
//   consistent  within one thread the thread pointer does not move, and
//               __thread storage stays at a fixed address relative to it
//   private     a value written to __thread storage before a barrier is
//               still there after every other thread has written its own
//   disjoint    no thread's stack pointer sits inside another thread's
//               reported stack range
//   refcount    the concrete pattern from the crash: many threads hammering
//               a shared refcount through the SAME outline-atomics helper
//               (__aarch64_ldadd4_relax) that faulted, with a per-thread
//               object whose "constructor" store must stay visible
//
// A failure here is the Android crash's cause. A pass rules the whole class
// out on this host and sends the next look back to the guest side -- which is
// worth just as much, because "the emulator is fine here" is the half of the
// answer that is otherwise never established.

// pthread_getattr_np is gated behind _GNU_SOURCE in musl. Without it the call
// compiles to an implicit declaration on a lax compiler and the stack bounds
// come back as garbage -- the same shape of silent miss that made
// F_SETPIPE_SZ's forwarding vanish (fs/fd.c), so it is spelled out here.
#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define NTHREADS 8

static void check(int cond, const char *what) {
    if (!cond)
        printf("FAIL %s\n", what);
    else
        test_logf("ok %s\n", what);
    if (!cond)
        failures_total++;
}

// Read TPIDR_EL0 directly. __builtin_thread_pointer() is not available on
// every clang that builds these, and the register is the thing under test, so
// read the register.
static inline uintptr_t thread_pointer(void) {
    uintptr_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return tp;
}

// Deliberately not initialized to a constant the loader could share: each
// thread writes its own id here and must read that id back.
static __thread volatile uint64_t tls_slot;
static __thread volatile uint64_t tls_guard;

// The shape RefBase has: a vtable-sized word, then a pointer set once at
// "construction" and never written again, then the counters the atomic helper
// touches. If a constructor store can go missing, this is where it shows.
struct fake_refbase {
    void *vptr;
    struct fake_counters *refs; // like RefBase::mRefs, written once
    uint64_t pad;
};

struct fake_counters {
    volatile int32_t strong; // offset 0, as in weakref_impl
    volatile int32_t weak;   // offset 4 -- the address that faulted
};

struct thread_result {
    uintptr_t tp;
    uintptr_t tls_addr;
    uintptr_t stack_local;
    uintptr_t stack_lo, stack_hi;
    uint64_t tls_readback;
    int tp_moved;
    int refs_null;
    int refs_wrong;
};

static struct thread_result results[NTHREADS];
static pthread_barrier_t barrier;
static struct fake_counters shared_counters;

static void *thread_main(void *arg) {
    long idx = (long) arg;
    struct thread_result *r = &results[idx];
    volatile char stack_probe = (char) idx;

    r->tp = thread_pointer();
    r->stack_local = (uintptr_t) &stack_probe;
    r->tls_addr = (uintptr_t) &tls_slot;

    // Where this thread's stack actually is, as the runtime understands it.
    pthread_attr_t attr;
    void *base = NULL;
    size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &attr) == 0) {
        if (pthread_attr_getstack(&attr, &base, &size) == 0) {
            r->stack_lo = (uintptr_t) base;
            r->stack_hi = (uintptr_t) base + size;
        }
        pthread_attr_destroy(&attr);
    }

    // Construct a per-thread object on this thread's stack, then make every
    // thread do so before anyone reads: that is the crash's timing, a pool
    // thread constructing while its siblings are starting.
    struct fake_counters counters = { .strong = 0, .weak = 0 };
    struct fake_refbase obj;
    obj.vptr = (void *) 0x1;
    obj.refs = &counters; // the "constructor" store
    obj.pad = 0;

    tls_slot = 0xA5A50000u + (uint64_t) idx;
    tls_guard = 0x5A5A0000u + (uint64_t) idx;

    pthread_barrier_wait(&barrier);

    // Everyone has now written their own TLS and their own object. If any of
    // that storage is shared, these three reads are where it surfaces.
    r->tls_readback = tls_slot;
    r->tp_moved = thread_pointer() != r->tp;
    r->refs_null = obj.refs == NULL;
    r->refs_wrong = obj.refs != &counters;

    // Now the exact operation that faulted: a relaxed atomic add on the field
    // at offset 4 of the pointed-to object, via the outline-atomics helper,
    // from many threads at once. Both a shared refcount and a per-thread one,
    // because the crash's object was per-thread but reached through a pointer.
    for (int i = 0; i < 2000; i++) {
        __atomic_fetch_add(&obj.refs->weak, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&obj.refs->strong, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&shared_counters.weak, 1, __ATOMIC_RELAXED);
        // Re-read through the pointer every iteration: a lost store to
        // obj.refs would show up as a null deref here, exactly as on device.
        if (obj.refs == NULL) {
            r->refs_null = 1;
            break;
        }
    }
    if (obj.refs == &counters && (counters.weak != 2000 || counters.strong != 2000))
        r->refs_wrong = 1;

    // And the TLS is still ours after all that traffic.
    if (tls_slot != 0xA5A50000u + (uint64_t) idx ||
        tls_guard != 0x5A5A0000u + (uint64_t) idx)
        r->tls_readback = 0; // flagged by the caller

    return NULL;
}

static int all_distinct(const char *what, uintptr_t (*get)(int), int allow_zero) {
    int ok = 1;
    for (int i = 0; i < NTHREADS; i++) {
        uintptr_t a = get(i);
        if (a == 0) {
            if (!allow_zero) {
                printf("  %s: thread %d reported 0\n", what, i);
                ok = 0;
            }
            continue;
        }
        for (int j = i + 1; j < NTHREADS; j++) {
            if (get(j) == a) {
                printf("  %s: threads %d and %d SHARE %#lx\n",
                       what, i, j, (unsigned long) a);
                ok = 0;
            }
        }
    }
    return ok;
}

static uintptr_t get_tp(int i) { return results[i].tp; }
static uintptr_t get_tls(int i) { return results[i].tls_addr; }
static uintptr_t get_stack(int i) { return results[i].stack_local; }

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    pthread_barrier_init(&barrier, NULL, NTHREADS);

    pthread_t th[NTHREADS];
    int created = 0;
    for (long i = 0; i < NTHREADS; i++) {
        if (pthread_create(&th[i], NULL, thread_main, (void *) i) != 0)
            break;
        created++;
    }
    check(created == NTHREADS, "all threads created");
    if (created != NTHREADS) {
        // Without every thread the barrier never releases; do not hang.
        printf("SKIP thread_identity: only %d of %d threads started\n",
               created, NTHREADS);
        return finish_suite("thread_identity");
    }
    for (int i = 0; i < NTHREADS; i++)
        pthread_join(th[i], NULL);

    for (int i = 0; i < NTHREADS; i++)
        test_logf("thread %d: tp=%#lx tls=%#lx sp~%#lx stack=[%#lx,%#lx)\n",
                  i, (unsigned long) results[i].tp,
                  (unsigned long) results[i].tls_addr,
                  (unsigned long) results[i].stack_local,
                  (unsigned long) results[i].stack_lo,
                  (unsigned long) results[i].stack_hi);

    check(all_distinct("thread pointer", get_tp, 0),
          "every thread has its own TPIDR_EL0");
    check(all_distinct("__thread storage", get_tls, 0),
          "every thread has its own __thread storage");
    check(all_distinct("stack", get_stack, 0),
          "every thread has its own stack");

    // A stack pointer landing inside another thread's declared stack is the
    // sharper form of the same bug, and catches the case where two stacks
    // merely overlap rather than coincide exactly.
    int disjoint = 1;
    for (int i = 0; i < NTHREADS; i++) {
        for (int j = 0; j < NTHREADS; j++) {
            if (i == j || results[j].stack_hi == 0)
                continue;
            if (results[i].stack_local >= results[j].stack_lo &&
                results[i].stack_local < results[j].stack_hi) {
                printf("  thread %d's sp %#lx is inside thread %d's stack "
                       "[%#lx,%#lx)\n", i, (unsigned long) results[i].stack_local,
                       j, (unsigned long) results[j].stack_lo,
                       (unsigned long) results[j].stack_hi);
                disjoint = 0;
            }
        }
    }
    check(disjoint, "no thread's stack pointer is inside another's stack");

    int tp_stable = 1, tls_private = 1, refs_ok = 1;
    for (int i = 0; i < NTHREADS; i++) {
        if (results[i].tp_moved)
            tp_stable = 0;
        if (results[i].tls_readback != 0xA5A50000u + (uint64_t) i)
            tls_private = 0;
        if (results[i].refs_null || results[i].refs_wrong)
            refs_ok = 0;
    }
    check(tp_stable, "TPIDR_EL0 does not change under a thread's feet");
    check(tls_private,
          "a value written to __thread storage survives every other thread "
          "writing its own");
    // The crash's exact shape: the pointer a "constructor" stored must still
    // be there when the atomic helper dereferences it.
    check(refs_ok,
          "a once-written object pointer is still valid after concurrent "
          "relaxed atomics through it (the RefBase::incStrong shape)");

    // Every thread added 2000; the total pins the atomic helper itself.
    check(shared_counters.weak == NTHREADS * 2000,
          "concurrent relaxed atomic adds do not lose updates");
    if (shared_counters.weak != NTHREADS * 2000)
        printf("  shared counter = %d, expected %d\n",
               (int) shared_counters.weak, NTHREADS * 2000);

    return finish_suite("thread_identity");
}
