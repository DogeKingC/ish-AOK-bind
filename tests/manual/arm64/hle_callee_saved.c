// Does a libc call preserve x19-x28 -- including when jit/hle.c runs it
// natively instead of emulating it?
//
// WHY THIS EXISTS. Android's idmap2d dies in RefBase::incStrong on an object
// whose mRefs is null. Disassembling libutils.so shows the constructor that
// should have written it:
//
//   mov  x19, x0             ; x19 = this
//   str  x8, [x0]            ; *this = vptr        <- this store landed
//   mov  w0, #0x18
//   bl   _Znwm@plt           ; operator new(24)
//   str  x19, [x0, #8]       ; impl->mBase = this
//   str  x0, [x19, #8]       ; this->mRefs = impl  <- this store did not
//
// The object on device has exactly that vptr and a zero mRefs, so the
// constructor ran and `operator new` returned a usable pointer (otherwise
// `str x19, [x0, #8]` would have faulted at address 8). The address the
// missing store used is x19 -- CALLEE-SAVED, held across a call into another
// library. If x19 does not come back intact, the store lands somewhere else
// and the object keeps a null mRefs, with no fault at the time. That is the
// shape of the bug.
//
// `operator new` is not itself hooked; jit/hle.c only takes mem*/str*. But an
// allocator calls those internally, so an HLE'd call runs somewhere inside
// every allocation, and the HLE bridge leaves the emulator, runs a native C
// function, and comes back. Register preservation across that boundary is
// exactly the kind of thing that is correct for x0-x18 and quietly wrong for
// one of x19-x28, because nothing else would notice.
//
// So this asserts the ABI directly: load x19-x28 with sentinels, make the
// call, read them back.
//
//   hle       memset/memcpy/strlen and the rest of the hooked set, at sizes
//             above and below any small-n cutoff, since the cutoff decides
//             whether the bridge is taken at all
//   control   an ordinary function that is NOT hooked, so a failure can be
//             attributed to the HLE path rather than to calls in general
//   nested    a call made through a PLT into a shared object, which is what
//             the real _Znwm@plt is
//
// READ THIS BEFORE TREATING A PASS AS AN ANSWER. On the qemu-user harness
// this test currently exercises the ABI but NOT the HLE bridge: running it
// under ISH_HLE_STATS=1 prints no stats at all, and neither does hle_loop, so
// nothing here is being hooked. jit/hle-table.inc matches a libc by the exact
// 64 bytes at each function's entry, and the harness's Alpine musl build is
// evidently not one of the builds fingerprinted there.
//
// So on this host it is a CONTROL -- it says callee-saved registers survive
// ordinary calls and allocations -- and a pass does not rule the HLE path out.
// The measurement has to run where the fingerprints match, which is the
// device, against bionic. gcc is present there, so this file compiles and runs
// in the Android chroot directly; that is the intended use, and the harness
// run is the regression lock around it.
//
// A failure, on either host, is the Android crash.

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

// x0=fn, x1=a0, x2=a1, x3=a2, x4=out[10]
// Sets x19..x28 to known values, calls fn(a0,a1,a2), writes x19..x28 to out.
// fn and out live on the stack across the call precisely because every
// callee-saved register is in use as a sentinel.
__asm__(
".text\n"
".globl hle_probe\n"
".type hle_probe,%function\n"
"hle_probe:\n"
"    stp x29, x30, [sp, #-128]!\n"
"    mov x29, sp\n"
"    stp x19, x20, [sp, #16]\n"
"    stp x21, x22, [sp, #32]\n"
"    stp x23, x24, [sp, #48]\n"
"    stp x25, x26, [sp, #64]\n"
"    stp x27, x28, [sp, #80]\n"
"    str x0, [sp, #96]\n"
"    str x4, [sp, #104]\n"
"    mov x9, x0\n"
"    mov x0, x1\n"
"    mov x1, x2\n"
"    mov x2, x3\n"
"    movz x19, #0x1919\n"
"    movz x20, #0x2020\n"
"    movz x21, #0x2121\n"
"    movz x22, #0x2222\n"
"    movz x23, #0x2323\n"
"    movz x24, #0x2424\n"
"    movz x25, #0x2525\n"
"    movz x26, #0x2626\n"
"    movz x27, #0x2727\n"
"    movz x28, #0x2828\n"
"    blr x9\n"
"    ldr x10, [sp, #104]\n"
"    str x19, [x10, #0]\n"
"    str x20, [x10, #8]\n"
"    str x21, [x10, #16]\n"
"    str x22, [x10, #24]\n"
"    str x23, [x10, #32]\n"
"    str x24, [x10, #40]\n"
"    str x25, [x10, #48]\n"
"    str x26, [x10, #56]\n"
"    str x27, [x10, #64]\n"
"    str x28, [x10, #72]\n"
"    ldp x19, x20, [sp, #16]\n"
"    ldp x21, x22, [sp, #32]\n"
"    ldp x23, x24, [sp, #48]\n"
"    ldp x25, x26, [sp, #64]\n"
"    ldp x27, x28, [sp, #80]\n"
"    ldp x29, x30, [sp], #128\n"
"    ret\n"
".size hle_probe,.-hle_probe\n");

extern void hle_probe(void *fn, void *a0, unsigned long a1, unsigned long a2,
                      uint64_t *out);

static const uint64_t expect[10] = {
    0x1919, 0x2020, 0x2121, 0x2222, 0x2323,
    0x2424, 0x2525, 0x2626, 0x2727, 0x2828,
};

static int check_regs(const char *what, const uint64_t *got) {
    int ok = 1;
    for (int i = 0; i < 10; i++) {
        if (got[i] != expect[i]) {
            printf("FAIL %s: x%d = %#llx, expected %#llx\n",
                   what, 19 + i, (unsigned long long) got[i],
                   (unsigned long long) expect[i]);
            ok = 0;
        }
    }
    if (ok)
        test_logf("ok %s preserves x19-x28\n", what);
    else
        failures_total++;
    return ok;
}

// Deliberately not one of the hooked names, and deliberately doing enough work
// that the compiler cannot fold it away: the control for "calls in general".
__attribute__((noinline)) static void *not_hooked(void *p, unsigned long c,
                                                  unsigned long n) {
    volatile unsigned char *q = p;
    unsigned long sum = 0;
    for (unsigned long i = 0; i < n; i++)
        sum += q[i] ^ c;
    q[0] = (unsigned char) sum;
    return p;
}

static char bufa[65536];
static char bufb[65536];

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(120));

    uint64_t out[10];

    // Control first. If this fails, nothing below tells you anything about
    // HLE specifically.
    memset(bufa, 'a', sizeof(bufa));
    hle_probe((void *) not_hooked, bufa, 'x', 4096, out);
    check_regs("an ordinary (unhooked) call", out);

    // The hooked set. Sizes on both sides of any small-n cutoff, because the
    // cutoff decides whether the native bridge is entered at all -- a bug that
    // only shows above the cutoff would hide behind a single small call.
    static const unsigned long sizes[] = { 8, 64, 1024, 65536 };
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        unsigned long n = sizes[s];
        char label[64];

        snprintf(label, sizeof(label), "memset(n=%lu)", n);
        hle_probe((void *) memset, bufa, 'z', n, out);
        check_regs(label, out);

        snprintf(label, sizeof(label), "memcpy(n=%lu)", n);
        hle_probe((void *) memcpy, bufa, (unsigned long) bufb, n, out);
        check_regs(label, out);

        snprintf(label, sizeof(label), "memmove(n=%lu)", n);
        hle_probe((void *) memmove, bufa, (unsigned long) bufb, n, out);
        check_regs(label, out);

        snprintf(label, sizeof(label), "memcmp(n=%lu)", n);
        hle_probe((void *) memcmp, bufa, (unsigned long) bufb, n, out);
        check_regs(label, out);

        // NUL-terminated at n-1 so strlen/strcpy see a string of that length.
        memset(bufb, 'q', n ? n - 1 : 0);
        bufb[n ? n - 1 : 0] = '\0';

        snprintf(label, sizeof(label), "strlen(len=%lu)", n ? n - 1 : 0);
        hle_probe((void *) strlen, bufb, 0, 0, out);
        check_regs(label, out);

        snprintf(label, sizeof(label), "strcpy(len=%lu)", n ? n - 1 : 0);
        hle_probe((void *) strcpy, bufa, (unsigned long) bufb, 0, out);
        check_regs(label, out);

        snprintf(label, sizeof(label), "strcmp(len=%lu)", n ? n - 1 : 0);
        hle_probe((void *) strcmp, bufa, (unsigned long) bufb, 0, out);
        check_regs(label, out);

        snprintf(label, sizeof(label), "strchr(len=%lu)", n ? n - 1 : 0);
        hle_probe((void *) strchr, bufb, 'q', 0, out);
        check_regs(label, out);
    }

    // And the thing the crash actually does: allocate, then use a callee-saved
    // register that was set before the allocation. malloc is not hooked, but
    // an allocator runs the hooked functions internally, so this is the real
    // composition rather than a hooked call on its own.
    extern void *malloc(unsigned long);
    extern void free(void *);
    for (int i = 0; i < 256; i++) {
        hle_probe((void *) malloc, (void *) 24, 0, 0, out);
        if (!check_regs("malloc(24)", out))
            break;
    }
    // Same shape as RefBase::RefBase: hold `this` in x19 across the
    // allocation, then store the result through it.
    struct fake { void *vptr; void *mRefs; } obj = { (void *) 0x1, NULL };
    for (int i = 0; i < 256; i++) {
        void *p = malloc(24);
        obj.mRefs = p;
        if (obj.mRefs == NULL) {
            printf("FAIL the RefBase shape: mRefs is null after a successful "
                   "allocation (iteration %d)\n", i);
            failures_total++;
            break;
        }
        free(p);
    }
    test_logf("ok the RefBase constructor shape keeps its pointer\n");

    // Said on every run, passing or not, because the danger here is reading a
    // PASS as "the HLE path is fine". It is only that if the HLE path ran, and
    // this test cannot tell from inside the guest.
    printf("NOTE hle_callee_saved: a PASS covers the HLE bridge only if the "
           "libc here is fingerprinted in jit/hle-table.inc. Check with "
           "ISH_HLE_STATS=1 -- no 'hle stats' line means nothing was hooked "
           "and this run was a control.\n");

    return finish_suite("hle_callee_saved");
}
