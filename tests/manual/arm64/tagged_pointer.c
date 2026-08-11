// tagged_pointer.c — AArch64 Top Byte Ignore (TBI) on guest pointers.
//
// AArch64 discards bits 56-63 of a data address on dereference. That is not
// an exotic corner: bionic's Scudo puts a heap tag there on every allocation
// (the TBI tagging level, which needs no MTE hardware and is on regardless of
// AT_HWCAP2), so under Android essentially every pointer libc touches is
// tagged. An emulator that treats the tag as part of the address rejects an
// otherwise perfectly good pointer.
//
// The bug this pins: the tag was stripped in exactly one place, the JIT's
// read_prep/write_prep TLB fast path (jit/guest-arm64/gadgets.h), and nowhere
// else. Every arm64 Android process died the same way -- the first tagged
// memset in libc's startup:
//
//   page fault on 0x2007ffec608f980 at 0x7fffbb084a80 (write)
//   x0=0x2007ffec608f980 ... x28=0x7ffec608f980     <- same address, untagged
//   pc-backing: /system/lib64/bootstrap/libc.so
//
// A 2^48 range check rejects a tagged address (it is ~500x over the limit)
// while the untagged one is comfortably inside, so the symptom is SEGV_MAPERR
// on an address that is genuinely mapped.
//
// Covered:
//   scalar      load/store of every width through a tagged pointer.
//   bulk        memset/memcpy at sizes that reach the SIMD pair stores --
//               the exact shape of the libc startup failure.
//   crosspage   a tagged access straddling a page boundary, which takes the
//               gadget's slow path rather than the TLB fast path.
//   atomics     LDXR/STXR and __sync builtins through a tagged pointer.
//   syscalls    a tagged buffer and a tagged pathname handed to the kernel.
//               Gated: real Linux only accepts these once the tagged-address
//               ABI is enabled by prctl, so this section is skipped rather
//               than failed where that prctl is unavailable.
//
// Passes on real arm64 Linux and on fixed iSH. Exits non-zero on any failure.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include "test_common.h"

#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#endif
#ifndef PR_TAGGED_ADDR_ENABLE
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#endif

// An arbitrary non-zero tag. 0x02 is what the device dump above carried, but
// nothing depends on the value -- any of the 256 is equally legal, and the
// point is only that the top byte is not zero.
#define TAG 0x02

static void *tag_ptr(void *p) {
    uintptr_t v = (uintptr_t) p;
    // A guest pointer must arrive untagged, or the test is not testing what
    // it thinks it is.
    if ((v >> 56) != 0) {
        printf("FAIL pointer %p already carries a tag; cannot tag it\n", p);
        failures_total++;
        return p;
    }
    return (void *) (v | ((uintptr_t) TAG << 56));
}

static void checkf(int cond, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (!cond) {
        printf("FAIL ");
        vprintf(fmt, ap);
        printf("\n");
        failures_total++;
    } else if (test_verbose) {
        printf("ok ");
        vprintf(fmt, ap);
        printf("\n");
    }
    va_end(ap);
}

// Announced BEFORE the operation, and flushed. This test's failure mode is a
// fatal signal, so a line printed after an operation is lost precisely when
// it is the one you need: the last `-> ` line names the thing that crashed.
static void step(const char *fmt, ...) {
    if (!test_verbose)
        return;
    va_list ap;
    va_start(ap, fmt);
    printf("-> ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s\n", what);
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

// One page, untagged, for the sections that need real memory.
static char *page;
static size_t page_size;

// ---------------------------------------------------------------------------

static void test_scalar(void) {
    volatile uint8_t  *p8  = tag_ptr(page);
    volatile uint16_t *p16 = tag_ptr(page + 8);
    volatile uint32_t *p32 = tag_ptr(page + 16);
    volatile uint64_t *p64 = tag_ptr(page + 24);

    step("8-bit store to tagged %p", (void *) p8);
    *p8 = 0xa5;
    step("16-bit store to tagged %p", (void *) p16);
    *p16 = 0x1234;
    step("32-bit store to tagged %p", (void *) p32);
    *p32 = 0xdeadbeef;
    step("64-bit store to tagged %p", (void *) p64);
    *p64 = 0x0123456789abcdefULL;
    step("reading the four back through the untagged page");

    // Read back through the UNtagged mapping: the tag must not have changed
    // which bytes were written.
    check(*(uint8_t *) (page + 0) == 0xa5, "8-bit store through a tagged pointer");
    check(*(uint16_t *) (page + 8) == 0x1234, "16-bit store through a tagged pointer");
    check(*(uint32_t *) (page + 16) == 0xdeadbeef, "32-bit store through a tagged pointer");
    check(*(uint64_t *) (page + 24) == 0x0123456789abcdefULL,
          "64-bit store through a tagged pointer");

    step("8-bit load from tagged %p", (void *) p8);
    check(*p8 == 0xa5, "8-bit load through a tagged pointer");
    step("64-bit load from tagged %p", (void *) p64);
    check(*p64 == 0x0123456789abcdefULL, "64-bit load through a tagged pointer");
}

// The failing case on the device. Sizes chosen to walk every branch of a
// SIMD memset: under 16 bytes, exactly the pair-store width, and past the
// point where it loops.
static void test_bulk(void) {
    static const size_t sizes[] = {1, 8, 15, 16, 17, 32, 64, 128, 1024, 4000};

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        size_t n = sizes[i];
        memset(page, 0, page_size);

        step("memset(tagged %p, 0x5a, %zu)", tag_ptr(page), n);
        memset(tag_ptr(page), 0x5a, n);
        int ok = 1;
        for (size_t j = 0; j < n; j++)
            if ((unsigned char) page[j] != 0x5a)
                ok = 0;
        // Nothing past the length may have been touched.
        if (n < page_size && (unsigned char) page[n] != 0)
            ok = 0;
        checkf(ok, "memset(tagged, 0x5a, %zu)", n);
    }

    char *src = page;
    char *dst = page + page_size / 2;
    for (size_t i = 0; i < page_size / 2; i++)
        src[i] = (char) (i * 7 + 1);

    step("memcpy(tagged, tagged, %zu)", page_size / 2);
    memcpy(tag_ptr(dst), tag_ptr(src), page_size / 2);
    check(memcmp(dst, src, page_size / 2) == 0, "memcpy between two tagged pointers");
}

// A tagged access that straddles a page boundary leaves the TLB fast path for
// the gadget's crosspage helper -- a different route to the same memory, and
// one the single mask in read_prep/write_prep does not obviously cover.
static void test_crosspage(void) {
    size_t len = page_size * 2;
    char *region = mmap(NULL, len, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        printf("FAIL cannot map a two-page region (errno=%d %s)\n", errno, strerror(errno));
        failures_total++;
        return;
    }
    memset(region, 0, len);

    // Straddle the boundary by 4 bytes either side.
    uint64_t *straddle = (uint64_t *) (region + page_size - 4);
    volatile uint64_t *tagged = tag_ptr(straddle);
    step("page-straddling 64-bit store to tagged %p", (void *) tagged);
    *tagged = 0xcafef00dd00dfeedULL;
    check(*straddle == 0xcafef00dd00dfeedULL, "page-straddling store through a tagged pointer");
    check(*tagged == 0xcafef00dd00dfeedULL, "page-straddling load through a tagged pointer");

    // And a bulk copy across the boundary.
    step("page-straddling memset through a tagged pointer");
    memset(tag_ptr(region + page_size - 64), 0x33, 128);
    int ok = 1;
    for (size_t i = 0; i < 128; i++)
        if ((unsigned char) region[page_size - 64 + i] != 0x33)
            ok = 0;
    check(ok, "page-straddling memset through a tagged pointer");

    munmap(region, len);
}

static void test_atomics(void) {
    uint64_t *slot = (uint64_t *) page;
    *slot = 0;
    uint64_t *tagged = tag_ptr(slot);

    // LDXR/STXR and the LSE forms both land here depending on the compiler.
    step("atomic store to tagged %p", (void *) tagged);
    __atomic_store_n(tagged, 100, __ATOMIC_SEQ_CST);
    check(*slot == 100, "atomic store through a tagged pointer");
    check(__atomic_load_n(tagged, __ATOMIC_SEQ_CST) == 100,
          "atomic load through a tagged pointer");
    step("atomic fetch-add on tagged %p", (void *) tagged);
    check(__atomic_fetch_add(tagged, 5, __ATOMIC_SEQ_CST) == 100,
          "atomic fetch-add through a tagged pointer");
    check(*slot == 105, "atomic fetch-add landed on the right address");

    uint64_t expected = 105;
    check(__atomic_compare_exchange_n(tagged, &expected, 7, 0,
                                      __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST),
          "compare-exchange through a tagged pointer");
    check(*slot == 7, "compare-exchange landed on the right address");
}

// Handing a tagged pointer to the kernel is a separate contract from
// dereferencing one: on real Linux it needs the tagged-address ABI turned on,
// and the kernel returns EFAULT otherwise. So this section reports what the
// platform does rather than insisting on one answer -- except that a kernel
// which ACCEPTED the pointer must also have used the right address.
static void test_syscalls(void) {
    if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) != 0) {
        test_logf("skip syscall section: no tagged-address ABI (errno=%d)\n", errno);
        return;
    }

    int fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) {
        printf("FAIL cannot open /dev/zero (errno=%d %s)\n", errno, strerror(errno));
        failures_total++;
        return;
    }
    memset(page, 0xff, 64);
    step("read() into tagged %p", tag_ptr(page));
    ssize_t n = read(fd, tag_ptr(page), 64);
    close(fd);

    if (n < 0) {
        printf("FAIL read() into a tagged buffer failed (errno=%d %s) even though the "
               "tagged-address ABI is enabled\n", errno, strerror(errno));
        failures_total++;
        return;
    }
    check(n == 64, "read() into a tagged buffer returned the full count");
    int zeroed = 1;
    for (ssize_t i = 0; i < n; i++)
        if (page[i] != 0)
            zeroed = 0;
    check(zeroed, "read() into a tagged buffer wrote through the untagged address");

    // A tagged *pathname* takes the kernel's string-copy path, which is a
    // different set of bounds checks from the bulk one above.
    char path[] = "/dev/null";
    char *heap_path = strdup(path);
    if (heap_path != NULL && (((uintptr_t) heap_path) >> 56) == 0) {
        int nfd = open(tag_ptr(heap_path), O_RDONLY);
        check(nfd >= 0, "open() with a tagged pathname pointer");
        if (nfd >= 0)
            close(nfd);
    }
    free(heap_path);
}

int main(int argc, char **argv) {
    test_init(argc, argv);

    long sz = sysconf(_SC_PAGESIZE);
    page_size = sz > 0 ? (size_t) sz : 4096;
    page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("FAIL cannot map a page (errno=%d %s)\n", errno, strerror(errno));
        failures_total++;
        return finish_suite("tagged_pointer");
    }
    memset(page, 0, page_size);

    step("== scalar ==");
    test_scalar();
    step("== bulk ==");
    test_bulk();
    step("== crosspage ==");
    test_crosspage();
    step("== atomics ==");
    test_atomics();
    step("== syscalls ==");
    test_syscalls();

    munmap(page, page_size);
    return finish_suite("tagged_pointer");
}
