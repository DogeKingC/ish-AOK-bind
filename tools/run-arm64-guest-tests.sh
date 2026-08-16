#!/bin/bash
# Runs this fork's arm64-guest regression tests against a real aarch64 build of
# iSH, from an x86_64 development machine, with no device involved.
#
# WHY THIS EXISTS
#
# The arm64 guest engine is aarch64-HOST-only: jit/guest-arm64/*.S is literal
# AArch64 assembly, and meson.build refuses to build it on any other host
# ("arm64 binaries will not run"). So on an x86_64 box the entire arm64 JIT --
# every gadget, the TLB prep macros, the fault-restart contract -- is
# unreachable, and the only way to test a change to it has been to build an
# IPA, install it, and read the result back off a phone. That loop is minutes
# to hours long and gives you one bit at a time.
#
# This script closes it: cross-build iSH for aarch64-linux with clang, and run
# THAT under qemu-user, with a real Alpine aarch64 rootfs as the guest root.
# The arm64 gadgets then execute for real (qemu emulates them; iSH's JIT is
# ordinary data-driven dispatch, not self-modifying code, so nothing here is
# faked). It found its first real answer on the first run.
#
# WHAT IT DOES NOT COVER
#
# qemu-user is not an Apple core. Two known differences matter:
#   - TBI. Real arm64 hardware IGNORES bits 56-63 on a load/store, so a gadget
#     that forgets to strip a tag still works there and fails here. That makes
#     this harness STRICTER than the device for tagged pointers, not weaker --
#     but it also means "passes here" is not proof for a TBI bug that only
#     reproduces on hardware.
#   - Exclusives. qemu's monitor is cleared far more eagerly than a real core's,
#     so LDXR/STXR sequences that interleave other accesses can fail here and
#     pass on device. tests/manual/arm64/tagged_pointer.c's `atomics` probe is
#     the known case.
# Treat a failure here as a lead, and a pass as one host's worth of evidence.
#
# REQUIREMENTS (Debian/Ubuntu)
#   clang lld qemu-user-static
#   dpkg --add-architecture arm64 + an arm64 apt source (ports.ubuntu.com),
#   then: apt-get install libsqlite3-dev:arm64 libgcc-13-dev:arm64 \
#                         libstdc++-13-dev:arm64
#
#   The two gcc-dev packages are not optional and their absence does not look
#   like a missing package: clang finds the arm64 libc through the multiarch
#   layout but not crtbeginS.o or libgcc, so meson reports the compiler
#   "cannot compile programs" and names nothing. lld is selected by
#   tools/cross-aarch64.ini; without that -fuse-ld=lld clang falls back to the
#   host binutils ld, which fails earlier still with "unrecognised emulation
#   mode: aarch64linux" during linker detection.
# Plus, downloaded on first run into the work dir: an Alpine aarch64 minirootfs
# and the matching musl-dev, which is what the guest test binaries link against
# (they must be musl binaries -- musl's memset/memcpy are the SIMD routines the
# arm64 gadget bugs actually show up in).
#
# Usage: tools/run-arm64-guest-tests.sh [test ...]
#   test   names under tests/manual/arm64 (default: all of them)
#
# Exits non-zero if any test does not report PASS.

set -uo pipefail

cd "$(dirname "$0")/.."
SRC=$PWD
WORK=${ISH_ARM64_WORK:-${TMPDIR:-/tmp}/ish-arm64-harness}
BUILD=$WORK/build
ROOTFS=$WORK/rootfs
SYSROOT=$WORK/musl-sysroot

ALPINE_URL=${ISH_ALPINE_AARCH64_URL:-https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/alpine-minirootfs-3.21.4-aarch64.tar.gz}
MUSL_DEV_URL=${ISH_MUSL_DEV_AARCH64_URL:-https://dl-cdn.alpinelinux.org/alpine/v3.21/main/aarch64/musl-dev-1.2.5-r11.apk}

TESTS=("$@")
if [ ${#TESTS[@]} -eq 0 ]; then
    TESTS=()
    for f in tests/manual/arm64/*.c; do
        [ -e "$f" ] || continue
        TESTS+=("$(basename "$f" .c)")
    done
fi
if [ ${#TESTS[@]} -eq 0 ]; then
    echo "no tests under tests/manual/arm64" >&2
    exit 1
fi

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing $1 -- see the requirements comment at the top of this script" >&2
        exit 1
    fi
}
need clang
need qemu-aarch64-static
need meson
need ninja

mkdir -p "$WORK"

# --- the emulator -----------------------------------------------------------
if [ ! -d "$BUILD" ]; then
    meson setup "$BUILD" "$SRC" --cross-file "$SRC/tools/cross-aarch64.ini" >"$WORK/setup.log" 2>&1 || {
        echo "meson setup failed; see $WORK/setup.log" >&2
        tail -20 "$WORK/setup.log" >&2
        exit 1
    }
fi
if ! ninja -C "$BUILD" ish >"$WORK/build.log" 2>&1; then
    echo "cross build failed; see $WORK/build.log" >&2
    grep -E "^FAILED|error:" "$WORK/build.log" | head -20 >&2
    exit 1
fi
ISH=$BUILD/ish

# --- the guest root ---------------------------------------------------------
# A real Alpine root, not a hand-made one: the tests are dynamically linked
# against its musl, so the code under test is the same libc the device runs.
if [ ! -d "$ROOTFS" ]; then
    echo "fetching $ALPINE_URL"
    mkdir -p "$ROOTFS"
    curl -fsSL "$ALPINE_URL" -o "$WORK/alpine.tar.gz" || { echo "download failed" >&2; exit 1; }
    tar -xzf "$WORK/alpine.tar.gz" -C "$ROOTFS"
fi
if [ ! -d "$SYSROOT" ]; then
    echo "fetching $MUSL_DEV_URL"
    mkdir -p "$SYSROOT"
    curl -fsSL "$MUSL_DEV_URL" -o "$WORK/musl-dev.apk" || { echo "download failed" >&2; exit 1; }
    # An apk is a gzipped tar with signature members tar refuses to name; the
    # payload extracts fine and the complaint is not an error worth failing on.
    tar -xzf "$WORK/musl-dev.apk" -C "$SYSROOT" 2>/dev/null || true
fi
if [ ! -f "$SYSROOT/usr/lib/libc.a" ]; then
    echo "musl-dev extraction produced no libc.a in $SYSROOT" >&2
    exit 1
fi

# musl-dev ships usr/lib/libc.so as a symlink to ../../lib/ld-musl-aarch64.so.1
# -- the ldso IS the shared libc -- but the ldso itself lives in the `musl`
# package, not `musl-dev`, so inside this sysroot that symlink dangles. lld
# cannot follow it, says nothing, and quietly satisfies -lc from libc.a
# instead. The result still links and still runs, which is why this survived
# ten tests and several sessions:
#
#   every test binary was STATICALLY linked musl that also carried a
#   PT_INTERP, so the dynamic musl loaded too and two copies of libc were
#   live at once.
#
# The main thread works, because the ldso sets its TLS up from PT_TLS. Threads
# do not: pthread_create runs out of the static copy, whose libc.tls_size was
# never initialized by its own __init_tls, so a spawned thread's TLS block is
# sized as though the program had none. One __thread variable fits in the
# slack; the second lands past the end of the mapping and the thread takes a
# SIGSEGV on first write. Nothing reports a link problem -- it presents as the
# emulator faulting on a plain TLS store, which is an expensive thing to
# believe. Copying the ldso in makes -lc resolve to the real shared libc
# (DT_NEEDED libc.musl-aarch64.so.1 appears, and the binaries become dynamic,
# which is what -Wl,-dynamic-linker was asking for all along).
if [ ! -f "$SYSROOT/lib/ld-musl-aarch64.so.1" ]; then
    mkdir -p "$SYSROOT/lib"
    cp "$ROOTFS/lib/ld-musl-aarch64.so.1" "$SYSROOT/lib/ld-musl-aarch64.so.1" || {
        echo "could not copy the musl ldso into $SYSROOT/lib" >&2
        exit 1
    }
fi

# -nostdlibinc above, not -nostdinc: the musl sysroot supplies the C library
# headers, but stdatomic.h, arm_neon.h and the rest of the compiler's own
# resource headers still have to come from clang, and several of these tests
# include them.

# musl's libc.a wants the soft-float128 helpers (__multf3, __netf2) that the
# compiler runtime provides, and the tests' own _Atomic operations lower to
# libgcc's LSE outline atomics (__aarch64_ldadd8_acq_rel and friends); clang's
# own aarch64 builtins are not installed on a typical x86_64 box, so borrow
# libgcc from whichever aarch64 toolchain is present.
#
# Two layouts, because the two ways of getting an aarch64 toolchain put it in
# different places: gcc-aarch64-linux-gnu installs under gcc-cross/, while
# libgcc-13-dev:arm64 -- what the requirements above ask for, since it is also
# what clang needs for crtbeginS.o -- installs under the multiarch gcc/ path.
# Checking only the first is why this used to report "did not compile" on a
# box that had a perfectly good libgcc.
LIBGCC=$(ls /usr/lib/gcc-cross/aarch64-linux-gnu/*/libgcc.a \
            /usr/lib/gcc/aarch64-linux-gnu/*/libgcc.a 2>/dev/null | head -1 || true)

# libgcc's LSE-atomics initializer calls __getauxval to read HWCAP. Alpine
# defines that alias in libc.a but the shared libc exports only getauxval, so
# linking against the real shared musl (which is what we now do) leaves it
# undefined -- it was previously satisfied by accident, through the same
# unintended static link that broke thread TLS. One forwarding shim settles it
# for every test, and keeps the outline-atomics dispatch working, which matters
# here: __aarch64_ldadd4_relax is exactly the helper Android's RefBase crash
# goes through, so these tests must exercise the same lowering the device does.
SHIM_SRC=$WORK/getauxval_shim.c
SHIM_OBJ=$WORK/getauxval_shim.o
if [ ! -f "$SHIM_OBJ" ] || [ "$SHIM_SRC" -nt "$SHIM_OBJ" ]; then
    cat >"$SHIM_SRC" <<'SHIM'
#include <sys/auxv.h>
unsigned long __getauxval(unsigned long type);
unsigned long __getauxval(unsigned long type) { return getauxval(type); }
SHIM
    clang --target=aarch64-linux-musl -O2 -c -nostdlibinc \
        -isystem "$SYSROOT/usr/include" -o "$SHIM_OBJ" "$SHIM_SRC" || {
        echo "could not build the __getauxval shim" >&2
        exit 1
    }
fi

fail=0
for test_name in "${TESTS[@]}"; do
    src=$SRC/tests/manual/arm64/$test_name.c
    if [ ! -f "$src" ]; then
        echo "FAIL $test_name (no such test: $src)"
        fail=1
        continue
    fi
    out=$ROOTFS/$test_name
    if ! clang --target=aarch64-linux-musl -fuse-ld=lld -O2 -std=gnu11 \
            -I"$SRC/tests/manual" -nostdlibinc -isystem "$SYSROOT/usr/include" \
            -nostdlib -pie -Wl,-dynamic-linker,/lib/ld-musl-aarch64.so.1 \
            "$SYSROOT/usr/lib/Scrt1.o" "$SYSROOT/usr/lib/crti.o" \
            -o "$out" "$src" \
            "$SHIM_OBJ" \
            -L"$SYSROOT/usr/lib" -lc ${LIBGCC:+"$LIBGCC"} \
            "$SYSROOT/usr/lib/crtn.o" 2>"$WORK/$test_name.cc.log"; then
        echo "FAIL $test_name (did not compile)"
        head -10 "$WORK/$test_name.cc.log" >&2
        fail=1
        continue
    fi

    # The link above must produce a DYNAMIC musl binary. If -lc ever falls back
    # to libc.a again (a dangling libc.so is all it takes) the binary still
    # builds and still runs, and the damage shows up only as threads with
    # undersized TLS -- read as an emulator fault, at the cost of a session.
    # See the ldso copy near the sysroot setup. readelf is not guaranteed
    # present, so this checks when it can and stays quiet when it cannot.
    if command -v readelf >/dev/null 2>&1; then
        if ! readelf -dW "$out" 2>/dev/null | grep -q 'NEEDED.*libc'; then
            echo "FAIL $test_name (linked static musl but kept a PT_INTERP:" \
                 "no DT_NEEDED for libc -- threads will get undersized TLS)"
            fail=1
            continue
        fi
    fi

    # iSH's printk goes to file descriptor 555 (LOG_HANDLER_DPRINTF in
    # kernel/log.c), not to stderr. Unredirected, that fd is closed and every
    # kernel-side diagnostic this harness could give you is silently dropped --
    # including the whole `ERROR: ... page fault ... pc-backing ...` block,
    # which is the single most useful thing iSH prints. A guest test that dies
    # of a SIGSEGV therefore looked like a test that produced no output, with
    # the explanation thrown away microseconds earlier.
    #
    # Captured to a file rather than merged into stdout: on a passing run it is
    # just noise (a boot banner per test), and on a failing one you want all of
    # it, not the tail that happened to interleave.
    klog=$WORK/$test_name.klog
    : >"$klog"
    output=$( { timeout 300 qemu-aarch64-static "$ISH" -r "$ROOTFS" "/$test_name" 2>&1 555>"$klog"; } |
             grep -v '^warning: setup step failed')
    echo "$output"
    # Prefix, not exact: several of these tests append a summary to the verdict
    # line ("smc_stale_block: PASS (200 + 200 rounds)").
    if echo "$output" | grep -q "^$test_name: PASS"; then
        echo "PASS $test_name"
    else
        echo "FAIL $test_name (no PASS line)"
        # The kernel's account of what happened, which is usually the whole
        # answer when a guest test dies rather than reporting. `page fault`
        # first, because if there is one it names the guest pc, the library
        # backing it (pc-backing) and the caller (lr-backing).
        if [ -s "$klog" ]; then
            echo "--- kernel log for $test_name ($klog) ---" >&2
            grep -E 'ERROR:|URGENT:|page fault|backing|opcode window' "$klog" >&2 ||
                tail -20 "$klog" >&2
        fi
        fail=1
    fi
done

exit $fail
