#!/bin/bash
# Builds this fork's guest regression tests for an i386 guest and runs them
# under a freshly built `ish`.
#
# This is the check that actually matters after an upstream merge. Building is
# not enough: binder and ashmem are drivers, and a regression in them is a
# behavioural one that only shows up when a guest process exercises the
# protocol. These are the same tests, run the same way, as during development.
#
# Usage: tools/run-guest-tests.sh [build-dir] [test ...]
#   build-dir  meson build directory containing `ish` (default: build)
#   test       test names from tests/manual (default: the fork's own tests)
#
# Requires a 32-bit toolchain (gcc-multilib on Debian/Ubuntu). Exits non-zero
# if any test does not report PASS.

set -uo pipefail

BUILD_DIR="${1:-build}"
shift || true
TESTS=("$@")
if [ ${#TESTS[@]} -eq 0 ]; then
    TESTS=(binder_ipc ashmem dma_heap)
fi

ISH="$BUILD_DIR/ish"
if [ ! -x "$ISH" ]; then
    echo "no ish binary at $ISH -- build first" >&2
    exit 1
fi

ROOTFS_TAR=alpine-minirootfs-3.23.3-x86.tar.xz
if [ ! -f "$ROOTFS_TAR" ]; then
    echo "missing $ROOTFS_TAR in the repo root" >&2
    exit 1
fi

if ! echo 'int main(void){return 0;}' | gcc -m32 -static -x c - -o /dev/null 2>/dev/null; then
    echo "no working 32-bit toolchain (need gcc-multilib)" >&2
    exit 1
fi

GUEST_ROOT=$(mktemp -d)
cleanup() { rm -rf "$GUEST_ROOT"; }
trap cleanup EXIT

tar -xf "$ROOTFS_TAR" -C "$GUEST_ROOT"

fail=0
for test_name in "${TESTS[@]}"; do
    src="tests/manual/$test_name.c"
    if [ ! -f "$src" ]; then
        echo "FAIL $test_name (no such test: $src)"
        fail=1
        continue
    fi
    if ! gcc -m32 -static -std=gnu11 -Itests/manual -o "$GUEST_ROOT/$test_name" "$src" 2>&1 |
            grep -v 'defined but not used'; then
        : # grep finding nothing is fine; the compiler's own status is checked next
    fi
    if [ ! -x "$GUEST_ROOT/$test_name" ]; then
        echo "FAIL $test_name (did not compile)"
        fail=1
        continue
    fi

    # The realfs root cannot hold device nodes here, so each test falls back to
    # its own route in (binderfs; a tmpfs for ashmem). A SKIP means the test
    # could not reach the driver at all, which after a merge is a failure, not
    # a pass -- so treat anything that is not an explicit PASS as a failure.
    output=$(timeout 300 "$ISH" -r "$GUEST_ROOT" "/$test_name" 2>&1 |
             grep -v '^warning: setup step failed')
    echo "$output"
    if echo "$output" | grep -q "^$test_name: PASS$"; then
        echo "PASS $test_name"
    else
        echo "FAIL $test_name (no PASS line)"
        fail=1
    fi
done

exit $fail
