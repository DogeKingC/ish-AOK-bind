#!/bin/sh
# Verifies that everything this fork adds on top of upstream emkey1/ish-AOK is
# still present in the tree.
#
# The automated upstream sync (.github/workflows/sync-upstream.yml) runs this
# after merging. A clean merge is not by itself proof our work survived: an
# upstream commit that deleted or rewrote one of the files we hook into would
# merge without any conflict, and most of these hooks are single lines in files
# upstream edits regularly (app/AppDelegate.m, kernel/exit.c, fs/dev.c,
# fs/mount.c, meson.build).
#
# Run it by hand any time: sh tools/check-fork-additions.sh
#
# When adding a new subsystem to this fork, add its files and hooks here. That
# is the whole maintenance burden, and it is what stops a future sync from
# quietly reverting it.

set -u
fail=0

need_file() {
    if [ ! -f "$1" ]; then
        echo "MISSING FILE: $1"
        fail=1
    fi
}

# need_in <file> <pattern> [description]
need_in() {
    if [ ! -f "$1" ]; then
        echo "MISSING FILE: $1 (wanted: $2)"
        fail=1
    elif ! grep -q -- "$2" "$1"; then
        echo "MISSING in $1: $2${3:+  ($3)}"
        fail=1
    fi
}

# --- Android binder -------------------------------------------------------
need_file kernel/binder.c
need_file kernel/binder.h
need_file fs/binderfs.c
need_file tests/manual/binder_ipc.c
need_file docs/binder.md
need_in app/AppDelegate.m binder_create_device_nodes "creates /dev/binder at boot"
need_in xX_main_Xx.h      binder_create_device_nodes "creates /dev/binder at boot (CLI)"
need_in kernel/exit.c     binder_task_exit           "releases binder threads on task exit"
need_in fs/dev.c          BINDER_MAJOR               "binder char device registration"
need_in fs/devices.h      BINDER_MAJOR
need_in fs/mount.c        binderfs                   "binderfs in the filesystems table"
need_in meson.build       kernel/binder.c
need_in meson.build       fs/binderfs.c

# --- Android ashmem -------------------------------------------------------
need_file kernel/ashmem.c
need_file kernel/ashmem.h
need_file tests/manual/ashmem.c
need_in app/AppDelegate.m ashmem_create_device_node "creates /dev/ashmem at boot"
need_in xX_main_Xx.h      ashmem_create_device_node "creates /dev/ashmem at boot (CLI)"
need_in fs/dev.c          MISC_MAJOR                "ashmem char device registration"
need_in fs/devices.h      DEV_ASHMEM_MINOR
need_in meson.build       kernel/ashmem.c

# --- DMA-BUF heaps --------------------------------------------------------
need_file kernel/dma_heap.c
need_file kernel/dma_heap.h
need_file tests/manual/dma_heap.c
need_in app/AppDelegate.m dma_heap_create_device_nodes "creates /dev/dma_heap at boot"
need_in xX_main_Xx.h      dma_heap_create_device_nodes "creates /dev/dma_heap at boot (CLI)"
need_in fs/dev.c          dma_heap_dev                 "dma-heap minor dispatch"
need_in fs/devices.h      DEV_DMA_HEAP_SYSTEM_MINOR
need_in meson.build       kernel/dma_heap.c

# --- shared ---------------------------------------------------------------
need_file kernel/ioctl_abi.h

# --- iOS integration ------------------------------------------------------
need_in app/AppGroup.m  NSApplicationSupportDirectory \
    "app group fallback, without which sideloaded builds cannot hold a root"
need_in app/AppDelegate.m /mnt/iphone   "Documents mounted into the guest"
need_in app/Info.plist  LSSupportsOpeningDocumentsInPlace
need_in app/Info.plist  UIFileSharingEnabled

# --- test wiring ----------------------------------------------------------
# fs/aok-tests.manifest is what actually ships test sources to /AOK/tests on
# device; setup-regressions.sh alone is not enough, and forgetting it is a
# mistake both this fork and upstream have made.
need_in fs/aok-tests.manifest             binder_ipc.c
need_in fs/aok-tests.manifest             ashmem.c
need_in fs/aok-tests.manifest             dma_heap.c
need_in tests/manual/setup-regressions.sh binder_ipc
need_in tests/manual/setup-regressions.sh ashmem
need_in tests/manual/setup-regressions.sh dma_heap

# --- CI -------------------------------------------------------------------
# Upstream guards these on repository *name*, which this fork's name does not
# match; if a sync reverts our owner/name pin, no IPA is ever built again.
need_in .github/workflows/build-dev-ipa.yml     "DogeKingC/ish-AOK-bind"
need_in .github/workflows/build-release-ipa.yml "DogeKingC/ish-AOK-bind"

if [ "$fail" -eq 0 ]; then
    echo "fork additions: all present"
fi
exit $fail
