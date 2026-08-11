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

# --- permissive SELinux stub ----------------------------------------------
need_file fs/selinuxfs.c
need_file tests/manual/selinuxfs.c
need_in kernel/fs.h  selinuxfs        "selinuxfs declared alongside the other filesystems"
need_in fs/mount.c   selinuxfs        "selinuxfs in the filesystems table"
need_in fs/sock.h    NETLINK_SELINUX_
need_in fs/sock.c    NETLINK_SELINUX_ "selinux_status_open's netlink fallback is accepted"
need_in meson.build  fs/selinuxfs.c
need_in fs/selinuxfs.c selinuxfs_class_index \
    "class/<name>/index, without which every access check is EINVAL and denied"

# /proc/<pid>/attr/* -- getcon/setcon/setexeccon. Upstream edits fs/proc/pid.c
# and kernel/exec.c regularly, and both hooks here are small enough to be lost
# in a clean merge.
need_in kernel/task.h  TASK_SECURITY_DEFAULT_CONTEXT "per-task SELinux contexts"
need_in kernel/task.c  TASK_SECURITY_DEFAULT_CONTEXT "the initial task's context"
need_in fs/proc/pid.c  proc_pid_attr_readdir         "/proc/<pid>/attr in the pid directory"
need_in fs/proc/pid.c  '{"attr", S_IFDIR'            "attr listed among the pid children"
need_in kernel/exec.c  'security.exec'               "execve consumes the setexeccon context"
need_in kernel/binder.c BR_TRANSACTION_SEC_CTX \
    "binder delivers the sender's context to a node that asked for one"
need_in kernel/binder.c binder_show_state "the /proc/ish/binder state dump"
need_in fs/proc/ish.c   binder_show_state "state dump wired into /proc/ish"

# --- writable /dev/kmsg ---------------------------------------------------
# Upstream's kmsg_write is a bare `return _EPERM`, so a sync that touches
# fs/mem.c can restore it in a clean merge and nothing will fail -- Android
# would just go back to dying silently, which is precisely the symptom that
# took a whole session to diagnose the first time.
need_file tests/manual/kmsg.c
need_in kernel/log.c ish_log_write_record "guest /dev/kmsg records reach the log"
need_in kernel/log.h ish_log_write_record
need_in fs/mem.c     ish_log_write_record "kmsg_write is not EPERM any more"

# --- boot_id generated once ------------------------------------------------
# Upstream generates it lazily with no lock. libbinder refuses to start on a
# bad boot_id and caches the one it read, so the "one value" contract is the
# whole point of the file.
need_file tests/manual/proc_random.c
need_in fs/proc/sys.c boot_id_lock "boot_id is generated under a lock"

# --- Android chroot setup --------------------------------------------------
need_file tools/android-chroot-setup.sh

# --- shared ---------------------------------------------------------------
need_file kernel/ioctl_abi.h

# --- iOS integration ------------------------------------------------------
need_in app/AppGroup.m  NSDocumentDirectory \
    "app group fallback to Documents; without it sideloaded builds cannot hold a root"
need_in app/AppGroup.m  ContainerIsAppGroup \
    "lets callers tell a real App Group from the fallback"
need_in app/RootsTableViewController.m ContainerIsAppGroup \
    "Browse Files routes to Documents when there is no File Provider"
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
need_in fs/aok-tests.manifest             selinuxfs.c
need_in fs/aok-tests.manifest             kmsg.c
need_in tests/manual/setup-regressions.sh binder_ipc
need_in tests/manual/setup-regressions.sh ashmem
need_in tests/manual/setup-regressions.sh dma_heap
need_in tests/manual/setup-regressions.sh selinuxfs
need_in tests/manual/setup-regressions.sh kmsg

# --- CI -------------------------------------------------------------------
# Upstream guards these on repository *name*, which this fork's name does not
# match; if a sync reverts our owner/name pin, no IPA is ever built again.
need_in .github/workflows/build-dev-ipa.yml     "DogeKingC/ish-AOK-bind"
need_in .github/workflows/build-release-ipa.yml "DogeKingC/ish-AOK-bind"

# Upstream's arm64-guest dispatch default (dmb) is tuned for the ARMv8.0 iPad
# the engine is benchmarked on. This fork targets modern Apple cores, where
# ldar wins. Upstream edits both the option default and xcode-meson.sh, so a
# sync can silently move us back onto dmb -- and nothing would fail, it would
# just be slower.
need_in .github/workflows/build-dev-ipa.yml     "ISH_ARM64_GRET=ldar"
need_in .github/workflows/build-release-ipa.yml "ISH_ARM64_GRET=ldar"

if [ "$fail" -eq 0 ]; then
    echo "fork additions: all present"
fi
exit $fail
