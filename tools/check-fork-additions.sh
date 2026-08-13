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
need_file tests/manual/binder_ping.c
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

# --- Android property area -------------------------------------------------
# /dev/__properties__. Without it every libbinder client spins on
# servicemanager.ready and never opens the binder driver, so losing the boot
# hook would look like a binder regression rather than a missing file.
need_file kernel/property_area.c
need_file kernel/property_area.h
need_file tests/manual/property_area.c
need_in app/AppDelegate.m property_area_create "builds /dev/__properties__ at boot"
need_in xX_main_Xx.h      property_area_create "builds /dev/__properties__ at boot (CLI)"
need_in fs/proc/ish.c     property_area_show   "/proc/ish/property_area, the chroot's only way in"
need_in fs/proc/ish.c     property_area_update
need_in meson.build       kernel/property_area.c

# --- arm64 guest: tagged pointers -----------------------------------------
# AArch64 TBI. bionic tags every heap pointer, so without the untagging every
# arm64 Android process dies in libc's first memset -- and the tag is stripped
# in the JIT's TLB fast path only, which is easy to lose track of.
need_file tests/manual/arm64/tagged_pointer.c
need_in kernel/abi.h   guest_abi_untag_addr "the shared TBI untagging helper"
need_in kernel/user.c  guest_abi_untag_addr "syscall pointers are untagged"
need_in emu/arm64_interp.c guest_abi_untag_addr "interpreter loads/stores are untagged"
need_in fs/aok-tests.manifest             arm64/tagged_pointer.c
need_in tests/manual/setup-regressions.sh tagged_pointer
need_in kernel/calls.c guest_abi_untag_addr \
    "the fault handler resolves arm64 faults untagged, as Linux's do_page_fault does"
# The last and worst of the TBI leaks, and the one nothing else would catch:
# jit/hle.c runs whole libc calls natively in C with pointers taken straight
# from the guest register file. Losing the mask there does not fail to build
# and does not fail any i386 test -- it just makes every memset and memcpy on
# an Android heap pointer fault, reported at the callee's first instruction,
# which is a week of somebody's life.
need_in jit/hle.c    guest_abi_untag_addr "HLE untags the guest pointer arguments"
need_in jit/hle.c    hle_fn_returns_pointer \
    "and puts the tag back on pointer-valued results, as hardware does"
need_in emu/tlb.c    guest_abi_untag_addr \
    "the arm64 C memory helpers that bypass the prep macros untag on entry"
need_in kernel/calls.c SAME_FAULT_LIMIT \
    "a fault that resolves and re-faults is delivered, not spun on forever"
# The tripwires that found the HLE leak, kept for the next one. They are the
# difference between "a tagged address got in somewhere" and a week of
# bisecting: they name the calling helper in the log the first time it happens.
need_in emu/tlb.c    tlb_note_tagged_miss \
    "the TBI tripwire that names whoever hands the TLB a tagged address"

# --- arm64 guest: testable without a device ---------------------------------
# The arm64 engine is aarch64-host-only, so on an x86_64 dev box every gadget
# in it is unreachable and the only feedback loop is building an IPA. This
# harness cross-builds iSH for aarch64-linux and runs the guest tests under
# qemu-user instead. Losing it silently puts that loop back to hours.
need_file tools/cross-aarch64.ini
need_file tools/run-arm64-guest-tests.sh
need_in meson.build "host_machine.system() == 'linux'" \
    "a Linux cross build still produces the CLI executable to run"

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
# Object offsets inside a parcel are 4-aligned, not 8: Parcel packs to 4, so
# libbinder's checkService reply (int32 status, then the binder) puts its
# object at offset 4. Requiring the buffer's own 8-byte alignment here looks
# tidier and breaks every checkService while leaving addService and
# listServices working, which reads as "the service is not registered". The
# align4 phase is the only test that pins it -- every other one builds its
# object behind a uint64_t and lands 8-aligned by accident.
need_in kernel/binder.c "off % 4 != 0" \
    "parcel object offsets are validated at 4-byte alignment, as Linux does"
need_in tests/manual/binder_ipc.c align4_client_handler \
    "the phase that replays libbinder's checkService reply byte for byte"
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
need_file opt/AOK/tools/android/chroot-setup.sh
need_file opt/AOK/tools/android/root-profile.sh
need_in fs/aok-tools.manifest android/chroot-setup.sh "shipped to /AOK/tools on the device"
need_file docs/android-bringup.md
# Builds the tree everything above is tested against. Its DT_NEEDED closure
# check is the only thing that says, before a device is involved, which Android
# daemons cannot start because the image never shipped their libraries.
need_file .github/workflows/extract-android-system.yml
need_file opt/AOK/tools/ish-report.sh
need_in fs/aok-tools.manifest ish-report.sh "the one-command diagnostic report"
need_file opt/AOK/tools/ish-remote.sh
need_in fs/aok-tools.manifest ish-remote.sh "the code-gated remote command listener"
need_in opt/AOK/tools/ish-remote.sh inflight \
    "a command that killed the listener is reported, not silently swallowed"
# The relay rate-limits, and every one of these is a bug that presented as
# "the channel is broken" rather than as an error.
need_in opt/AOK/tools/ish-remote.sh 'sleep "$_ra"' \
    "429 backs off as long as the relay asks, not faster than it replenishes"
need_in opt/AOK/tools/ish-remote.sh net_limited \
    "a rate limit abandons the remaining chunks instead of deepening it"
need_in opt/AOK/tools/ish-remote.sh 'exit "$_st"' \
    "the EXIT trap preserves the status, so die does not report success"
need_in opt/AOK/tools/ish-remote.sh resume_from \
    "a listener with no state starts from now, rather than re-running 12h of topic"

# --- host CPU feature detection --------------------------------------------
# One binary ships to every device from an ARMv8.0 iPad up, so "what can this
# core do" is a runtime question. Losing this turns every ISA decision back
# into a guess made at compile time for the oldest device.
need_in kernel/hostinfo.h host_cpu_features "the runtime ARM feature query"
need_in fs/proc/ish.c     cpu_features      "/proc/ish/cpu_features"
need_in meson_options.txt ldapr             "the FEAT_LRCPC dispatch variant"

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
need_in fs/aok-tests.manifest             property_area.c
need_in tests/manual/setup-regressions.sh binder_ipc
need_in tests/manual/setup-regressions.sh ashmem
need_in tests/manual/setup-regressions.sh dma_heap
need_in tests/manual/setup-regressions.sh selinuxfs
need_in tests/manual/setup-regressions.sh kmsg
need_in tests/manual/setup-regressions.sh property_area

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

# The automated sync is what runs THIS script, so it is the one file whose
# loss would disarm every check above at once and report nothing. Guard the
# workflow and both gates it depends on: without check-fork-additions.sh the
# sync stops noticing that our work vanished, and without the arm64 harness it
# stops testing the only engine this fork actually ships on -- neither of which
# fails a build or shows up anywhere except on a phone, weeks later.
need_file .github/workflows/sync-upstream.yml
need_in .github/workflows/sync-upstream.yml check-fork-additions.sh \
    "the sync verifies this fork's work survived the merge"
need_in .github/workflows/sync-upstream.yml run-guest-tests.sh \
    "the sync runs the i386 guest regression tests"
need_in .github/workflows/sync-upstream.yml run-arm64-guest-tests.sh \
    "the sync runs the arm64 guest tests under qemu-user"
need_in .github/workflows/sync-upstream.yml "github.repository == 'DogeKingC/ish-AOK-bind'" \
    "pinned, so a fork of this fork does not push to a repo it should not"

if [ "$fail" -eq 0 ]; then
    echo "fork additions: all present"
fi
exit $fail
