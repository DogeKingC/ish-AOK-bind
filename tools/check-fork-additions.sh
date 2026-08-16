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
# The two binder diagnostics. They are NOT in setup-regressions.sh's test list
# and must not be: they answer questions ("which alignment rule does the driver
# I am talking to implement", "are wakeups being discarded") rather than
# passing or failing. They ARE in fs/aok-tests.manifest, so they land on a
# device -- which is the whole point, since the device is where the questions
# get asked and gcc is already there.
need_file tests/manual/binder_poll_wakeup_probe.c
need_file tests/manual/binder_object_align_probe.c
need_in fs/aok-tests.manifest binder_object_align_probe.c "shipped to /AOK/tests"
need_in fs/aok-tests.manifest binder_poll_wakeup_probe.c  "shipped to /AOK/tests"
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
# The harness linked every test binary against the STATIC musl (its sysroot's
# libc.so is a dangling symlink, so -lc silently fell back to libc.a) while
# still setting a PT_INTERP. Two libcs, and any thread's TLS sized as though
# the program had none -- which presents as the emulator faulting on a plain
# TLS store. Both halves of the fix are load-bearing.
need_in tools/run-arm64-guest-tests.sh "ld-musl-aarch64.so.1\" \]; then" \
    "the ldso is copied in so -lc resolves to the shared libc"
need_in tools/run-arm64-guest-tests.sh "NEEDED.*libc" \
    "and a static fallback is caught rather than silently shipped"
need_in tools/run-arm64-guest-tests.sh __getauxval \
    "libgcc's LSE-atomics init still resolves against the shared libc"

# --- arm64 guest: threads get their own stack and TLS -----------------------
# Android's idmap2d dies in RefBase::incStrong with a null mRefs, from a binder
# pool thread. Shared stacks or shared TLS would produce exactly that, so it is
# asserted directly rather than reasoned about.
need_file tests/manual/arm64/thread_identity.c
need_in fs/aok-tests.manifest             arm64/thread_identity.c
need_in tests/manual/setup-regressions.sh thread_identity
# The ABI assertion around the crash: RefBase::RefBase holds `this` in x19
# across a PLT call into another library and stores through it afterwards.
need_file tests/manual/arm64/hle_callee_saved.c
need_in fs/aok-tests.manifest             arm64/hle_callee_saved.c
need_in tests/manual/setup-regressions.sh hle_callee_saved
# HLE defaults to OFF, so the tests that exist to cover it were passing
# against the plain interpreted path. The runner turns it on for those.
need_in tools/run-arm64-guest-tests.sh "ISH_HLE=1" \
    "the HLE tests actually run with HLE enabled"

# --- arm64 fault diagnostics ------------------------------------------------
# A guest fault has to name the library and offset it happened at, and the one
# it was CALLED from: an outline-atomics helper builds no frame, so without x30
# a crash in one is unattributable. And the knob that dumps memory around a
# register has to be reachable from a guest shell -- getenv reads the app's
# environment, which no phone can set, so it was dev-machine-only.
need_in kernel/calls.c "lr-backing" \
    "an arm64 fault names the caller, not just the faulting helper"
need_in kernel/calls.c arm64_faultdump_set \
    "the fault memdump is settable at runtime, not only from the environment"
need_in fs/proc/ish.c  arm64_faultdump \
    "and is exposed at /proc/ish/arm64_faultdump"

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
# Binder must not use poll_wakeup_trylock for its own wakeups: it discards them
# when it loses the lock, and an epoll-driven receiver (which real Android is)
# has no guaranteed second chance. Measured at ~3100 discards per 12000 under
# contention. The deferred list plus binder_unlock() is what replaces it, and
# the flush before binder_thread_read parks is the half that a well-meaning
# refactor would drop -- without it the wakeup waits on the thread it is
# supposed to wake.
need_in kernel/binder.c binder_defer_wakeup \
    "poll wakeups are deferred past binder_lock, not discarded on a lost trylock"
need_in kernel/binder.c binder_have_deferred_wakeups \
    "and flushed before a reader parks, or the wakeup waits on its own target"
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

# --- logd sink -------------------------------------------------------------
# /dev/socket/logdw. Without it Android's own account of a failure goes
# nowhere: the kmsg path only catches what android::base's KernelLogger writes,
# which is fatals, so everything else fails silently -- the exact blindness
# that made the earlier bring-up walls expensive.
#
# Two hooks in fs/sock.c are what make a kernel-side server on a guest socket
# work at all, and both were found the hard way: the inode reference has to be
# HELD or socket_id is reassigned and the guest connects to a socket nobody
# bound, and a guest datagram arrives with an internal credential header that
# only the guest recv paths strip.
need_file kernel/logd_sink.c
need_file kernel/logd_sink.h
need_file tests/manual/logd_sink.c
need_in meson.build       kernel/logd_sink.c
need_in app/AppDelegate.m logd_sink_start "starts the logd sink at boot"
need_in xX_main_Xx.h      logd_sink_start "starts the logd sink at boot (CLI)"
need_in fs/proc/ish.c     logd_sink_show  "/proc/ish/logd, which says whether the sink is up"
need_in fs/sock.c  unix_socket_host_path_for \
    "the host path behind a guest socket name, with the inode reference held"
need_in fs/sock.c  unix_dgram_strip_cred \
    "a kernel-side reader strips the credential header the guest recv paths do"
need_in fs/real.c  S_ISSOCK \
    "realfs can create a socket inode, or no unix socket binds on a realfs root"
need_in fs/aok-tests.manifest             logd_sink.c
need_in tests/manual/setup-regressions.sh logd_sink
need_in opt/AOK/tools/android/chroot-setup.sh /proc/ish/logd \
    "a chroot gets its own logdw, or Android logs into the outer root's socket"

# --- pipe capacity ----------------------------------------------------------
# F_SETPIPE_SZ/F_GETPIPE_SZ. bionic's crash handler sets a pipe's size before
# spawning crash_dump; without these it got EINVAL on every Android crash.
# The numeric constants are deliberate: <fcntl.h> only defines the names under
# _GNU_SOURCE, so a `#if defined(F_SETPIPE_SZ)` guard silently compiles the
# forwarding path OUT and a Linux host answers from the fallback.
need_file tests/manual/pipe_size.c
need_in fs/fd.c F_SETPIPE_SZ_ "pipe capacity is settable"
need_in fs/fd.c F_GETPIPE_SZ_
need_in fs/aok-tests.manifest             pipe_size.c
need_in tests/manual/setup-regressions.sh pipe_size

# --- Android chroot setup --------------------------------------------------
need_file opt/AOK/tools/android/chroot-setup.sh
need_file opt/AOK/tools/android/root-profile.sh
# One command for the whole crash-reproduction sequence, which has a fixed
# order that is expensive to get wrong: arm the memdump BEFORE the run, and
# read dmesg back UNFILTERED (grep logd/ drops the fault block).
need_file opt/AOK/tools/android/crash-probe.sh
need_in fs/aok-tools.manifest android/crash-probe.sh "shipped to /AOK/tools on the device"
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

# --- the native subsystem's non-Darwin gate --------------------------------
# Upstream's native-program work (kernel/native_libc.c) is written against
# BSD/macOS libc and does not compile on glibc. That is invisible to the iOS
# build and fatal to this one: a Linux host is where run-guest-tests.sh and
# run-arm64-guest-tests.sh run, so without the gate the entire test apparatus
# stops building -- which is exactly what the 108-commit sync did before this.
# A future sync that drops the gate would reproduce it, and the symptom is a
# wall of errors in a file nobody here edited.
need_file kernel/native_stubs.c
need_in meson.build have_native \
    "the non-Darwin gate; without it upstream's native libc breaks every Linux gate"
need_in meson.build "kernel/native_stubs.c" \
    "and the stub that stands in for it"

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
