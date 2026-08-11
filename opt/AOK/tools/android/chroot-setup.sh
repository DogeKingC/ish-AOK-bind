#!/bin/sh
# Prepares an Android system tree for chroot under iSH-AOK.
#
# Run it once per iSH launch, before chrooting:
#     sh /AOK/tools/android/chroot-setup.sh /root/android-sys
#
# Mounts do NOT survive an app restart, so this needs re-running after every
# update or relaunch even though the tree itself persists. Device nodes and the
# linker symlink DO persist, so those steps are no-ops the second time.
#
# Every failure this handles has cost a real debugging round:
#
#   no /proc           libbinder reads /proc/sys/kernel/random/boot_id and
#                      aborts with "Bad boot_id: ''". getcon() also lives here,
#                      so nothing SELinux-related works either.
#   no /dev/binder     libbinder aborts with "Binder driver '/dev/binder'
#                      failed. Terminating." A chroot cannot see the outer /dev.
#   no property area   every libbinder client spins on servicemanager.ready
#                      without ever opening the binder driver, so it looks
#                      like a binder hang and is not one.
#   no /dev/null       a great deal of Android code opens it unconditionally
#                      and dies quietly when it cannot.
#   no selinuxfs       servicemanager's first act is a fatal CHECK on
#                      selinux_status_open().
#   no linker64        every binary is "No such file or directory", because
#                      PT_INTERP is an absolute path the tree may not have.
#   plain-file kmsg    Android's KernelLogger writes there; if it is a regular
#                      file instead of the device, its dying words go into the
#                      file instead of `dmesg` and you never see them.
#
# Exits non-zero if anything essential is missing at the end.

set -u

ROOT="${1:-/root/android-sys}"

if [ ! -d "$ROOT" ]; then
    echo "no such directory: $ROOT" >&2
    exit 1
fi
cd "$ROOT" || exit 1

fail=0
note() { echo "  $*"; }

# --- the linker ------------------------------------------------------------
# PT_INTERP is /system/bin/linker64, an absolute path resolved inside the
# chroot. Modern trees ship the real one under bootstrap/.
if [ ! -e system/bin/linker64 ] && [ -e system/bin/bootstrap/linker64 ]; then
    ln -sf /system/bin/bootstrap/linker64 system/bin/linker64
    note "linked system/bin/linker64 -> bootstrap/linker64"
fi

# --- device nodes ----------------------------------------------------------
# Only the major/minor matter; a chroot needs its own nodes because it cannot
# see the ones the app creates in the outer /dev.
mkdir -p dev/dma_heap dev/socket

mknod_if_missing() {
    path="$1"; major="$2"; minor="$3"
    # A plain file left at one of these paths is worse than nothing: writes
    # succeed and go nowhere useful. dev/kmsg has been exactly that mistake.
    if [ -e "$path" ] && [ ! -c "$path" ]; then
        rm -f "$path"
        note "replaced non-device $path"
    fi
    if [ ! -e "$path" ]; then
        mknod "$path" c "$major" "$minor" 2>/dev/null || {
            echo "  FAILED to create $path (c $major $minor)"
            fail=1
            return
        }
    fi
    chmod 666 "$path" 2>/dev/null
}

mknod_if_missing dev/null            1 3
mknod_if_missing dev/zero            1 5
mknod_if_missing dev/full            1 7
mknod_if_missing dev/random          1 8
mknod_if_missing dev/urandom         1 9
mknod_if_missing dev/kmsg            1 11
mknod_if_missing dev/ashmem         10 55
mknod_if_missing dev/dma_heap/system 10 56
mknod_if_missing dev/binder        249 0
mknod_if_missing dev/hwbinder      249 1
mknod_if_missing dev/vndbinder     249 2

# --- the property area -----------------------------------------------------
# iSH builds /dev/__properties__ at boot, but into the OUTER root's /dev,
# which a chroot cannot see -- and it reads the outer root's build.prop files,
# which are not this tree's. Writing the tree's path to /proc/ish/property_area
# rebuilds it from THIS tree: its build.prop files in, its dev/__properties__
# out. See kernel/property_area.c.
#
# Unlike the device nodes this does not persist usefully: it is a snapshot of
# the tree's property files, so re-running it after editing one is the point.
if [ -w /proc/ish/property_area ]; then
    if echo "$ROOT" > /proc/ish/property_area; then
        note "built dev/__properties__ ($(cat /proc/ish/property_area | tr '\n' ' '))"
    else
        echo "  FAILED to build dev/__properties__"
        fail=1
    fi
else
    echo "  FAILED: no /proc/ish/property_area (is /proc mounted, and is this iSH-AOK?)"
    fail=1
fi

# --- mounts ----------------------------------------------------------------
# Lost on every restart. Mounting something twice on the same point would
# shadow the first, so each is skipped when already present.
mounted_on() {
    grep -q " $ROOT/$1 " /proc/mounts 2>/dev/null
}

mkdir -p proc sys/fs/selinux tmp
chmod 1777 tmp 2>/dev/null

if mounted_on proc; then
    note "proc already mounted"
elif mount -t proc proc proc; then
    note "mounted proc"
else
    echo "  FAILED to mount proc"
    fail=1
fi

# selinuxfs goes on last: if sysfs is ever mounted over sys/ it would hide a
# selinuxfs mounted underneath it.
if mounted_on sys/fs/selinux; then
    note "selinuxfs already mounted"
elif mount -t selinuxfs selinuxfs sys/fs/selinux; then
    note "mounted selinuxfs"
else
    echo "  FAILED to mount selinuxfs"
    fail=1
fi

# --- linker config ---------------------------------------------------------
# Without it the linker falls back to a permissive default namespace, which is
# survivable for toybox and not for anything that dlopens a vendor library.
if [ ! -f linkerconfig/ld.config.txt ] && [ -x apex/com.android.runtime/bin/linkerconfig ]; then
    mkdir -p linkerconfig
    if chroot . /apex/com.android.runtime/bin/linkerconfig --target /linkerconfig 2>/dev/null; then
        note "generated linkerconfig/ld.config.txt"
    else
        note "linkerconfig failed (not fatal)"
    fi
fi

# --- verify ----------------------------------------------------------------
# Checked from INSIDE the chroot, which is the only view that matters and is
# where all four of the failures above actually bite.
echo "verifying:"
if [ -x system/bin/toybox ]; then
    boot_id=$(chroot . /system/bin/toybox cat /proc/sys/kernel/random/boot_id 2>/dev/null)
    if [ -n "$boot_id" ]; then
        note "boot_id: $boot_id"
    else
        echo "  FAILED: /proc/sys/kernel/random/boot_id is empty inside the chroot"
        fail=1
    fi

    ctx=$(chroot . /system/bin/toybox cat /proc/self/attr/current 2>/dev/null)
    [ -n "$ctx" ] && note "context: $ctx" || { echo "  FAILED: no /proc/self/attr/current"; fail=1; }

    magic=$(chroot . /system/bin/toybox stat -f -c '%t' /sys/fs/selinux 2>/dev/null)
    if [ "$magic" = "f97cff8c" ]; then
        note "selinuxfs magic ok"
    else
        echo "  FAILED: /sys/fs/selinux magic is '$magic', wanted f97cff8c"
        fail=1
    fi
else
    note "no system/bin/toybox, skipping the inside-the-chroot checks"
fi

for node in dev/binder dev/null dev/kmsg; do
    [ -c "$node" ] || { echo "  FAILED: $node is not a character device"; fail=1; }
done

# A directory here would send bionic looking for per-SELinux-context files
# that nothing writes; it has to be the single pre-split file.
if [ -f dev/__properties__ ]; then
    note "property area: $(wc -c < dev/__properties__) bytes"
else
    echo "  FAILED: dev/__properties__ is not a regular file"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "ready: chroot . /system/bin/servicemanager"
else
    echo "setup incomplete, see above" >&2
fi
exit $fail
