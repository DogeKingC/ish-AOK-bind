#!/system/bin/sh
# Session setup for running an Android system image as an iSH-AOK ROOT, with no
# chroot. Place it in the tree as /android-profile.sh and point
# Settings -> Launch Command at:
#
#     /system/bin/sh /android-profile.sh
#
# Most of what the chroot needed is already done by the time this runs: iSH
# mounts /proc, /sys and /dev/pts at boot, creates /dev/binder, /dev/ashmem
# and /dev/dma_heap/* itself, and builds /dev/__properties__ from this tree's
# own build.prop files. What is left is the environment and one mount.
#
# After editing a build.prop, rebuild the property area without restarting the
# app:
#
#     echo / > /proc/ish/property_area
#     cat /proc/ish/property_area
#
# A process that already started keeps the area it mapped, so restart the
# process too -- but not the session.
#
# The environment matters more than it looks. iSH boots the session with
# PATH=/usr/local/sbin:...:/bin and HOME=/root, and an Android tree has none of
# those directories -- so without this, nothing resolves by name and every
# command needs a full path.

export PATH=/system/bin:/system/xbin:/apex/com.android.runtime/bin:/apex/com.android.art/bin
export TMPDIR=/data/local/tmp
export HOME=/data/local/tmp

# bionic and ART default these to the same values, but an image that was built
# with them relocated will not. Setting them explicitly costs nothing and turns
# a confusing library-not-found into a working lookup.
export ANDROID_ROOT=/system
export ANDROID_DATA=/data
export ANDROID_ART_ROOT=/apex/com.android.art
export ANDROID_I18N_ROOT=/apex/com.android.i18n
export ANDROID_TZDATA_ROOT=/apex/com.android.tzdata

# Not optional, and not cosmetic like the four above. installd does
# strlen(getenv("ASEC_MOUNTPOINT")) with no null check, so an unset one is a
# read of address 0 and a SIGSEGV a few instructions into startup -- the "0x0
# null dereference" that sat on the remaining-work list as a suspected emulator
# bug until the fault was read. ASEC is long dead (Android 4.x app-on-SD); the
# value only has to be a string, and init used /mnt/asec.
export ASEC_MOUNTPOINT=/mnt/asec

mkdir -p /data/local/tmp 2>/dev/null
mkdir -p /mnt/asec 2>/dev/null

# installd creates per-user directories under these and exits 1 with "Could not
# create directories" if their parents are missing. On a device init and vold
# build this tree; nothing here does, so it has to exist up front.
mkdir -p /data/misc/installd /data/misc/user/0 /data/system \
         /data/system_de/0 /data/system_ce/0 \
         /data/user/0 /data/user_de/0 /data/user_ce/0 \
         /data/misc_de/0 /data/misc_ce/0 /data/data /data/app /data/media/0 \
         2>/dev/null

# PT_INTERP is an absolute /system/bin/linker64, resolved against this root.
# Modern images ship the real linker under bootstrap/ and expect init to have
# made this link.
if [ ! -e /system/bin/linker64 ] && [ -e /system/bin/bootstrap/linker64 ]; then
    ln -sf /system/bin/bootstrap/linker64 /system/bin/linker64
fi

# selinuxfs cannot go at its canonical /sys/fs/selinux here: /sys is iSH's own
# sysfs, which is synthetic and read-only, so that directory does not exist and
# cannot be created. libselinux tries that path first, fails, and then scans
# /proc/self/mountinfo for a filesystem of type selinuxfs -- so any mount point
# works. /selinux is where Android itself put it before 4.3.
if ! grep -q ' selinuxfs ' /proc/self/mountinfo 2>/dev/null; then
    mkdir -p /selinux 2>/dev/null
    mount -t selinuxfs selinuxfs /selinux 2>/dev/null
fi

if [ ! -f /linkerconfig/ld.config.txt ] && [ -x /apex/com.android.runtime/bin/linkerconfig ]; then
    mkdir -p /linkerconfig 2>/dev/null
    /apex/com.android.runtime/bin/linkerconfig --target /linkerconfig 2>/dev/null
fi

# exec, not a plain call: iSH restarts the launch command when it exits, and a
# shell that returns here would be respawned rather than ending the session.
exec /system/bin/sh -i
