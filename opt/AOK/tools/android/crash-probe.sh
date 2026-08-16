#!/bin/sh
# Reproduce an Android daemon's native crash and print everything iSH knows
# about it, in one command.
#
#     sh /AOK/tools/android/crash-probe.sh idmap2d
#     sh /AOK/tools/android/crash-probe.sh installd
#     sh /AOK/tools/android/crash-probe.sh -r 19,20 idmap2d   # dump x19, x20
#
# WHY THIS EXISTS. Getting a usable account of one of these crashes takes
# several steps in a fixed order, and getting the order wrong wastes a whole
# reproduction: mark where dmesg is now, arm the fault memdump BEFORE the run
# (arming it afterwards tells you nothing), run the daemon with the right
# environment, wait for the sink to flush, then read back only the new lines --
# unfiltered, because `grep logd/` drops the very lines that matter and that
# has cost a debugging round already.
#
# It also collects what is easy to forget: the daemon's own stdout, the fault
# block with its pc-backing and lr-backing lines, and the logd records that
# came out just before the crash.
#
# WHAT TO DO WITH THE OUTPUT. `pc-backing` and `lr-backing` each name a file
# and a resolved `file+0x...` offset. Those go straight into
#     llvm-objdump -d --start-address=0x<off> --stop-address=0x<off+0x80> <file>
# on a development machine (the file is in the tree, under system/lib64). That
# is how idmap2d's fault was identified as RefBase::incStrong -- no tombstone,
# no debugger, no symbols.
#
# The memdump is the part that needs arming, and the part that answers "was
# this object ever constructed". For idmap2d, x20 is the object and x19 is its
# null mRefs, so -r 19,20 is the useful setting.

set -u

TREE=${ANDROID_TREE:-/root/android-sys}
REGS=
WAIT=6

usage() {
    echo "usage: crash-probe.sh [-t tree] [-r regs] [-w secs] <daemon> [args...]" >&2
    echo "  -t  Android tree to chroot into (default $TREE)" >&2
    echo "  -r  registers to dump memory around, e.g. 19,20 (default: off)" >&2
    echo "  -w  seconds to wait for the daemon and the log sink (default $WAIT)" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -t) TREE=${2:?}; shift 2 ;;
        -r) REGS=${2:?}; shift 2 ;;
        -w) WAIT=${2:?}; shift 2 ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -*) usage ;;
        *) break ;;
    esac
done
[ "$#" -ge 1 ] || usage

daemon=$1
shift

[ -d "$TREE" ] || { echo "no such tree: $TREE" >&2; exit 1; }
if [ ! -x "$TREE/system/bin/$daemon" ]; then
    echo "no such daemon: $TREE/system/bin/$daemon" >&2
    exit 1
fi

# The tree needs its mounts, and they do not survive an app restart. Saying so
# here beats the symptom, which is "Bad boot_id: ''" and a daemon that exits
# without explaining itself -- five rounds lost to that across three sessions.
if [ ! -e "$TREE/proc/self" ]; then
    echo "WARNING: $TREE/proc is not mounted. Run chroot-setup.sh first," >&2
    echo "         or every result below will be about that instead." >&2
fi

restore_faultdump=
if [ -n "$REGS" ]; then
    if [ -w /proc/ish/arm64_faultdump ]; then
        restore_faultdump=$(cat /proc/ish/arm64_faultdump 2>/dev/null || echo off)
        echo "$REGS" > /proc/ish/arm64_faultdump || {
            echo "could not arm /proc/ish/arm64_faultdump" >&2
            restore_faultdump=
        }
    else
        # An older build has this only as an environment variable, which no
        # phone can set. Say so rather than silently producing no dump.
        echo "NOTE: /proc/ish/arm64_faultdump is not present in this build," >&2
        echo "      so -r has no effect. Update iSH to get the memory dump." >&2
    fi
fi

mark=$(dmesg | wc -l)
out=${TMPDIR:-/tmp}/crash-probe.$daemon.out
rm -f "$out"

# installd needs ANDROID_DATA, which init supplies on a real Android and
# nothing here does; without it the daemon exits before it reaches any of the
# interesting code. Harmless for the others.
ANDROID_DATA=${ANDROID_DATA:-/data} \
ANDROID_ROOT=${ANDROID_ROOT:-/system} \
    chroot "$TREE" "/system/bin/$daemon" "$@" >"$out" 2>&1
status=$?

# The log sink forwards on its own thread, so reading dmesg immediately can
# miss the daemon's last words -- which are usually the interesting ones.
sleep "$WAIT"

echo "=== $daemon exited $status ==="
if [ "$status" -gt 128 ]; then
    echo "(signal $((status - 128))$([ "$status" = 139 ] && echo ' -- SIGSEGV'))"
fi

echo
echo "=== its own stdout/stderr ==="
head -20 "$out"

echo
echo "=== new kernel log (UNFILTERED -- the fault block is not a logd/ line) ==="
dmesg | tail -n +$((mark + 1))

if [ -n "$restore_faultdump" ]; then
    echo "$restore_faultdump" > /proc/ish/arm64_faultdump 2>/dev/null || true
fi
