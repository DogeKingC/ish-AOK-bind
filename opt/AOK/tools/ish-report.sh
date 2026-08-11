#!/bin/sh
# One command, one file: everything needed to diagnose a guest failure from
# somewhere else.
#
#     sh /AOK/tools/ish-report.sh tagged_pointer
#     sh /AOK/tools/ish-report.sh                 # state only, no tests
#     sh /AOK/tools/ish-report.sh --push tagged_pointer   # and push it
#
# Debugging iSH from a distance means someone reads output they cannot
# produce. Doing that by hand costs a round trip per fact -- run the test,
# paste it, be asked for dmesg, paste that, be asked which ABI, and so on --
# and the answer usually needs three of those together. This collects the lot
# in the right order: state first, then the run, then the kernel log AFTER the
# run so any fault the run caused is in it.
#
# The report goes to a file and to stdout, so it can be pasted or redirected.
#
# --push additionally commits it to a throwaway branch and pushes, which is
# worth it for anyone reading this from elsewhere: a pasted report gets
# truncated or reflowed exactly when it is long, and it is long precisely when
# something interesting happened. Needs to run from inside a checkout that can
# push; ISH_REPORT_REPO names one if the working directory is not it.
#
# It records paths, mounts and a process list. Nothing is uploaded anywhere by
# this script, but glance at it before sending it on.

set -u

push=0
if [ "${1:-}" = "--push" ]; then
    push=1
    shift
fi

tests="$*"
out="${ISH_REPORT_OUT:-${TMPDIR:-/tmp}/ish-report.txt}"

# Everything below writes to stdout; the whole thing is teed to $out at the end.
report() {

echo "===== iSH-AOK report ====="
echo "date:        $(date 2>/dev/null)"
echo "guest arch:  $(uname -m 2>/dev/null)"
echo "uname:       $(uname -a 2>/dev/null)"
echo "ish version: $(cat /proc/ish/version 2>/dev/null || echo '(no /proc/ish -- is /proc mounted, and is this iSH-AOK?)')"
echo "requested:   ${tests:-'(no tests, state only)'}"

echo
echo "===== /proc/ish ====="
for f in property_area binder; do
    echo "--- /proc/ish/$f"
    cat "/proc/ish/$f" 2>/dev/null || echo "(absent)"
done

echo
echo "===== the Android bits, if present ====="
for n in /dev/binder /dev/ashmem /dev/dma_heap/system /dev/kmsg /dev/__properties__; do
    if [ -e "$n" ]; then
        ls -l "$n" 2>/dev/null
    else
        echo "missing: $n"
    fi
done
echo "--- selinuxfs"
grep selinuxfs /proc/self/mountinfo 2>/dev/null || echo "(not mounted)"

echo
echo "===== mounts ====="
cat /proc/mounts 2>/dev/null | head -40

# The kernel log is sampled twice: once here, so a fault from BEFORE this run
# is not mistaken for one the run caused, and again at the end.
echo
echo "===== dmesg, before the run ====="
dmesg 2>/dev/null | tail -15 || echo "(no dmesg)"

if [ -n "$tests" ]; then
    echo
    echo "===== regression run: $tests ====="
    only=$(echo "$tests" | tr ' ' ',')
    # Verbose, because the point of this file is that nobody can ask a
    # follow-up question cheaply.
    sh /AOK/tests/setup-regressions.sh --run --only "$only" -v 2>&1
    echo "(runner exit: $?)"
fi

echo
echo "===== dmesg, after the run ====="
# Generous: an arm64 guest fault dumps 31 registers plus a stack window, so
# one crash is ~25 lines and a forked test can produce several.
dmesg 2>/dev/null | tail -120 || echo "(no dmesg)"

echo
echo "===== end of report ====="

}

report 2>&1 | tee "$out"
echo
echo "written to: $out" >&2

[ "$push" -eq 1 ] || exit 0

repo="${ISH_REPORT_REPO:-$(pwd)}"
if ! (cd "$repo" && git rev-parse --git-dir >/dev/null 2>&1); then
    echo "--push: $repo is not a git checkout (set ISH_REPORT_REPO)" >&2
    exit 1
fi

stamp=$(date -u +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)
branch="reports/$(uname -m 2>/dev/null || echo guest)-$stamp"
dest="reports/ish-report-$stamp.txt"

# A branch per report, never merged: it is a message, not history. Delete it
# once it has been read.
(
    cd "$repo" || exit 1
    mkdir -p reports || exit 1
    cp "$out" "$dest" || exit 1
    git checkout -b "$branch" >/dev/null 2>&1 || exit 1
    git add "$dest" || exit 1
    git -c user.email=report@ish -c user.name="iSH report" \
        commit -q -m "report: $stamp ${tests:-state only}" || exit 1
    git push -u origin "$branch" >/dev/null 2>&1 || {
        echo "--push: the push failed; the commit is on $branch locally" >&2
        exit 1
    }
    echo "pushed: $branch" >&2
    echo "  ask whoever is reading to look at $dest on that branch" >&2
) || exit 1
