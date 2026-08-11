#!/bin/sh
# One command, one file: everything needed to diagnose a guest failure from
# somewhere else.
#
#     sh /AOK/tools/ish-report.sh tagged_pointer
#     sh /AOK/tools/ish-report.sh                 # state only, no tests
#     sh /AOK/tools/ish-report.sh --post tagged_pointer   # and upload it
#     sh /AOK/tools/ish-report.sh --push tagged_pointer   # and push it to a branch
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
# --post uploads it and prints a URL, which is the shortest path when the
# reader is elsewhere: they fetch the URL instead of being sent a retyping of
# the output. It needs no credentials, which --push does, so it is the one that
# works from a phone. The endpoint is ISH_REPORT_POST_URL if the default does
# not suit -- point it at your own host and nothing leaves your control.
#
# --push additionally commits it to a throwaway branch and pushes, which is
# worth it for anyone reading this from elsewhere: a pasted report gets
# truncated or reflowed exactly when it is long, and it is long precisely when
# something interesting happened. Needs to run from inside a checkout that can
# push; ISH_REPORT_REPO names one if the working directory is not it.
#
# It records paths, mounts and a process list. Neither --post nor --push is the
# default, and plain runs upload nothing -- but --post puts the file on a
# third-party host, so glance at it first.

set -u

push=0
post=0
while :; do
    case "${1:-}" in
        --push) push=1; shift ;;
        --post) post=1; shift ;;
        *) break ;;
    esac
done

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

if [ "$post" -eq 1 ]; then
    post_url="${ISH_REPORT_POST_URL:-https://paste.rs}"
    url=""
    if command -v curl >/dev/null 2>&1; then
        url=$(curl -sS --data-binary @"$out" "$post_url" 2>&1 | tail -1)
    elif command -v wget >/dev/null 2>&1; then
        # busybox wget has no --post-file; this fails cleanly on those.
        url=$(wget -qO- --post-file="$out" "$post_url" 2>&1 | tail -1)
    else
        echo "--post: needs curl or wget (apk add curl)" >&2
    fi
    case "$url" in
        http*) echo "posted: $url" >&2 ;;
        "")    ;;
        *)     echo "--post: upload did not return a URL: $url" >&2 ;;
    esac
fi

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
