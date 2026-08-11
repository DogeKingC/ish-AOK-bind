#!/bin/sh
# ish-remote: run commands sent from elsewhere, so a debugging session does not
# cost a round trip per command.
#
#     sh /AOK/tools/ish-remote.sh FLcKa          # listen, using the code FLcKa
#     sh /AOK/tools/ish-remote.sh --send FLcKa 'uname -a'   # post one command
#
# The problem it solves: debugging iSH from a distance means someone tells you
# a command, you type it, you read back the output, they ask for the next one.
# Every command is a round trip. This lets that someone post the command and
# read the output directly, so a session is one exchange per command instead of
# three.
#
# HOW IT WORKS. A "code" is a shared secret -- pick any string, the more
# random the better. From it both sides derive one ntfy.sh topic to send
# commands on and one to send output back on. The listener polls the command
# topic; anything stamped with the matching code, it runs; the output goes to
# the reply topic, split across several messages when it is large. ntfy.sh is a
# public relay and needs no account.
#
# It drains every pending command, oldest first, rather than only the newest.
# That matters on iOS, where the app is suspended whenever it is not in the
# foreground: a sender working meanwhile queues several commands, and they all
# land at once when it resumes.
#
# READ THIS BEFORE YOU RUN IT. This executes commands fetched from the network
# as you, in this shell. Whoever knows the code can run anything on this
# device. So:
#   - There is no default code. Without one this script does nothing, which is
#     what keeps a shipped copy on someone else's device from being a way in.
#   - The code is the only thing protecting you. Use a long random one, treat
#     it like a password, and stop the listener (Ctrl-C) when you are done.
#   - The traffic goes through ntfy.sh in clear text. Do not send secrets over
#     it, and for anything real, point ISH_REMOTE_BASE at your own ntfy server.
#   - Never put this in a launch/boot command. It is a thing you start by hand
#     for a session and stop afterwards.
#
# Tunables (environment):
#   ISH_REMOTE_BASE      relay base URL           (default https://ntfy.sh)
#   ISH_REMOTE_INTERVAL  seconds between polls     (default 4)
#   ISH_REMOTE_MAX       stop after N polls        (default 900, ~1h at 4s)
#   ISH_REMOTE_INLINE    bytes per reply message, split above it (default 3000)

set -u

base="${ISH_REMOTE_BASE:-https://ntfy.sh}"
interval="${ISH_REMOTE_INTERVAL:-4}"
max="${ISH_REMOTE_MAX:-900}"
inline_max="${ISH_REMOTE_INLINE:-3000}"

die() { echo "ish-remote: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "needs curl (apk add curl)"
command -v base64 >/dev/null 2>&1 || die "needs base64 (busybox provides it)"

# Both sides derive the same two topics from the one shared code.
cmd_topic() { echo "ishr-$1"; }
out_topic() { echo "ishr-$1-out"; }

# ---- sender: post one command ---------------------------------------------
# Used to test the channel, and it is exactly what the far end runs to drive
# this listener. The command is base64'd so it can carry newlines and quotes
# through a single line of relay payload without escaping.
if [ "${1:-}" = "--send" ]; then
    code="${2:-}"
    shift 2 2>/dev/null || true
    [ -n "$code" ] || die "usage: ish-remote.sh --send <code> <command...>"
    [ "$#" -gt 0 ] || die "nothing to send"
    b64=$(printf '%s' "$*" | base64 | tr -d '\n')
    id=$(date +%s 2>/dev/null || echo 0)
    printf 'ISH-REMOTE %s %s %s' "$code" "$id" "$b64" \
        | curl -sS --data-binary @- "$base/$(cmd_topic "$code")" >/dev/null \
        && echo "sent (id $id)" || die "send failed"
    exit 0
fi

# ---- listener -------------------------------------------------------------
code="${1:-${ISH_REMOTE_CODE:-}}"
[ -n "$code" ] || die "no code. Usage: ish-remote.sh <code>   (a shared secret; without it this does nothing)"

ct=$(cmd_topic "$code")
ot=$(out_topic "$code")
seen="${TMPDIR:-/tmp}/ish-remote.$code.seen"
stopflag="${TMPDIR:-/tmp}/ish-remote.$code.stop"
rm -f "$stopflag"
# Ids already run. Kept across restarts so resuming does not replay the topic's
# whole history; delete it to deliberately re-run everything.
[ -f "$seen" ] || : > "$seen"

echo "================================================================"
echo " ish-remote listening"
echo "   command topic: $base/$ct"
echo "   reply topic:   $base/$ot"
echo "   WARNING: every command sent with this code runs here, as you."
echo "   Ctrl-C to stop. Do not leave it running."
echo "================================================================"

# Announce readiness on the reply topic, so the far end knows the listener is
# actually up before it starts sending into the void.
curl -sS -d "ish-remote up on $(uname -m 2>/dev/null): waiting for commands" \
    "$base/$ot" >/dev/null 2>&1 || true

i=0
while [ "$i" -lt "$max" ]; do
    i=$((i + 1))
    sleep "$interval"

    # EVERY pending message, oldest first -- not just the newest. iOS suspends
    # iSH whenever it is not the foreground app, so a sender working in the
    # meantime queues several commands and they all arrive at once on resume.
    # Taking only the latest silently dropped the rest, which looks from the
    # far end like commands vanishing.
    batch=$(curl -sS "$base/$ct/json?poll=1&since=all" 2>/dev/null)
    [ -n "$batch" ] || continue

    printf '%s\n' "$batch" | while IFS= read -r msg; do
        [ -n "$msg" ] || continue

    # The payload is "ISH-REMOTE <code> <id> <base64>", all JSON-safe
    # characters, so a plain field extraction is enough -- no JSON parser.
    payload=$(printf '%s' "$msg" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p')
    set -- $payload
    [ "${1:-}" = "ISH-REMOTE" ] || continue
    [ "${2:-}" = "$code" ] || continue          # wrong code: not for us
    id="${3:-}"
    b64="${4:-}"
    [ -n "$id" ] || continue
    # Already-run ids live in a seen-file: a batch replays the whole cached
    # topic every poll, so "the last one I ran" is not enough state.
    grep -qx "$id" "$seen" 2>/dev/null && continue

    cmd=$(printf '%s' "$b64" | base64 -d 2>/dev/null)
    echo "$id" >> "$seen"
    [ -n "$cmd" ] || continue

    echo
    echo "--- [$id] running: $cmd"
    if [ "$cmd" = "stop" ] || [ "$cmd" = "ish-remote-stop" ]; then
        curl -sS -d "listener stopping" "$base/$ot" >/dev/null 2>&1 || true
        echo "--- stop received"
        : > "$stopflag"
        break
    fi

    out="${TMPDIR:-/tmp}/ish-remote.$code.out"
    # Combined stdout+stderr, and the exit status, because both matter when
    # something you cannot see went wrong.
    sh -c "$cmd" > "$out" 2>&1
    rc=$?
    echo "rc=$rc" >> "$out"
    cat "$out"

    size=$(wc -c < "$out" 2>/dev/null || echo 0)
    if [ "$size" -le "$inline_max" ]; then
        curl -sS --data-binary @"$out" "$base/$ot" >/dev/null 2>&1 || true
    else
        # Chunk it over the relay rather than depending on a paste host: the
        # device that most needs this (a phone) is the one most likely to
        # reach the relay and nothing else -- observed exactly that, ntfy
        # fine and the paste upload refused.
        parts=$(( size / inline_max + 1 ))
        curl -sS -d "[$id] rc=$rc, $size bytes in $parts parts" "$base/$ot" >/dev/null 2>&1 || true
        split_dir="${TMPDIR:-/tmp}/ish-remote.$code.parts"
        rm -rf "$split_dir"; mkdir -p "$split_dir"
        # split -C keeps lines whole, which matters: the far end reads these.
        split -C "$inline_max" "$out" "$split_dir/p" 2>/dev/null \
            || split -b "$inline_max" "$out" "$split_dir/p" 2>/dev/null
        part_i=0
        for part in "$split_dir"/p*; do
            [ -f "$part" ] || continue
            part_i=$((part_i + 1))
            { echo "[$id part $part_i/$parts]"; cat "$part"; } \
                | curl -sS --data-binary @- "$base/$ot" >/dev/null 2>&1 || true
        done
        rm -rf "$split_dir"
    fi
    done   # end of the per-message batch loop

    [ -f "$stopflag" ] && break
done

echo "ish-remote: done after $i polls"
