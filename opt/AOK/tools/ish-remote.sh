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
# the reply topic (or, when large, to a paste whose URL it sends). ntfy.sh is a
# public relay and needs no account.
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
#   ISH_REMOTE_INLINE    reply inline up to N bytes, paste above that (default 3000)

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
state="${TMPDIR:-/tmp}/ish-remote.$code.last"
last=$(cat "$state" 2>/dev/null || echo "")

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

    # Newest cached message on the command topic. since=all + tail -1 is
    # robust to the listener having been busy running a slow command: the
    # freshest message is always the last line regardless of timing.
    msg=$(curl -sS "$base/$ct/json?poll=1&since=all" 2>/dev/null | tail -1)
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
    [ "$id" != "$last" ] || continue            # already ran this one

    cmd=$(printf '%s' "$b64" | base64 -d 2>/dev/null)
    if [ -z "$cmd" ]; then
        last="$id"; echo "$last" > "$state" 2>/dev/null || true
        continue
    fi

    echo
    echo "--- [$id] running: $cmd"
    if [ "$cmd" = "stop" ] || [ "$cmd" = "ish-remote-stop" ]; then
        curl -sS -d "listener stopping" "$base/$ot" >/dev/null 2>&1 || true
        echo "--- stop received"
        last="$id"; echo "$last" > "$state" 2>/dev/null || true
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
    if [ "$size" -gt "$inline_max" ]; then
        # Too big for one relay message: stash it on a paste and send the URL.
        url=$(curl -sS --data-binary @"$out" https://paste.rs 2>/dev/null | tail -1)
        case "$url" in
            http*) curl -sS -d "[$id] rc=$rc, output ($size bytes): $url" "$base/$ot" >/dev/null 2>&1 || true ;;
            *)     curl -sS -d "[$id] rc=$rc, output was $size bytes and the paste upload failed" "$base/$ot" >/dev/null 2>&1 || true ;;
        esac
    else
        curl -sS --data-binary @"$out" "$base/$ot" >/dev/null 2>&1 || true
    fi

    last="$id"
    echo "$last" > "$state" 2>/dev/null || true
done

echo "ish-remote: done after $i polls"
