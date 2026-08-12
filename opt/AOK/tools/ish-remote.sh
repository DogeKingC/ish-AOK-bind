#!/bin/sh
# ish-remote: run commands sent from elsewhere, so a debugging session does not
# cost a round trip per command.
#
#     sh /AOK/tools/ish-remote.sh FLcKa               # listen, using the code FLcKa
#     sh /AOK/tools/ish-remote.sh --keepalive FLcKa   # ...and survive backgrounding
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
# ISH_REMOTE_CMD_URL exists because the relay's free tier rate-limits the
# SENDER, and the sender is the one end that cannot simply wait: a debugging
# session is a stream of commands. Point it at any URL whose contents the far
# end can update -- a file on a git forge's raw view is the obvious one, since
# it needs no account on this side and no quota on theirs. Replies still go to
# the relay, which is fine: they are a fraction of the traffic and they come
# from this device rather than from whoever is driving it.
#
# Same line format either way, so nothing else changes:
#     ISH-REMOTE <code> <id> <base64 of the command>
#
# --keepalive addresses the thing that otherwise makes this useless on a phone:
# iOS suspends the app the moment it stops being frontmost, so the listener only
# polls while you are staring at it -- which is exactly when you are not reading
# the results. iSH declares the "audio" background mode (app/Info.plist) and
# exposes an OSS device at /dev/dsp, so playing silence keeps the app scheduled
# with the screen off. That is a real cost: it holds an audio session and drains
# battery, and iOS can still reclaim the app. Use it for a debugging session and
# stop it afterwards; it is off by default for those reasons.
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
#   ISH_REMOTE_DSP       audio device for --keepalive (default /dev/dsp)
#   ISH_REMOTE_CMD_URL   fetch commands from this URL instead of the relay
#   ISH_REMOTE_INLINE    bytes per reply message, split above it (default 3000)

set -u

base="${ISH_REMOTE_BASE:-https://ntfy.sh}"
dsp="${ISH_REMOTE_DSP:-/dev/dsp}"
cmd_url="${ISH_REMOTE_CMD_URL:-}"
interval="${ISH_REMOTE_INTERVAL:-4}"
max="${ISH_REMOTE_MAX:-900}"
inline_max="${ISH_REMOTE_INLINE:-3000}"

die() { echo "ish-remote: $*" >&2; exit 1; }

# Network calls retry, and -- the part that matters -- check the HTTP status.
# curl -sS exits 0 on an HTTP error, so a rejected message looks exactly like a
# delivered one. That is not hypothetical: ntfy.sh answered 429 "daily message
# quota reached" and the listener cheerfully reported every reply as sent while
# none arrived. Anything that reports success without checking the status is
# lying by omission.
#
# Everything is sent from a FILE rather than a pipe, because a retry has to be
# able to send the same bytes again and stdin is gone after the first attempt.
net_fails=0
net_error=""
_netbody="${TMPDIR:-/tmp}/ish-remote.netbody.$$"

# net_req <url> [extra curl args...] -- body on stdout, status checked.
net_req() {
    _url="$1"; shift
    _try=0
    while [ "$_try" -lt 3 ]; do
        _try=$((_try + 1))
        _code=$(curl -sS --max-time 25 -o "$_netbody" -w '%{http_code}' "$@" "$_url" 2>/dev/null)
        case "$_code" in
            2*) cat "$_netbody" 2>/dev/null; rm -f "$_netbody"; net_fails=0; net_error=""; return 0 ;;
            429) net_error="relay refused: quota or rate limit (429). Wait, or set ISH_REMOTE_BASE to another relay." ;;
            "" ) net_error="no response from $_url (offline?)" ;;
            *  ) net_error="HTTP $_code from $_url" ;;
        esac
        sleep 2
    done
    rm -f "$_netbody"
    net_fails=$((net_fails + 1))
    return 1
}

net_get()  { net_req "$1"; }
net_post_file() { net_req "$2" --data-binary @"$1"; }
net_post_str()  {
    _tmp="${TMPDIR:-/tmp}/ish-remote.send.$$"
    printf '%s' "$1" > "$_tmp" || return 1
    net_post_file "$_tmp" "$2"; _rc=$?
    rm -f "$_tmp"
    return $_rc
}

# Sending output is best-effort but never silent: the far end sees only an
# absence, so a failure has to be visible HERE.
say() {
    if ! net_post_str "$1" "$base/$ot" >/dev/null; then
        echo "!! reply not delivered: $net_error" >&2
    fi
}

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
    if net_post_str "ISH-REMOTE $code $id $b64" "$base/$(cmd_topic "$code")" >/dev/null; then
        echo "sent (id $id)"
    else
        die "send failed: $net_error"
    fi
    exit 0
fi

# ---- listener -------------------------------------------------------------
keepalive=0
if [ "${1:-}" = "--keepalive" ]; then
    keepalive=1
    shift
fi

code="${1:-${ISH_REMOTE_CODE:-}}"
[ -n "$code" ] || die "no code. Usage: ish-remote.sh <code>   (a shared secret; without it this does nothing)"

ct=$(cmd_topic "$code")
ot=$(out_topic "$code")
seen="${TMPDIR:-/tmp}/ish-remote.$code.seen"
# The id currently being run, removed once it finishes. Its whole job is to
# survive the listener NOT finishing -- see the startup report below.
inflight="${TMPDIR:-/tmp}/ish-remote.$code.inflight"
stopflag="${TMPDIR:-/tmp}/ish-remote.$code.stop"
rm -f "$stopflag"
# Ids already run. Kept across restarts so resuming does not replay the topic's
# whole history; delete it to deliberately re-run everything.
[ -f "$seen" ] || : > "$seen"

echo "================================================================"
echo " ish-remote listening"
if [ -n "$cmd_url" ]; then
    echo "   commands from: $cmd_url  (no relay quota on the sending side)"
else
    echo "   command topic: $base/$ct"
fi
echo "   reply topic:   $base/$ot"
echo "   WARNING: every command sent with this code runs here, as you."
echo "   Ctrl-C to stop. Do not leave it running."
echo "================================================================"

ka_pid=""
cleanup() {
    [ -n "$ka_pid" ] && kill "$ka_pid" 2>/dev/null
    rm -f "$stopflag" 2>/dev/null
    exit 0
}
# Ctrl-C and ordinary termination both have to stop the silence, or the app is
# left holding an audio session with nothing listening.
trap cleanup INT TERM HUP EXIT

if [ "$keepalive" -eq 1 ]; then
    if [ -c "$dsp" ]; then
        # Silence at the device's default format (48 kHz, S16LE): zeros are
        # silence in any PCM encoding, so the format never has to be agreed.
        # dd from /dev/zero rather than a loop of writes, so this costs
        # essentially no CPU while it holds the audio session open.
        ( while : ; do dd if=/dev/zero of="$dsp" bs=8192 count=64 2>/dev/null || sleep 1; done ) &
        ka_pid=$!
        echo "   keepalive: playing silence to $dsp (pid $ka_pid) so iOS does not suspend us"
        echo "   this drains battery -- stop the listener when you are done"
    else
        echo "   keepalive: $dsp is not a character device; backgrounding will still suspend us" >&2
        keepalive=0
    fi
fi

# A command is marked seen BEFORE it runs, deliberately: one that kills this
# listener (or the whole app) must not be retried forever on every restart.
# The cost of that is silence -- the far end sees a command it sent simply
# never answered, and cannot tell it apart from one that was never delivered.
# That happened for real: iSH was suspended mid-command, the listener came
# back, skipped the id as already-seen, and the answer was just missing.
# Reporting it on restart costs one message and turns "vanished" into "died
# running this".
if [ -s "$inflight" ]; then
    dead_id=$(cat "$inflight" 2>/dev/null)
    rm -f "$inflight"
    startup_note=" -- NOTE: id $dead_id did not finish (the listener died or was suspended running it); it will NOT be retried, resend it with a new id if you still want it"
else
    startup_note=""
fi

# Announce readiness on the reply topic, so the far end knows the listener is
# actually up before it starts sending into the void.
if ! net_post_str "ish-remote up on $(uname -m 2>/dev/null): waiting for commands$startup_note" \
        "$base/$ot" >/dev/null; then
    die "cannot use the relay: $net_error"
fi

i=0
while [ "$i" -lt "$max" ]; do
    i=$((i + 1))
    sleep "$interval"

    # EVERY pending message, oldest first -- not just the newest. iOS suspends
    # iSH whenever it is not the foreground app, so a sender working in the
    # meantime queues several commands and they all arrive at once on resume.
    # Taking only the latest silently dropped the rest, which looks from the
    # far end like commands vanishing.
    if [ -n "$cmd_url" ]; then
        # Cache-busted: a CDN in front of the file will otherwise serve a
        # stale copy for minutes, which reads as the channel being dead.
        fetch_url="$cmd_url?cb=$(date +%s 2>/dev/null || echo $i)"
    else
        fetch_url="$base/$ct/json?poll=1&since=all"
    fi
    if ! batch=$(net_get "$fetch_url"); then
        # Three failed tries in a row. Say it once per stretch rather than
        # every poll, and keep going: connectivity usually comes back.
        [ "$net_fails" -eq 1 ] && echo "!! poll failed: $net_error" >&2
        continue
    fi
    [ -n "$batch" ] || continue

    # Via a file, not a pipe: a command run below inherits this loop's stdin,
    # and anything that reads stdin would swallow the rest of the queue --
    # which looked exactly like commands being dropped.
    batchfile="${TMPDIR:-/tmp}/ish-remote.$code.batch"
    printf '%s\n' "$batch" > "$batchfile" 2>/dev/null || continue
    while IFS= read -r msg; do
        [ -n "$msg" ] || continue

    # The relay wraps each command in JSON; a plain URL serves the line as-is.
    # Telling them apart on the leading brace avoids needing to know which
    # source this is, and a JSON parser is not required either way because the
    # payload is deliberately all JSON-safe characters.
    case "$msg" in
        \{*) payload=$(printf '%s' "$msg" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p') ;;
        *)   payload="$msg" ;;
    esac
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
        say "listener stopping"
        echo "--- stop received"
        : > "$stopflag"
        break
    fi

    out="${TMPDIR:-/tmp}/ish-remote.$code.out"
    # Combined stdout+stderr, and the exit status, because both matter when
    # something you cannot see went wrong. A command that cannot even be
    # written out (full disk, unwritable TMPDIR) still has to be reported.
    if ! : > "$out" 2>/dev/null; then
        say "[$id] cannot write $out -- no space, or TMPDIR unwritable"
        continue
    fi
    # stdin from /dev/null: a command that reads stdin must not consume the
    # queue, and an interactive one must fail rather than hang the listener.
    # Note what is running before running it, so a listener that does not come
    # back from this can say so next time it starts (see the startup note).
    printf '%s\n' "$id" > "$inflight" 2>/dev/null
    sh -c "$cmd" > "$out" 2>&1 < /dev/null
    rc=$?
    rm -f "$inflight" 2>/dev/null
    echo "rc=$rc" >> "$out"
    cat "$out"

    size=$(wc -c < "$out" 2>/dev/null || echo 0)
    # A command that printed nothing at all still needs an answer, or the far
    # end cannot tell "it ran and said nothing" from "it never ran".
    if [ "$size" -eq 0 ]; then
        say "[$id] rc=$rc, no output"
    elif [ "$size" -le "$inline_max" ]; then
        if ! net_post_file "$out" "$base/$ot" >/dev/null; then
            echo "!! $size bytes of output not delivered: $net_error" >&2
        fi
    else
        # Chunk it over the relay rather than depending on a paste host: the
        # device that most needs this (a phone) is the one most likely to
        # reach the relay and nothing else -- observed exactly that, ntfy
        # fine and the paste upload refused.
        parts=$(( size / inline_max + 1 ))
        say "[$id] rc=$rc, $size bytes in $parts parts"
        split_dir="${TMPDIR:-/tmp}/ish-remote.$code.parts"
        rm -rf "$split_dir"; mkdir -p "$split_dir"
        # split -C keeps lines whole, which matters: the far end reads these.
        split -C "$inline_max" "$out" "$split_dir/p" 2>/dev/null \
            || split -b "$inline_max" "$out" "$split_dir/p" 2>/dev/null
        part_i=0
        for part in "$split_dir"/p*; do
            [ -f "$part" ] || continue
            part_i=$((part_i + 1))
            _labeled="$part.msg"
            { echo "[$id part $part_i/$parts]"; cat "$part"; } > "$_labeled"
            if ! net_post_file "$_labeled" "$base/$ot" >/dev/null; then
                echo "!! part $part_i/$parts not delivered: $net_error" >&2
            fi
        done
        rm -rf "$split_dir"
    fi
    done < "$batchfile"
    rm -f "$batchfile" 2>/dev/null

    [ -f "$stopflag" ] && break
done

echo "ish-remote: done after $i polls"
