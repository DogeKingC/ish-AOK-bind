// A stand-in for logd, covering the one thing bring-up needs: somewhere for
// liblog to write.
//
// WHY NOT REAL logd. logd does not open its own sockets. It asks init for them
// -- android_get_control_socket("logdw") reads the fd number out of
// ANDROID_SOCKET_logdw, which init created, bound and passed down. There is no
// init here, so a logd started by hand has no socket to serve and nothing can
// reach it. That is the same wall the property area hit (servicemanager cannot
// set a property because there is no property service) and it gets the same
// answer: supply the thing directly instead of building the daemon that would
// have supplied it.
//
// WHAT THIS IS NOT. There is no ring buffer, no reader socket, no logcat, no
// filtering by tag or priority, and nothing is retained: a record is formatted
// and pushed into the kernel log, where `dmesg` shows it. That is enough to
// stop Android failing silently, which is the actual blocker -- everything
// else logd does is comfort. If something later needs `logcat`, this is the
// wrong object and real logd (plus socket activation) is the right one.
//
// HOW IT REACHES THE GUEST. A guest AF_UNIX address is a fakefs S_IFSOCK
// inode; the host socket behind it lives at sock_tmp_prefix.<socket_id>, with
// the id assigned lazily by the unix socket layer. So creating the inode and
// asking fs/sock.c which host path it maps to (unix_socket_host_path_for) is
// enough for the guest's connect("/dev/socket/logdw") to land on a socket this
// file owns. Nothing in liblog has to change, and nothing else in iSH does.
//
// THE WIRE FORMAT is liblog's, and it was MEASURED rather than assumed. A
// datagram is a packed 11-byte header -- log id, tid (u16), realtime sec and
// nsec (u32 each) -- then a priority byte, a NUL-terminated tag and a
// NUL-terminated message. Captured from a real Android binary's liblog on
// device, by binding this socket from an ordinary guest process and dumping
// what arrived:
//
//   04 | 53 00 | 8d 06 81 6a | 18 ee 1f 02 | 07 | 6c 69 62 63 00 | "Fatal ..."
//   id   tid=83   sec              nsec      F    "libc"           message
//
// id 4 is the crash buffer, and the seconds field was the wall clock at the
// time of capture, which is what makes the alignment unambiguous rather than
// merely plausible.
//
// The parse is still total: a packet that fails the length or termination
// checks is emitted RAW instead of being dropped, so a future liblog that
// changes this costs readability rather than the log line. Check the raw form
// against this comment before assuming the socket is broken.

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "kernel/log.h"
#include "kernel/logd_sink.h"
#include "fs/fd.h"
#include "fs/inode.h"
#include "fs/path.h"
#include "fs/proc.h"
#include "fs/sock.h"
#include "util/sync.h"

#define LOGD_SOCKET_DIR  "/dev/socket"
#define LOGD_SOCKET_PATH "/dev/socket/logdw"
#define LOGD_MAX_RECORD  (8 * 1024)

// liblog's header, packed exactly as it goes on the wire.
struct android_log_header {
    uint8_t id;
    uint16_t tid;
    uint32_t sec;
    uint32_t nsec;
} __attribute__((packed));
_Static_assert(sizeof(struct android_log_header) == 11, "liblog header ABI");

// The log ids, in liblog's order. An id outside this list is reported by
// number rather than guessed at.
static const char *const logd_buffer_names[] = {
    "main", "radio", "events", "system", "crash", "stats", "security", "kernel",
};

static lock_t logd_lock = LOCK_INITIALIZER;
static int logd_fd = -1;
static pthread_t logd_thread;
static bool logd_running = false;
static char logd_path[MAX_PATH + 1];
static char logd_host_path[MAX_PATH + 1];
// Held for the sink's lifetime; see unix_socket_host_path_for.
static struct inode_data *logd_inode;
static unsigned long logd_records;
static unsigned long logd_malformed;
static int logd_last_err;

// Android priorities are 0..7; the letter is what logcat prints and what
// anyone reading dmesg will recognise.
static char logd_priority_letter(uint8_t prio) {
    static const char letters[] = "??VDIWEF";
    return prio < sizeof(letters) - 1 ? letters[prio] : '?';
}

// Formats one datagram into `out`. Deliberately total: anything that does not
// parse is still rendered, because a dropped line is exactly the failure this
// file exists to prevent.
// events, stats and security are the BINARY buffers: their payload is a
// 4-byte tag id followed by typed values, with no priority byte and no
// NUL-terminated strings. Running the text parse over one produces a line with
// an empty tag and an empty message, which is worse than saying nothing --
// observed on device as `logd/events ?/ (1128:1128):`.
static bool logd_buffer_is_binary(uint8_t id) {
    return id == 2 /* events */ || id == 5 /* stats */ || id == 6 /* security */;
}

static size_t logd_format(const char *pkt, size_t len, uint32_t sender_pid,
                          char *out, size_t out_size) {
    if (len > sizeof(struct android_log_header) + 2 &&
        logd_buffer_is_binary((uint8_t) pkt[0])) {
        struct android_log_header hdr;
        memcpy(&hdr, pkt, sizeof(hdr));
        const char *body = pkt + sizeof(hdr);
        size_t body_len = len - sizeof(hdr);
        uint32_t event_tag = 0;
        if (body_len >= sizeof(event_tag))
            memcpy(&event_tag, body, sizeof(event_tag));
        // The tag id indexes event-log-tags, which is a file we do not have,
        // so report the number and the size rather than inventing a name. A
        // short hex preview is enough to tell two events apart.
        int n = snprintf(out, out_size, "logd/%s binary (%u:%u): tag=%u, %zu bytes",
                         hdr.id < sizeof(logd_buffer_names) / sizeof(logd_buffer_names[0])
                             ? logd_buffer_names[hdr.id] : "buf",
                         sender_pid, hdr.tid, event_tag, body_len);
        if (n > 0)
            return (size_t) n < out_size ? (size_t) n : out_size - 1;
    }

    if (len > sizeof(struct android_log_header) + 2) {
        struct android_log_header hdr;
        memcpy(&hdr, pkt, sizeof(hdr));
        const char *body = pkt + sizeof(hdr);
        size_t body_len = len - sizeof(hdr);

        uint8_t prio = (uint8_t) body[0];
        const char *tag = body + 1;
        size_t tag_max = body_len - 1;
        size_t tag_len = strnlen(tag, tag_max);
        // The tag must be NUL-terminated inside the packet, and something must
        // follow it, or this is not the layout we think it is.
        if (tag_len < tag_max) {
            const char *msg = tag + tag_len + 1;
            size_t msg_len = strnlen(msg, tag_max - tag_len - 1);
            const char *buffer = hdr.id < sizeof(logd_buffer_names) / sizeof(logd_buffer_names[0])
                                     ? logd_buffer_names[hdr.id] : NULL;
            char buffer_desc[16];
            if (buffer == NULL) {
                snprintf(buffer_desc, sizeof(buffer_desc), "buf%u", hdr.id);
                buffer = buffer_desc;
            }
            // pid is the guest process; tid is what liblog put in the
            // header. Both, because a native reader expects the tid and
            // anyone debugging wants the pid they can see in ps.
            int n = snprintf(out, out_size, "logd/%s %c/%.*s(%u:%u): %.*s",
                             buffer, logd_priority_letter(prio),
                             (int) tag_len, tag, sender_pid, hdr.tid,
                             (int) msg_len, msg);
            if (n > 0)
                return (size_t) n < out_size ? (size_t) n : out_size - 1;
        }
    }

    // Unparsed. Say so, and print what arrived rather than swallowing it.
    lock(&logd_lock, 0);
    logd_malformed++;
    unlock(&logd_lock);
    size_t show = len < 160 ? len : 160;
    int n = snprintf(out, out_size, "logd/raw pid %u (%zu bytes, unparsed): %.*s",
                     sender_pid, len, (int) show, pkt);
    if (n <= 0)
        return 0;
    return (size_t) n < out_size ? (size_t) n : out_size - 1;
}

static void *logd_drain(void *arg) {
    int fd = (int) (intptr_t) arg;
    char pkt[LOGD_MAX_RECORD];
    char line[LOGD_MAX_RECORD + 128];
    for (;;) {
        ssize_t n = recv(fd, pkt, sizeof(pkt), 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break; // the socket was closed under us: this sink is done
        }
        if (n == 0)
            continue;
        // A guest unix datagram arrives with an internal credential header on
        // the host wire; nothing has stripped it for us here. It also tells us
        // which guest process sent the record, which is worth putting in the
        // line.
        struct ucred_ cred;
        memset(&cred, 0, sizeof(cred));
        size_t off = unix_dgram_strip_cred(pkt, (size_t) n, &cred);
        size_t len = logd_format(pkt + off, (size_t) n - off, cred.pid,
                                 line, sizeof(line));
        if (len > 0) {
            ish_log_write_record(line, len);
            lock(&logd_lock, 0);
            logd_records++;
            unlock(&logd_lock);
        }
    }
    return NULL;
}

// Tears down a running sink. Called with logd_lock held.
static void logd_stop_locked(void) {
    if (!logd_running)
        return;
    int fd = logd_fd;
    logd_fd = -1;
    logd_running = false;
    // Closing the fd is what ends the drain thread's blocking recv.
    if (fd >= 0)
        close(fd);
    pthread_join(logd_thread, NULL);
    if (logd_host_path[0] != '\0')
        unlink(logd_host_path);
    if (logd_inode != NULL) {
        inode_release(logd_inode);
        logd_inode = NULL;
    }
}

int logd_sink_create(const char *prefix) {
    if (prefix == NULL)
        prefix = "";
    // "/" means the current root, the same convention /proc/ish/property_area
    // uses, and the prefix is glued to an absolute path so it must not end in
    // a slash of its own.
    size_t prefix_len = strlen(prefix);
    while (prefix_len > 0 && prefix[prefix_len - 1] == '/')
        prefix_len--;

    char dir[MAX_PATH + 1], path[MAX_PATH + 1];
    if (prefix_len + strlen(LOGD_SOCKET_PATH) >= MAX_PATH)
        return _ENAMETOOLONG;
    snprintf(dir, sizeof(dir), "%.*s%s", (int) prefix_len, prefix, LOGD_SOCKET_DIR);
    snprintf(path, sizeof(path), "%.*s%s", (int) prefix_len, prefix, LOGD_SOCKET_PATH);

    lock(&logd_lock, 0);
    logd_stop_locked();
    logd_last_err = 0;

    // /dev/socket is init's directory; nothing else creates it here.
    int err = generic_mkdirat(AT_PWD, dir, 0755);
    if (err < 0 && err != _EEXIST)
        goto fail;

    // Replace whatever is at the path: a stale S_IFSOCK inode from a previous
    // boot has an id whose host socket is long gone, and bind() refuses to
    // reuse an existing name anyway.
    generic_unlinkat(AT_PWD, path);
    err = generic_mknodat(AT_PWD, path, S_IFSOCK | 0666, 0);
    if (err < 0)
        goto fail;

    err = unix_socket_host_path_for(path, logd_host_path, sizeof(logd_host_path),
                                    &logd_inode);
    if (err < 0)
        goto fail;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        err = errno_map();
        goto fail;
    }
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    if (strlen(logd_host_path) >= sizeof(un.sun_path)) {
        close(fd);
        err = _ENAMETOOLONG;
        goto fail;
    }
    strcpy(un.sun_path, logd_host_path);
    unlink(logd_host_path); // ours from a previous run, if anything
    if (bind(fd, (struct sockaddr *) &un, sizeof(un)) < 0) {
        // The real errno, not a guess. Reporting EADDRINUSE for every bind
        // failure sent the first device diagnosis down the wrong path: the
        // boot-time sink failed with "error -98" when the actual cause was
        // something else entirely, and the number said nothing about it.
        err = errno_map();
        close(fd);
        goto fail;
    }

    if (pthread_create(&logd_thread, NULL, logd_drain, (void *) (intptr_t) fd) != 0) {
        close(fd);
        unlink(logd_host_path);
        err = _ENOMEM;
        goto fail;
    }

    logd_fd = fd;
    logd_running = true;
    logd_records = 0;
    logd_malformed = 0;
    snprintf(logd_path, sizeof(logd_path), "%s", path);
    unlock(&logd_lock);
    return 0;

fail:
    if (logd_inode != NULL) {
        inode_release(logd_inode);
        logd_inode = NULL;
    }
    logd_last_err = err;
    logd_host_path[0] = '\0';
    snprintf(logd_path, sizeof(logd_path), "%s", path);
    unlock(&logd_lock);
    return err;
}

void logd_sink_start(void) {
    int err = logd_sink_create("");
    if (err < 0)
        ish_printk("logd sink: could not create %s (%d)\n", LOGD_SOCKET_PATH, err);
}

// ---------------------------------------------------------------------------
// /proc/ish/logd
// ---------------------------------------------------------------------------
//
// The same reasoning as /proc/ish/property_area: from inside the guest, "no
// Android logs are appearing" and "the sink was never created" look identical
// and call for opposite next steps.

int logd_sink_show(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    lock(&logd_lock, 0);
    if (!logd_running) {
        proc_printf(buf, "no sink: %s (error %d)\n",
                    logd_path[0] != '\0' ? logd_path : LOGD_SOCKET_PATH, logd_last_err);
    } else {
        proc_printf(buf, "path %s\n", logd_path);
        proc_printf(buf, "host %s\n", logd_host_path);
        proc_printf(buf, "records %lu\n", logd_records);
        // Non-zero here means the wire format is not what this file expects;
        // the raw bytes are in dmesg. See the header comment.
        if (logd_malformed > 0)
            proc_printf(buf, "unparsed %lu\n", logd_malformed);
    }
    unlock(&logd_lock);
    return 0;
}

int logd_sink_update(struct proc_entry *UNUSED(entry), struct proc_data *data) {
    size_t start = 0, end = data->size;
    while (start < end && (data->data[start] == ' ' || data->data[start] == '\t' ||
                           data->data[start] == '\r' || data->data[start] == '\n'))
        start++;
    while (end > start && (data->data[end - 1] == ' ' || data->data[end - 1] == '\t' ||
                           data->data[end - 1] == '\r' || data->data[end - 1] == '\n'))
        end--;

    size_t len = end - start;
    if (len >= MAX_PATH)
        return _ENAMETOOLONG;
    char prefix[MAX_PATH + 1];
    memcpy(prefix, &data->data[start], len);
    prefix[len] = '\0';
    return logd_sink_create(prefix);
}
