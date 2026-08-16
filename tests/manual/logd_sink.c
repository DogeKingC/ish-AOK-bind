// The logd sink: does a liblog-shaped datagram reach the kernel log?
//
// This is the test the Android side cannot give us cheaply. liblog connects an
// AF_UNIX SOCK_DGRAM socket to /dev/socket/logdw and writes a packed header
// plus priority, tag and message. Reproducing that here means the socket, the
// path mapping and the parse are all checked without an Android image, a
// device, or logd -- and it pins the wire format kernel/logd_sink.c decodes,
// so a future change to either side fails here instead of on a phone.
//
// Checks, in order:
//   socket     /dev/socket/logdw exists, is a socket, and accepts a connect
//   record     a well-formed record comes back out of /dev/kmsg, parsed --
//              right tag, right message, right priority letter, right buffer
//   raw        a packet that is NOT the expected shape is still reported
//              rather than dropped, which is the whole point of the sink
//   state      /proc/ish/logd counts what went through

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <unistd.h>

#include "test_common.h"

#define LOGDW "/dev/socket/logdw"
#define MEM_DEV_MAJOR 1
#define KMSG_DEV_MINOR 11

static char kmsg_path[128];

static void check(int cond, const char *what) {
    if (!cond)
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
    else
        test_logf("ok %s\n", what);
    if (!cond)
        failures_total++;
}

// liblog's on-the-wire header. Must match kernel/logd_sink.c.
struct android_log_header {
    uint8_t id;
    uint16_t tid;
    uint32_t sec;
    uint32_t nsec;
} __attribute__((packed));

#define LOG_ID_MAIN 0
#define LOG_ID_CRASH 4
#define ANDROID_LOG_ERROR 6

// Only the device numbers matter -- a char device (1,11) anywhere is
// /dev/kmsg. On a realfs root mknod in /dev is not permitted, so fall back to
// a tmpfs, exactly as tests/manual/kmsg.c does.
static int kmsg_setup_device(void) {
    snprintf(kmsg_path, sizeof(kmsg_path), "/dev/kmsg");
    if (access(kmsg_path, F_OK) == 0)
        return 0;
    if (mknod(kmsg_path, S_IFCHR | 0666, makedev(MEM_DEV_MAJOR, KMSG_DEV_MINOR)) == 0)
        return 0;
    int mknod_errno = errno;
    const char *dir = "/tmp/logd-kmsg";
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) { errno = mknod_errno; return -1; }
    if (mount("tmpfs", dir, "tmpfs", 0, NULL) != 0) { errno = mknod_errno; return -1; }
    snprintf(kmsg_path, sizeof(kmsg_path), "%s/kmsg", dir);
    if (mknod(kmsg_path, S_IFCHR | 0666, makedev(MEM_DEV_MAJOR, KMSG_DEV_MINOR)) != 0)
        return -1;
    test_logf("using %s (mknod in /dev failed: %s)\n", kmsg_path, strerror(mknod_errno));
    return 0;
}

// Reads the whole of /dev/kmsg that is currently buffered. The sink writes
// through ish_log_write_record, the same path android::base's KernelLogger
// uses, so this is where a delivered record lands.
static int kmsg_contains(const char *needle) {
    // Plain O_RDONLY, as tests/manual/kmsg.c does: a fresh open starts at
    // offset 0 and reads the whole ring, and O_NONBLOCK is refused here.
    int fd = open(kmsg_path, O_RDONLY);
    if (fd < 0)
        return -1;
    static char buf[262144];
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        if (n <= 0)
            break;
        used += (size_t) n;
        if (used >= sizeof(buf) - 1)
            break;
    }
    close(fd);
    buf[used] = '\0';
    return strstr(buf, needle) != NULL;
}

// Builds a liblog datagram: header, priority, NUL-terminated tag, message.
static size_t build_record(char *out, uint8_t log_id, uint8_t prio,
                           const char *tag, const char *msg) {
    struct android_log_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.id = log_id;
    hdr.tid = 4321;
    hdr.sec = 1000;
    hdr.nsec = 0;
    size_t off = 0;
    memcpy(out + off, &hdr, sizeof(hdr)); off += sizeof(hdr);
    out[off++] = (char) prio;
    size_t tag_len = strlen(tag) + 1;
    memcpy(out + off, tag, tag_len); off += tag_len;
    size_t msg_len = strlen(msg) + 1;
    memcpy(out + off, msg, msg_len); off += msg_len;
    return off;
}

static int proc_ish_logd(char *buf, size_t size) {
    int fd = open("/proc/ish/logd", O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return 0;
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    struct stat st;
    if (stat(LOGDW, &st) != 0) {
        printf("SKIP logd_sink: %s does not exist (errno=%d %s)\n",
               LOGDW, errno, strerror(errno));
        return finish_suite("logd_sink");
    }
    check(S_ISSOCK(st.st_mode), "logdw is a socket");

    if (kmsg_setup_device() != 0) {
        printf("SKIP logd_sink: no readable kmsg device (errno=%d %s)\n",
               errno, strerror(errno));
        return finish_suite("logd_sink");
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    check(fd >= 0, "create AF_UNIX SOCK_DGRAM");
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof(un.sun_path), "%s", LOGDW);
    // liblog connects rather than sending to an address, so connect is the
    // operation that has to work.
    check(connect(fd, (struct sockaddr *) &un, sizeof(un)) == 0,
          "connect to the logdw socket");

    // A well-formed record. The marker makes it findable in a busy dmesg.
    char rec[512];
    const char *tag = "ishLogdTest";
    const char *msg = "hello from the logd sink test 0xC0FFEE";
    size_t len = build_record(rec, LOG_ID_MAIN, ANDROID_LOG_ERROR, tag, msg);
    check(write(fd, rec, len) == (ssize_t) len, "write a liblog record");

    // The sink formats and forwards on its own thread, so give it a moment
    // before concluding it did not arrive.
    int seen_msg = 0, seen_tag = 0;
    for (int i = 0; i < 50 && !seen_msg; i++) {
        usleep(20000);
        seen_msg = kmsg_contains(msg) == 1;
    }
    seen_tag = kmsg_contains(tag) == 1;
    check(seen_msg, "the message reaches /dev/kmsg");
    check(seen_tag, "and is labelled with the tag liblog sent");
    // E for ANDROID_LOG_ERROR, and the main buffer: proves the header was
    // decoded rather than the payload merely being echoed.
    check(kmsg_contains("logd/main E/") == 1,
          "priority and buffer are decoded from the header");

    // A packet that is not the expected shape must still be reported. This is
    // the property that makes a wrong guess about liblog's format survivable.
    const char *garbage = "ThisIsNotALiblogPacket_ishRawMarker";
    check(write(fd, garbage, strlen(garbage)) == (ssize_t) strlen(garbage),
          "write a malformed record");
    int seen_raw = 0;
    for (int i = 0; i < 50 && !seen_raw; i++) {
        usleep(20000);
        seen_raw = kmsg_contains("logd/raw") == 1;
    }
    check(seen_raw, "an unparsed packet is reported raw, not dropped");

    // The binary buffers (events/stats/security) carry a 4-byte tag id and
    // typed values -- no priority byte, no NUL-terminated strings. Running the
    // text parse over one produced `logd/events ?/ (1128:1128):` on device: an
    // empty tag and an empty message, which is worse than saying nothing.
    char ev[64];
    struct android_log_header evh;
    memset(&evh, 0, sizeof(evh));
    evh.id = 2; // events
    evh.tid = 99;
    size_t eoff = 0;
    memcpy(ev + eoff, &evh, sizeof(evh)); eoff += sizeof(evh);
    uint32_t event_tag = 1397638484;
    memcpy(ev + eoff, &event_tag, sizeof(event_tag)); eoff += sizeof(event_tag);
    ev[eoff++] = 0x00; ev[eoff++] = 0x11; ev[eoff++] = 0x22; ev[eoff++] = 0x33;
    check(write(fd, ev, eoff) == (ssize_t) eoff, "write an events-buffer record");
    int seen_bin = 0;
    for (int i = 0; i < 50 && !seen_bin; i++) {
        usleep(20000);
        seen_bin = kmsg_contains("logd/events binary") == 1;
    }
    check(seen_bin, "a binary buffer is reported as binary, not parsed as text");
    check(kmsg_contains("tag=1397638484") == 1,
          "and its event tag id is reported");

    char state[4096];
    if (proc_ish_logd(state, sizeof(state)) == 0) {
        check(strstr(state, "no sink") == NULL, "/proc/ish/logd reports a live sink");
        check(strstr(state, "records ") != NULL, "and counts the records it forwarded");
        check(strstr(state, "unparsed ") != NULL,
              "and counts the ones it could not parse");
    } else {
        test_logf("skip /proc/ish/logd (not present)\n");
    }

    close(fd);
    return finish_suite("logd_sink");
}
