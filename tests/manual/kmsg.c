// kmsg: writing to /dev/kmsg (fs/mem.c, kernel/log.c).
//
// Reading the kernel log has always worked here; writing to it returned EPERM,
// so a guest could see the log but never add to it.
//
// That gap is load-bearing for Android. android::base's KernelLogger writes
// here, and before logd exists it is the ONLY place a dying process says why --
// servicemanager's fatal CHECKs go here and nowhere else. A silent EPERM means
// a process aborts with no message at all, which is exactly as much fun to
// debug as it sounds.
//
// Covered:
//   write        a record is accepted and appears in a subsequent read.
//   priority     the "<N>" syslog prefix is parsed off rather than printed as
//                part of the message.
//   framing      one write is one record: an embedded newline cannot split it
//                into two lines, because every reader of this buffer assumes
//                one record per line.
//   truncation   an oversized record reports the whole write consumed, so the
//                caller does not retry a tail that would be dropped again.
//   empty        a zero-length write is accepted and adds nothing.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "test_common.h"

#define MEM_DEV_MAJOR 1
#define KMSG_DEV_MINOR 11

static char kmsg_path[128];

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

// Only the device numbers matter -- a char device (1,11) anywhere is /dev/kmsg.
// On a root where mknod in /dev is not permitted (a realfs root without
// CAP_MKNOD, e.g. the CLI build), fall back to a tmpfs we can create it on.
// Is this path the kmsg CHARACTER DEVICE, rather than something that merely
// exists at that name? A regular file at /dev/kmsg reads back exactly what was
// written to it, so every positive check here passes and every negative one
// fails -- "the message text is logged" ok, "the <N> prefix is not part of it"
// FAIL -- which reads as the kernel having stopped stripping prefixes.
//
// That is not hypothetical: it is the state a device was found in, and
// chroot-setup.sh already warns about it for the Android tree ("plain-file
// kmsg ... its dying words go into the file instead of dmesg"). The outer root
// can be in it too. Ten confusing assertion failures across this file and
// logd_sink.c came from accepting a 24-byte regular file as the log device.
static int kmsg_is_device(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISCHR(st.st_mode))
        return 0;
    // Only the numbers matter; a char device (1,11) anywhere is /dev/kmsg.
    return major(st.st_rdev) == MEM_DEV_MAJOR && minor(st.st_rdev) == KMSG_DEV_MINOR;
}

static int kmsg_setup_device(void) {
    snprintf(kmsg_path, sizeof(kmsg_path), "/dev/kmsg");
    if (kmsg_is_device(kmsg_path))
        return 0;
    // Present but not the device: say so, then fall through to the fallback
    // below rather than testing against a file that echoes writes back.
    struct stat st;
    if (stat(kmsg_path, &st) == 0 && !S_ISCHR(st.st_mode))
        test_logf("/dev/kmsg is not a character device (mode %#o) -- "
                  "using a private one instead\n", (unsigned) st.st_mode);
    if (mknod(kmsg_path, S_IFCHR | 0666, makedev(MEM_DEV_MAJOR, KMSG_DEV_MINOR)) == 0)
        return 0;

    int mknod_errno = errno;
    const char *dir = "/tmp/kmsg-test";
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
        errno = mknod_errno;
        return -1;
    }
    if (mount("tmpfs", dir, "tmpfs", 0, NULL) != 0) {
        errno = mknod_errno;
        return -1;
    }
    snprintf(kmsg_path, sizeof(kmsg_path), "%s/kmsg", dir);
    if (mknod(kmsg_path, S_IFCHR | 0666, makedev(MEM_DEV_MAJOR, KMSG_DEV_MINOR)) != 0)
        return -1;
    test_logf("using %s (mknod in /dev failed: %s)\n", kmsg_path, strerror(mknod_errno));
    return 0;
}

static int kmsg_put(const char *record, size_t len) {
    int fd = open(kmsg_path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, record, len);
    close(fd);
    if (n < 0)
        return -1;
    return n == (ssize_t) len ? 0 : -1;
}

// Reads the whole log back. Returns a malloc'd NUL-terminated buffer, or NULL.
// A fresh open starts at offset 0, so this sees everything still in the ring.
//
// O_NONBLOCK is required, not tidiness. /dev/kmsg is a STREAM: once a reader
// has caught up, a blocking read waits for the next message rather than
// reporting end-of-file, exactly as on Linux -- `dmesg --follow` is that wait.
// The drain loop below stops on `n <= 0`, which a blocking fd never returns,
// so without this the test hangs forever on its last read instead of
// finishing. (It did: the emulator sat in ish_log_wait_past() until the
// harness's timeout killed it, with the guest's own alarm(60) never getting a
// chance to fire.) Non-blocking turns "caught up" into EAGAIN, which is what
// this loop is written to see.
static char *kmsg_slurp(void) {
    int fd = open(kmsg_path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return NULL;
    size_t cap = 1 << 16, used = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        close(fd);
        return NULL;
    }
    for (;;) {
        if (used + 4096 > cap) {
            char *bigger = realloc(buf, cap * 2);
            if (bigger == NULL)
                break;
            buf = bigger;
            cap *= 2;
        }
        ssize_t n = read(fd, buf + used, 4096);
        if (n <= 0)
            break;
        used += (size_t) n;
    }
    close(fd);
    buf[used] = '\0';
    return buf;
}

static int log_contains(const char *needle) {
    char *log = kmsg_slurp();
    if (log == NULL)
        return 0;
    int found = strstr(log, needle) != NULL;
    free(log);
    return found;
}

static void test_write_is_accepted(void) {
    // The whole point: this used to be EPERM.
    check(kmsg_put("ish-kmsg-plain-marker\n", strlen("ish-kmsg-plain-marker\n")) == 0,
          "a plain record is accepted");
    check(log_contains("ish-kmsg-plain-marker"), "and shows up in a read");
}

static void test_priority_prefix(void) {
    // KernelLogger emits "<3>tag: message". The prefix is metadata, not text --
    // printing it would put "<3>" in front of every Android log line.
    const char *rec = "<3>ish-kmsg-prio-marker\n";
    check(kmsg_put(rec, strlen(rec)) == 0, "a record with a <N> prefix is accepted");
    check(log_contains("ish-kmsg-prio-marker"), "the message text is logged");
    check(!log_contains("<3>ish-kmsg-prio-marker"), "the <N> prefix is not part of it");

    // Not a priority prefix: no digits, so it is ordinary text and must survive.
    const char *angle = "ish-kmsg-<angle>-marker\n";
    check(kmsg_put(angle, strlen(angle)) == 0, "a record containing < > is accepted");
    check(log_contains("ish-kmsg-<angle>-marker"), "text that merely looks like a prefix survives");

    // The cases that actually exercise the parser, because they start with '<'
    // and only the contents decide. Eating either would silently truncate a
    // message that never had a prefix at all.
    const char *word = "<abc>ish-kmsg-word-marker\n";
    check(kmsg_put(word, strlen(word)) == 0, "a record starting with <abc> is accepted");
    check(log_contains("<abc>ish-kmsg-word-marker"), "a non-numeric <...> is kept as text");

    const char *empty = "<>ish-kmsg-empty-marker\n";
    check(kmsg_put(empty, strlen(empty)) == 0, "a record starting with <> is accepted");
    check(log_contains("<>ish-kmsg-empty-marker"), "an empty <> is kept as text");

    // Three digits is the widest real prefix (<191> is the largest value).
    const char *wide = "<191>ish-kmsg-wide-marker\n";
    check(kmsg_put(wide, strlen(wide)) == 0, "a record with a three-digit prefix is accepted");
    check(log_contains("ish-kmsg-wide-marker"), "the message text is logged");
    check(!log_contains("<191>ish-kmsg-wide-marker"), "a three-digit prefix is parsed off");

    // Four digits is not a prefix, so none of it may be eaten.
    const char *toowide = "<1234>ish-kmsg-toowide-marker\n";
    check(kmsg_put(toowide, strlen(toowide)) == 0, "a record with four digits is accepted");
    check(log_contains("<1234>ish-kmsg-toowide-marker"), "four digits is text, not a prefix");
}

static void test_one_write_is_one_record(void) {
    // Readers of this buffer split on newlines, so an embedded newline must not
    // be able to forge a second record.
    const char *rec = "ish-kmsg-split-a\nish-kmsg-split-b\n";
    check(kmsg_put(rec, strlen(rec)) == 0, "a record containing a newline is accepted");
    char *log = kmsg_slurp();
    check(log != NULL, "read the log back");
    if (log == NULL)
        return;
    char *at = strstr(log, "ish-kmsg-split-a");
    check(at != NULL, "the record is present");
    if (at != NULL) {
        char *nl = strchr(at, '\n');
        check(nl != NULL && strstr(at, "ish-kmsg-split-b") != NULL &&
                  strstr(at, "ish-kmsg-split-b") < nl,
              "both halves stay on one line");
    }
    free(log);
}

static void test_truncation(void) {
    // Linux consumes the whole write and truncates the record. Reporting a
    // short write instead would send the caller into a retry loop over a tail
    // that gets dropped every time.
    size_t big = 8192;
    char *rec = malloc(big + 1);
    check(rec != NULL, "allocate an oversized record");
    if (rec == NULL)
        return;
    memset(rec, 'x', big);
    memcpy(rec, "ish-kmsg-long-marker", strlen("ish-kmsg-long-marker"));
    rec[big] = '\0';

    int fd = open(kmsg_path, O_WRONLY);
    check(fd >= 0, "open for the oversized write");
    if (fd >= 0) {
        ssize_t n = write(fd, rec, big);
        check(n == (ssize_t) big, "an oversized write reports the whole record consumed");
        close(fd);
    }
    check(log_contains("ish-kmsg-long-marker"), "and its beginning is logged");
    free(rec);
}

static void test_empty_write(void) {
    int fd = open(kmsg_path, O_WRONLY);
    check(fd >= 0, "open for the empty write");
    if (fd < 0)
        return;
    check(write(fd, "", 0) == 0, "a zero-length write is accepted");
    // A record of nothing but a newline has no text and must not add a blank
    // line to a log people read.
    check(write(fd, "\n", 1) == 1, "a newline-only write is accepted");
    close(fd);
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    if (kmsg_setup_device() < 0) {
        printf("SKIP kmsg: no /dev/kmsg available (errno=%d %s)\n", errno, strerror(errno));
        return finish_suite("kmsg");
    }
    test_logf("using %s\n", kmsg_path);

    test_write_is_accepted();
    test_priority_prefix();
    test_one_write_is_one_record();
    test_truncation();
    test_empty_write();

    return finish_suite("kmsg");
}
