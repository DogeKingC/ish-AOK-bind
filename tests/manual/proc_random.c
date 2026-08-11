// proc_random: /proc/sys/kernel/random/{boot_id,uuid} (fs/proc/sys.c).
//
// boot_id's whole contract is that it is ONE value: constant for this boot,
// different across boots. Callers read it once and cache it -- libbinder does,
// and refuses to start when it reads an empty or malformed one -- so a reader
// that got a different value than everyone else would carry it for the rest of
// the run with nothing to reveal the disagreement.
//
// Covered:
//   agreement    concurrent first readers all get the same boot_id. This runs
//                before any other read, because the value is generated lazily
//                and a race could only exist on the first one. See the comment
//                on READERS for why this is a contract test and not a race
//                detector.
//   stability    repeated reads keep returning it.
//   uuid         the neighbouring file is the opposite: a fresh value per read.
//   format       both are canonical 8-4-4-4-12 RFC 4122 v4 UUIDs. libbinder
//                parses boot_id rather than just checking it is non-empty.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "test_common.h"

#define BOOT_ID "/proc/sys/kernel/random/boot_id"
#define UUID    "/proc/sys/kernel/random/uuid"

// Several readers released together, to exercise the first read from more than
// one task at once. Note what this does NOT do: with the generation unguarded
// on purpose, 25 runs of this suite never once caught a disagreement -- the
// window between testing the flag and setting it is a few instructions, and
// each reader has a whole procfs path walk in front of it. So treat this as a
// test of the contract (one value, stable, shared) rather than as a race
// detector. The lock in fs/proc/sys.c is there because the access is
// unsynchronized, not because this test would fail without it.
#define READERS 8
#define SLOT 64

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

static int read_line(const char *path, char *buf, size_t bufsize) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsize - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    // Trailing newline is part of the file, not part of the value.
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return (int) len;
}

// Canonical 8-4-4-4-12, version 4, RFC 4122 variant -- what Linux emits and
// what a parser on the other end expects.
static int is_uuid_v4(const char *s) {
    static const int groups[] = {8, 4, 4, 4, 12};
    size_t at = 0;
    for (int g = 0; g < 5; g++) {
        if (g > 0 && s[at++] != '-')
            return 0;
        for (int i = 0; i < groups[g]; i++) {
            char c = s[at++];
            int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex)
                return 0;
        }
    }
    if (s[at] != '\0')
        return 0;
    if (s[14] != '4')          // version nibble
        return 0;
    char v = s[19];            // variant: 8, 9, a or b
    return v == '8' || v == '9' || v == 'a' || v == 'b';
}

// MUST run before anything else touches boot_id: it is generated on first read,
// so that is the only moment a race can exist. Afterwards every reader agrees
// trivially and this would prove nothing.
static void test_concurrent_first_readers_agree(void) {
    int start[2], result[2];
    if (pipe(start) != 0 || pipe(result) != 0) {
        check(0, "pipes for the concurrent readers");
        return;
    }

    pid_t kids[READERS];
    int spawned = 0;
    for (int i = 0; i < READERS; i++) {
        pid_t pid = fork();
        if (pid < 0)
            break;
        if (pid == 0) {
            close(start[1]);
            close(result[0]);
            char go;
            (void) !read(start[0], &go, 1); // all released together
            char slot[SLOT];
            memset(slot, 0, sizeof(slot));
            if (read_line(BOOT_ID, slot, sizeof(slot)) <= 0)
                slot[0] = '\0';
            // <= PIPE_BUF, so each record lands whole rather than interleaved.
            (void) !write(result[1], slot, SLOT);
            _exit(0);
        }
        kids[spawned++] = pid;
    }
    close(start[0]);
    close(result[1]);
    check(spawned == READERS, "forked the concurrent readers");

    char go[READERS];
    memset(go, 'g', sizeof(go));
    (void) !write(start[1], go, (size_t) spawned);
    close(start[1]);

    char first[SLOT] = {0};
    int collected = 0, agree = 1;
    for (int i = 0; i < spawned; i++) {
        char slot[SLOT];
        size_t off = 0;
        while (off < SLOT) {
            ssize_t n = read(result[0], slot + off, SLOT - off);
            if (n <= 0)
                break;
            off += (size_t) n;
        }
        if (off < SLOT)
            break;
        if (collected == 0)
            memcpy(first, slot, SLOT);
        else if (memcmp(first, slot, SLOT) != 0)
            agree = 0;
        collected++;
    }
    close(result[0]);
    for (int i = 0; i < spawned; i++) {
        int status;
        waitpid(kids[i], &status, 0);
    }

    check(collected == spawned, "every reader reported a boot_id");
    check(first[0] != '\0', "the boot_id is not empty");
    check(agree, "concurrent first readers all see the same boot_id");
    if (!agree)
        printf("       readers disagreed; first was \"%s\"\n", first);
}

static void test_boot_id_is_stable(void) {
    char a[64], b[64];
    check(read_line(BOOT_ID, a, sizeof(a)) > 0, "read boot_id");
    check(is_uuid_v4(a), "boot_id is a canonical v4 UUID");
    check(read_line(BOOT_ID, b, sizeof(b)) > 0, "read boot_id again");
    check(strcmp(a, b) == 0, "boot_id does not change between reads");

    // And across processes, which is the property that makes it usable as a
    // boot identity at all.
    int p[2];
    if (pipe(p) != 0) {
        check(0, "pipe for the child reader");
        return;
    }
    pid_t pid = fork();
    check(pid >= 0, "fork a child reader");
    if (pid == 0) {
        close(p[0]);
        char slot[SLOT];
        memset(slot, 0, sizeof(slot));
        (void) read_line(BOOT_ID, slot, sizeof(slot));
        (void) !write(p[1], slot, SLOT);
        _exit(0);
    }
    close(p[1]);
    char slot[SLOT];
    size_t off = 0;
    while (off < SLOT) {
        ssize_t n = read(p[0], slot + off, SLOT - off);
        if (n <= 0)
            break;
        off += (size_t) n;
    }
    close(p[0]);
    int status;
    waitpid(pid, &status, 0);
    check(off == SLOT && strcmp(slot, a) == 0, "a child process sees the same boot_id");
}

static void test_uuid_is_fresh(void) {
    char a[64], b[64];
    check(read_line(UUID, a, sizeof(a)) > 0, "read uuid");
    check(is_uuid_v4(a), "uuid is a canonical v4 UUID");
    check(read_line(UUID, b, sizeof(b)) > 0, "read uuid again");
    // The opposite contract to boot_id: this one is regenerated per read.
    check(strcmp(a, b) != 0, "uuid is a fresh value on every read");
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    if (access(BOOT_ID, R_OK) != 0) {
        printf("SKIP proc_random: no %s (is /proc mounted?)\n", BOOT_ID);
        return finish_suite("proc_random");
    }

    test_concurrent_first_readers_agree();
    test_boot_id_is_stable();
    test_uuid_is_fresh();

    return finish_suite("proc_random");
}
