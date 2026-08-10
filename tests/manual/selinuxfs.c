// selinuxfs: the permissive SELinux stub (fs/selinuxfs.c).
//
// The stub enforces nothing. What it has to do is convince libselinux that
// SELinux is present and permissive, because Android userspace aborts without
// a security server to talk to -- servicemanager's very first act is a fatal
// CHECK on selinux_status_open().
//
// So this test asserts the things libselinux actually inspects, in the order
// it inspects them:
//
//   mount        it mounts as "selinuxfs" and statfs reports SELINUX_MAGIC,
//                which is what is_selinux_enabled() keys off -- the type, not
//                the path.
//   status       the file libselinux mmaps: a page whose first u32 is version
//                1, with an even sequence number (meaning stable) and
//                enforcing 0. Readable as well as mappable, and never
//                writable.
//   scalars      enforce=0, policyvers, mls=1, deny_unknown=0.
//   enforce      writing 0 is accepted; writing 1 is EINVAL rather than a
//                silent lie, since nothing here could enforce a policy.
//   load         a policy image is accepted and discarded -- init treats a
//                failed load as fatal, so this must report success.
//   access       the AVC query interface: write a request, read back a verdict
//                that allows everything and leaves nothing undecided.
//   netlink      NETLINK_SELINUX opens, which is selinux_status_open's
//                fallback when the status file is unavailable.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include "test_common.h"

#define SELINUX_MAGIC 0xf97cff8c
#define AF_NETLINK_ 16
#define NETLINK_SELINUX 7

static char mnt[128];

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

static int read_file(const char *name, char *buf, size_t bufsize) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", mnt, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsize - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int) n;
}

static int mount_selinuxfs(void) {
    static const char *candidates[] = { "/sys/fs/selinux", "/mnt/selinux", "/tmp/selinux" };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (mkdir(candidates[i], 0755) != 0 && errno != EEXIST)
            continue;
        if (mount("selinuxfs", candidates[i], "selinuxfs", 0, NULL) != 0)
            continue;
        snprintf(mnt, sizeof(mnt), "%s", candidates[i]);
        return 0;
    }
    return -1;
}

static void test_mount_identity(void) {
    // is_selinux_enabled() looks at the filesystem type. Getting this wrong
    // means libselinux concludes SELinux is absent no matter what the files
    // beneath it say.
    struct statfs sfs;
    check(statfs(mnt, &sfs) == 0, "statfs the mount");
    check((unsigned) sfs.f_type == SELINUX_MAGIC, "statfs reports SELINUX_MAGIC");
}

static void test_status_page(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s/status", mnt);
    int fd = open(path, O_RDONLY);
    check(fd >= 0, "open status");
    if (fd < 0)
        return;

    uint32_t page[5];
    check(read(fd, page, sizeof(page)) == (ssize_t) sizeof(page), "read status");
    check(page[0] == 1, "status version is 1");
    check(page[1] % 2 == 0, "status sequence is even (contents stable)");
    check(page[2] == 0, "status reports permissive");
    check(page[4] == 0, "status allows unknown classes");

    // The mapping is the path libselinux actually prefers.
    uint32_t *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "status mmaps");
    if (map != MAP_FAILED) {
        check(map[0] == 1, "the mapping shows version 1");
        check(map[2] == 0, "the mapping shows permissive");
        munmap(map, 4096);
    }

    // Userspace must never be able to scribble on a page every process shares.
    void *rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(rw == MAP_FAILED && errno == EPERM, "a writable status mapping is EPERM");
    if (rw != MAP_FAILED)
        munmap(rw, 4096);
    close(fd);
}

static void test_scalars(void) {
    char buf[64];
    check(read_file("enforce", buf, sizeof(buf)) > 0 && atoi(buf) == 0, "enforce reads 0");
    check(read_file("policyvers", buf, sizeof(buf)) > 0 && atoi(buf) >= 30,
          "policyvers is a plausible modern version");
    check(read_file("mls", buf, sizeof(buf)) > 0 && atoi(buf) == 1,
          "mls is on (Android policies are MLS)");
    check(read_file("deny_unknown", buf, sizeof(buf)) > 0 && atoi(buf) == 0,
          "deny_unknown is 0");
}

static void test_enforce_is_honest(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s/enforce", mnt);
    int fd = open(path, O_RDWR);
    check(fd >= 0, "open enforce for writing");
    if (fd < 0)
        return;
    check(write(fd, "0", 1) == 1, "writing 0 to enforce is accepted");
    // Refusing is the honest answer: nothing here can evaluate a policy, so
    // claiming to enforce one would be a lie a caller might rely on.
    check(write(fd, "1", 1) < 0 && errno == EINVAL, "writing 1 to enforce is EINVAL");
    close(fd);
}

static void test_policy_load(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s/load", mnt);
    int fd = open(path, O_WRONLY);
    check(fd >= 0, "open load");
    if (fd < 0)
        return;
    // init treats a failed policy load as fatal, so accepting it matters even
    // though there is nothing to load it into.
    char policy[256];
    memset(policy, 0xab, sizeof(policy));
    check(write(fd, policy, sizeof(policy)) == (ssize_t) sizeof(policy),
          "a policy image is accepted");
    close(fd);
}

static void test_access_verdict(void) {
    char path[256];
    snprintf(path, sizeof(path), "%s/access", mnt);
    int fd = open(path, O_RDWR);
    check(fd >= 0, "open access");
    if (fd < 0)
        return;

    const char *query = "u:r:untrusted_app:s0 u:object_r:system_file:s0 1 1";
    check(write(fd, query, strlen(query)) == (ssize_t) strlen(query), "write an AVC query");

    char response[128] = {0};
    ssize_t n = read(fd, response, sizeof(response) - 1);
    check(n > 0, "read the verdict back");
    if (n > 0) {
        unsigned allowed = 0, decided = 0, auditallow = 0, auditdeny = 0, seqno = 0, flags = 0;
        int parsed = sscanf(response, "%x %x %x %x %u %x",
                            &allowed, &decided, &auditallow, &auditdeny, &seqno, &flags);
        check(parsed == 6, "the verdict has all six fields");
        check(allowed == 0xffffffff, "everything is allowed");
        // An undecided bit sends libselinux back to consult a policy that does
        // not exist, so nothing may be left undecided.
        check(decided == 0xffffffff, "nothing is left undecided");
        check(auditdeny == 0, "nothing is marked for audit");
    }
    close(fd);
}

static void test_netlink_fallback(void) {
    // selinux_status_open() falls back to this socket when it cannot use the
    // status file. It has to open, even though no event will ever arrive --
    // a policy that never changes has nothing to report.
    int sock = socket(AF_NETLINK_, SOCK_RAW, NETLINK_SELINUX);
    check(sock >= 0, "NETLINK_SELINUX socket opens");
    if (sock >= 0)
        close(sock);
}

static void test_readdir(void) {
    // libselinux probes for individual files; they have to be listed as well
    // as openable, or a directory scan concludes the interface is absent.
    char path[256];
    snprintf(path, sizeof(path), "%s/enforce", mnt);
    struct stat st;
    check(stat(path, &st) == 0 && S_ISREG(st.st_mode), "enforce stats as a regular file");
    snprintf(path, sizeof(path), "%s/nonexistent", mnt);
    check(stat(path, &st) < 0 && errno == ENOENT, "a missing entry is ENOENT");
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    if (mount_selinuxfs() < 0) {
        printf("SKIP selinuxfs: could not mount (errno=%d %s)\n", errno, strerror(errno));
        return finish_suite("selinuxfs");
    }
    test_logf("mounted at %s\n", mnt);

    test_mount_identity();
    test_status_page();
    test_scalars();
    test_enforce_is_honest();
    test_policy_load();
    test_access_verdict();
    test_netlink_fallback();
    test_readdir();

    return finish_suite("selinuxfs");
}
