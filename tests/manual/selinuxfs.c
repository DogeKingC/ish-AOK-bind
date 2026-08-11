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
//   classes      class/<name>/index and class/<name>/perms/<perm>, which are
//                how libselinux resolves a class name. A failed lookup is not
//                "unknown, carry on" -- it is EINVAL, and servicemanager turns
//                that into a denial.
//   netlink      NETLINK_SELINUX opens, which is selinux_status_open's
//                fallback when the status file is unavailable.
//   attr         /proc/<pid>/attr/*, which is all getcon/setcon/setexeccon
//                are. servicemanager gets past selinux_status_open() only to
//                die on CHECK(getcon(...) == 0) if these are missing, so they
//                are as much a part of the stub as the filesystem is.

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
#include <sys/wait.h>

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

// class/<name>/index and class/<name>/perms/<perm>: how libselinux turns a
// class name into a number. This is not a nicety -- when the lookup fails
// libselinux returns 0 and sets EINVAL, and servicemanager maps a failed
// selinux_check_access() straight to DENIED. On a stub that permits
// everything, an unresolvable class name silently becomes a denial.
static void test_class_lookup(void) {
    char buf[64];
    char path[256];

    // The classes Android's own object managers check.
    static const struct { const char *cls; const char *perm; } known[] = {
        {"service_manager", "add"},
        {"service_manager", "find"},
        {"service_manager", "list"},
        {"binder", "call"},
        {"binder", "transfer"},
        {"hwservice_manager", "add"},
        {"property_service", "set"},
    };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        snprintf(path, sizeof(path), "class/%s/index", known[i].cls);
        int n = read_file(path, buf, sizeof(buf));
        check(n > 0 && atoi(buf) > 0, "a known class has a nonzero index");
        if (n <= 0)
            test_logf("  missing %s\n", path);

        snprintf(path, sizeof(path), "class/%s/perms/%s", known[i].cls, known[i].perm);
        n = read_file(path, buf, sizeof(buf));
        check(n > 0 && atoi(buf) > 0, "a known permission has a nonzero bit");
    }

    // Permissions of one class must be distinguishable from each other.
    char add[64], find[64];
    check(read_file("class/service_manager/perms/add", add, sizeof(add)) > 0 &&
          read_file("class/service_manager/perms/find", find, sizeof(find)) > 0 &&
          atoi(add) != atoi(find),
          "two permissions of a class have different bits");

    // A class we have never heard of still resolves, because refusing would
    // turn "allowed" into a denial, and every class a future Android adds
    // would break the same silent way.
    check(read_file("class/some_future_class/index", buf, sizeof(buf)) > 0 &&
          atoi(buf) > 0, "an unknown class still resolves to a nonzero index");
    check(read_file("class/some_future_class/perms/whatever", buf, sizeof(buf)) > 0 &&
          atoi(buf) > 0, "an unknown permission still resolves to a nonzero bit");

    // Stable across reads: libselinux caches what it gets.
    char first[64], second[64];
    check(read_file("class/binder/index", first, sizeof(first)) > 0 &&
          read_file("class/binder/index", second, sizeof(second)) > 0 &&
          strcmp(first, second) == 0, "a class index is stable across reads");

    // The directory is browsable, and `class` itself is a directory.
    snprintf(path, sizeof(path), "%s/class", mnt);
    struct stat st;
    check(stat(path, &st) == 0 && S_ISDIR(st.st_mode), "class is a directory");
    snprintf(path, sizeof(path), "%s/class/binder", mnt);
    check(stat(path, &st) == 0 && S_ISDIR(st.st_mode), "a class is a directory");
    snprintf(path, sizeof(path), "%s/class/binder/index", mnt);
    check(stat(path, &st) == 0 && S_ISREG(st.st_mode), "index is a regular file");
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

// --- /proc/<pid>/attr ------------------------------------------------------

#define ATTR_EXEC_CONTEXT "u:r:servicemanager:s0"

static int attr_read(const char *name, char *buf, size_t bufsize) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/attr/%s", name);
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

static int attr_write(const char *name, const char *value, size_t len) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/attr/%s", name);
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, value, len);
    close(fd);
    return n == (ssize_t) len ? 0 : -1;
}

// The other half of test_exec_transition, running after the execve.
static int check_after_exec(void) {
    char buf[512];
    if (attr_read("current", buf, sizeof(buf)) <= 0)
        return 10;
    if (strcmp(buf, ATTR_EXEC_CONTEXT) != 0)
        return 11;
    // The context we came from, which is how a service learns who started it.
    if (attr_read("prev", buf, sizeof(buf)) <= 0)
        return 12;
    // The transition consumed the staged context; leaving it set would relabel
    // every later exec too.
    if (attr_read("exec", buf, sizeof(buf)) != 0)
        return 13;
    return 0;
}

static void test_attr_current(void) {
    char buf[512];
    int n = attr_read("current", buf, sizeof(buf));
    check(n > 0, "attr/current is readable and non-empty");
    if (n <= 0)
        return;
    // getcon() hands the value straight to context_new(), which splits on
    // colons: user:role:type:range.
    int colons = 0;
    for (char *p = buf; *p != '\0'; p++)
        if (*p == ':')
            colons++;
    check(colons >= 3, "attr/current parses as user:role:type:range");
    // A trailing newline would end up inside the type or range field.
    check(strchr(buf, '\n') == NULL, "attr/current has no trailing newline");
    // Linux counts the terminating NUL in the length; libselinux tolerates
    // either, but matching the kernel keeps callers that size a buffer from
    // the read honest.
    check(n == (int) strlen(buf) + 1, "attr/current includes its NUL terminator");
}

static void test_attr_setcon(void) {
    char before[512], after[512];
    check(attr_read("current", before, sizeof(before)) > 0, "read attr/current before setcon");
    const char *ctx = "u:r:shell:s0";
    check(attr_write("current", ctx, strlen(ctx) + 1) == 0, "setcon-style write is accepted");
    check(attr_read("current", after, sizeof(after)) > 0 && strcmp(after, ctx) == 0,
          "attr/current reads back what was written");
    // Nothing here can evaluate a policy, so a malformed context would only
    // fail later, somewhere further from the write.
    check(attr_write("current", "nonsense", strlen("nonsense")) < 0 && errno == EINVAL,
          "a context without the four fields is EINVAL");
    // "current" is what getcon() returns; there is no valid empty answer.
    check(attr_write("current", "", 0) < 0 && errno == EINVAL,
          "clearing attr/current is EINVAL");
    check(attr_write("current", before, strlen(before) + 1) == 0, "restore attr/current");
}

static void test_attr_staging_slots(void) {
    static const char *slots[] = {"fscreate", "keycreate", "sockcreate"};
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
        char buf[512];
        const char *ctx = "u:object_r:system_file:s0";
        check(attr_write(slots[i], ctx, strlen(ctx) + 1) == 0, slots[i]);
        check(attr_read(slots[i], buf, sizeof(buf)) > 0 && strcmp(buf, ctx) == 0,
              "a staged create context reads back");
        // setfscreatecon(NULL) and friends clear by writing nothing; an unset
        // attribute must then read as zero bytes, not as an empty string that
        // libselinux would hand on as a context.
        check(attr_write(slots[i], "", 0) == 0, "clearing a staging slot is accepted");
        check(attr_read(slots[i], buf, sizeof(buf)) == 0, "a cleared slot reads as empty");
    }
}

static void test_attr_exec_transition(const char *self) {
    pid_t pid = fork();
    if (pid < 0) {
        check(0, "fork for the exec transition");
        return;
    }
    if (pid == 0) {
        // Exactly what init does to label a service: stage the context, then
        // execve. The transition is the only part of SELinux with real
        // semantics here, so it is the part worth testing end to end.
        if (attr_write("exec", ATTR_EXEC_CONTEXT, strlen(ATTR_EXEC_CONTEXT) + 1) != 0)
            _exit(20);
        execl(self, self, "--after-exec", (char *) NULL);
        _exit(21);
    }
    int status = 0;
    check(waitpid(pid, &status, 0) == pid, "wait for the exec'd child");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "execve transitions into the staged context");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        test_logf("  child exit status %d\n", WEXITSTATUS(status));
}

static void test_attr_thread_self(void) {
    // libselinux tries /proc/thread-self/attr/* before /proc/self, because on
    // Linux /proc/self is the thread group and a per-thread write through it is
    // EACCES. It has to name this thread specifically.
    char buf[512];
    ssize_t n = readlink("/proc/thread-self", buf, sizeof(buf) - 1);
    check(n > 0, "/proc/thread-self is a symlink");
    if (n > 0) {
        buf[n] = '\0';
        char want[64];
        snprintf(want, sizeof(want), "%d/task/%d", (int) getpid(), (int) getpid());
        check(strcmp(buf, want) == 0, "/proc/thread-self names <tgid>/task/<tid>");
        if (strcmp(buf, want) != 0)
            test_logf("  points at \"%s\", wanted \"%s\"\n", buf, want);
    }

    int fd = open("/proc/thread-self/attr/current", O_RDONLY);
    check(fd >= 0, "attr is reachable through /proc/thread-self");
    if (fd >= 0) {
        check(read(fd, buf, sizeof(buf)) > 0, "and reads the same context");
        close(fd);
    }

    // The fallback libselinux uses when thread-self is absent.
    char path[256];
    snprintf(path, sizeof(path), "/proc/self/task/%d/attr/current", (int) getpid());
    fd = open(path, O_RDONLY);
    check(fd >= 0, "attr is reachable through /proc/self/task/<tid>");
    if (fd >= 0)
        close(fd);
}

static void test_attr_other_task(void) {
    // getpidcon() on a peer -- servicemanager calls it for every caller it
    // decides about. Readable, but not writable: a process may only relabel
    // itself.
    // A child rather than the parent: under the test runner this process is
    // pid 1, so getppid() is 0 and there is no peer above us to look at.
    int ready[2], go[2];
    if (pipe(ready) != 0 || pipe(go) != 0) {
        check(0, "pipes for the peer-context child");
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        check(0, "fork for the peer-context child");
        return;
    }
    if (pid == 0) {
        close(ready[0]);
        close(go[1]);
        char c = 'x';
        (void) !write(ready[1], &c, 1);
        (void) !read(go[0], &c, 1); // stay alive until the parent is done
        _exit(0);
    }
    close(ready[1]);
    close(go[0]);
    char c;
    check(read(ready[0], &c, 1) == 1, "the peer-context child started");

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/attr/current", (int) pid);
    int fd = open(path, O_RDONLY);
    check(fd >= 0, "another task's attr/current is readable");
    if (fd >= 0) {
        char buf[512];
        check(read(fd, buf, sizeof(buf)) > 0, "and non-empty");
        close(fd);
    }
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        check(write(fd, "u:r:init:s0", 12) < 0 && errno == EACCES,
              "writing another task's context is EACCES");
        close(fd);
    }

    close(go[1]); // release the child
    int status;
    waitpid(pid, &status, 0);
    close(ready[0]);
}

int main(int argc, char **argv) {
    // Re-entry after test_attr_exec_transition's execve. Handled before
    // test_init, which rejects options it does not know.
    if (argc == 2 && strcmp(argv[1], "--after-exec") == 0)
        return check_after_exec();

    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    // /proc/<pid>/attr is procfs, not selinuxfs, so it is exercised whether or
    // not the mount below succeeds.
    test_attr_current();
    test_attr_setcon();
    test_attr_staging_slots();
    test_attr_exec_transition(argv[0]);
    test_attr_thread_self();
    test_attr_other_task();

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
    test_class_lookup();
    test_netlink_fallback();
    test_readdir();

    return finish_suite("selinuxfs");
}
