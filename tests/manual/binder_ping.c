// binder_ping: a full transaction round trip to whatever owns handle 0.
//
// PING_TRANSACTION is the simplest thing binder can do: every BBinder answers
// it, it carries no payload, and -- crucially -- it needs nothing else from
// Android userspace. That makes it the one call that can be made against a
// live servicemanager while the rest of the platform is still missing.
//
// It exists because `service list` cannot do this job. Modern libbinder waits
// for the "servicemanager.ready" property before it constructs ProcessState,
// so with no property service every real client spins without ever opening the
// driver, and a hang there says nothing at all about binder.
//
// Two modes:
//   (default)    fork a server, claim handle 0, ping it. Self-contained, so it
//                runs in CI and proves the round trip end to end.
//   --external   ping whoever already owns handle 0 and report what came back.
//                This is the one to run on device against a live
//                servicemanager: a reply is real Android userspace answering a
//                transaction through this driver.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include "test_common.h"

#define BINDER_DEV_MAJOR 249
#define BINDER_MAP_SIZE (128 * 1024)

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;

struct binder_write_read {
    binder_size_t write_size, write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size, read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    uint32_t code, flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size, offsets_size;
    union {
        struct { binder_uintptr_t buffer, offsets; } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_transaction_data_secctx {
    struct binder_transaction_data transaction_data;
    binder_uintptr_t secctx;
};

#define BINDER_WRITE_READ      _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, int32_t)

enum {
    BR_ERROR = _IOR('r', 0, int32_t),
    BR_OK = _IO('r', 1),
    BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
    BR_TRANSACTION_SEC_CTX = _IOR('r', 2, struct binder_transaction_data_secctx),
    BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
    BR_DEAD_REPLY = _IO('r', 5),
    BR_TRANSACTION_COMPLETE = _IO('r', 6),
    BR_INCREFS = _IOR('r', 7, binder_uintptr_t[2]),
    BR_ACQUIRE = _IOR('r', 8, binder_uintptr_t[2]),
    BR_RELEASE = _IOR('r', 9, binder_uintptr_t[2]),
    BR_DECREFS = _IOR('r', 10, binder_uintptr_t[2]),
    BR_NOOP = _IO('r', 12),
    BR_SPAWN_LOOPER = _IO('r', 13),
    BR_FAILED_REPLY = _IO('r', 17),
};

enum {
    BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
    BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
    BC_FREE_BUFFER = _IOW('c', 3, binder_uintptr_t),
    BC_INCREFS_DONE = _IOW('c', 8, binder_uintptr_t[2]),
    BC_ACQUIRE_DONE = _IOW('c', 9, binder_uintptr_t[2]),
    BC_ENTER_LOOPER = _IO('c', 12),
};

// B_PACK_CHARS('_','P','N','G') -- what every BBinder answers.
#define PING_TRANSACTION 0x5f504e47

// In --external mode this is a probe aimed at another process, and its two
// outcomes must not print the same last line. finish_suite reports PASS
// whenever nothing FAILED, and a skip is not a failure -- so a skipped probe
// and a successful one both ended with "binder_ping: PASS", which is exactly
// the ambiguity a probe exists to remove. The default mode keeps finish_suite,
// because it is a real self-contained test and the harness looks for that line.
static int skipped(int external) {
    if (!external)
        return finish_suite("binder_ping");
    printf("binder_ping: SKIP (nothing was verified)\n");
    return 2;
}

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

struct binder {
    int fd;
    void *map;
};

static int binder_open_dev(struct binder *b, const char *path) {
    b->fd = open(path, O_RDWR | O_CLOEXEC);
    if (b->fd < 0)
        return -1;
    b->map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, b->fd, 0);
    if (b->map == MAP_FAILED) {
        close(b->fd);
        b->fd = -1;
        return -1;
    }
    return 0;
}

static void binder_close_dev(struct binder *b) {
    if (b->map != NULL && b->map != MAP_FAILED)
        munmap(b->map, BINDER_MAP_SIZE);
    if (b->fd >= 0)
        close(b->fd);
    b->fd = -1;
}

static int binder_wr(struct binder *b, void *wbuf, size_t wsize, void *rbuf, size_t rsize,
                     size_t *consumed) {
    struct binder_write_read bwr = {
        .write_size = wsize,
        .write_buffer = (binder_uintptr_t) (uintptr_t) wbuf,
        .read_size = rsize,
        .read_buffer = (binder_uintptr_t) (uintptr_t) rbuf,
    };
    if (ioctl(b->fd, BINDER_WRITE_READ, &bwr) < 0)
        return -1;
    if (consumed != NULL)
        *consumed = (size_t) bwr.read_consumed;
    return 0;
}

static ssize_t br_payload_size(uint32_t cmd) {
    switch (cmd) {
        case BR_NOOP: case BR_OK: case BR_TRANSACTION_COMPLETE:
        case BR_SPAWN_LOOPER: case BR_DEAD_REPLY: case BR_FAILED_REPLY:
            return 0;
        case BR_ERROR:
            return sizeof(int32_t);
        case BR_TRANSACTION: case BR_REPLY:
            return sizeof(struct binder_transaction_data);
        case BR_TRANSACTION_SEC_CTX:
            return sizeof(struct binder_transaction_data_secctx);
        case BR_INCREFS: case BR_ACQUIRE: case BR_RELEASE: case BR_DECREFS:
            return 2 * (ssize_t) sizeof(binder_uintptr_t);
        default:
            return -1;
    }
}

// Sends PING to handle 0 and waits for the verdict. Returns 1 on a reply, 0 on
// an explicit failure, -1 if the protocol went off the rails.
static int ping_handle_zero(struct binder *b, int *saw_failure) {
    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) out;
    memset(&out, 0, sizeof(out));
    out.cmd = BC_TRANSACTION;
    out.tr.target.handle = 0;
    out.tr.code = PING_TRANSACTION;

    uint8_t readbuf[512];
    size_t consumed = 0;
    if (binder_wr(b, &out, sizeof(out), readbuf, sizeof(readbuf), &consumed) < 0)
        return -1;

    for (int round = 0; round < 64; round++) {
        size_t off = 0;
        while (off + sizeof(uint32_t) <= consumed) {
            uint32_t cmd;
            memcpy(&cmd, readbuf + off, sizeof(cmd));
            off += sizeof(cmd);
            ssize_t payload = br_payload_size(cmd);
            if (payload < 0 || off + (size_t) payload > consumed)
                return -1;
            if (cmd == BR_REPLY) {
                struct binder_transaction_data tr;
                memcpy(&tr, readbuf + off, sizeof(tr));
                // The reply's buffer belongs to us now.
                struct {
                    uint32_t cmd;
                    binder_uintptr_t buffer;
                } __attribute__((packed)) freebuf = { BC_FREE_BUFFER, tr.data.ptr.buffer };
                (void) binder_wr(b, &freebuf, sizeof(freebuf), NULL, 0, NULL);
                return 1;
            }
            if (cmd == BR_DEAD_REPLY || cmd == BR_FAILED_REPLY || cmd == BR_ERROR) {
                *saw_failure = (int) cmd;
                return 0;
            }
            off += (size_t) payload;
        }
        consumed = 0;
        if (binder_wr(b, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
    }
    return -1;
}

// A minimal BBinder: claims handle 0 and answers one ping, so the default mode
// needs nothing outside this process tree.
static void serve_one_ping(const char *dev, int ready_fd) {
    struct binder server = { .fd = -1 };
    if (binder_open_dev(&server, dev) < 0)
        _exit(70);
    int32_t zero = 0;
    if (ioctl(server.fd, BINDER_SET_CONTEXT_MGR, &zero) < 0)
        _exit(71);
    uint32_t enter = BC_ENTER_LOOPER;
    (void) binder_wr(&server, &enter, sizeof(enter), NULL, 0, NULL);

    char c = 'r';
    (void) !write(ready_fd, &c, 1);
    close(ready_fd);

    uint8_t readbuf[512];
    for (int round = 0; round < 64; round++) {
        size_t consumed = 0;
        if (binder_wr(&server, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            _exit(72);
        }
        size_t off = 0;
        while (off + sizeof(uint32_t) <= consumed) {
            uint32_t cmd;
            memcpy(&cmd, readbuf + off, sizeof(cmd));
            off += sizeof(cmd);
            ssize_t payload = br_payload_size(cmd);
            if (payload < 0)
                _exit(73);
            if (cmd == BR_INCREFS || cmd == BR_ACQUIRE) {
                struct {
                    uint32_t cmd;
                    binder_uintptr_t pc[2];
                } __attribute__((packed)) ack;
                ack.cmd = (cmd == BR_INCREFS) ? BC_INCREFS_DONE : BC_ACQUIRE_DONE;
                memcpy(ack.pc, readbuf + off, sizeof(ack.pc));
                (void) binder_wr(&server, &ack, sizeof(ack), NULL, 0, NULL);
            } else if (cmd == BR_TRANSACTION || cmd == BR_TRANSACTION_SEC_CTX) {
                struct binder_transaction_data tr;
                memcpy(&tr, readbuf + off, sizeof(tr));
                struct {
                    uint32_t free_cmd;
                    binder_uintptr_t buffer;
                    uint32_t reply_cmd;
                    struct binder_transaction_data reply;
                } __attribute__((packed)) response;
                memset(&response, 0, sizeof(response));
                response.free_cmd = BC_FREE_BUFFER;
                response.buffer = tr.data.ptr.buffer;
                response.reply_cmd = BC_REPLY;
                (void) binder_wr(&server, &response, sizeof(response), NULL, 0, NULL);
                _exit(0);
            }
            off += (size_t) payload;
        }
    }
    _exit(74);
}

static const char *pick_device(void) {
    static char path[128];
    snprintf(path, sizeof(path), "/dev/binder");
    if (access(path, F_OK) == 0)
        return path;
    if (mknod(path, S_IFCHR | 0666, makedev(BINDER_DEV_MAJOR, 0)) == 0)
        return path;
    const char *dir = "/tmp/binder-ping";
    if ((mkdir(dir, 0777) == 0 || errno == EEXIST) &&
            mount("binder", dir, "binder", 0, NULL) == 0) {
        snprintf(path, sizeof(path), "%s/binder", dir);
        if (access(path, F_OK) == 0)
            return path;
    }
    return NULL;
}

int main(int argc, char **argv) {
    // test_init exits on an option it does not recognise, so ours are consumed
    // here and only the rest is passed through. Compacting in place is safe:
    // kept entries only ever move toward the front.
    int external = 0;
    const char *dev = NULL;
    int kept = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--external") == 0)
            external = 1;
        else if (argv[i][0] == '/')
            dev = argv[i];
        else
            argv[kept++] = argv[i];
    }
    test_init(kept, argv);
    alarm(test_watchdog_secs(30));

    if (dev == NULL)
        dev = pick_device();
    if (dev == NULL) {
        printf("SKIP binder_ping: no binder device (errno=%d %s)\n", errno, strerror(errno));
        return skipped(external);
    }
    test_logf("device %s\n", dev);

    pid_t server = -1;
    if (!external) {
        int ready[2];
        if (pipe(ready) != 0) {
            check(0, "ready pipe");
            return finish_suite("binder_ping");
        }
        server = fork();
        check(server >= 0, "fork the ping server");
        if (server == 0) {
            close(ready[0]);
            serve_one_ping(dev, ready[1]);
        }
        close(ready[1]);
        char c;
        if (read(ready[0], &c, 1) != 1) {
            printf("SKIP binder_ping: could not claim handle 0 (something else owns it)\n");
            close(ready[0]);
            waitpid(server, NULL, 0);
            return skipped(external);
        }
        close(ready[0]);
    }

    struct binder client = { .fd = -1 };
    if (binder_open_dev(&client, dev) < 0) {
        check(0, "client open+mmap");
        return finish_suite("binder_ping");
    }

    int failure = 0;
    int rc = ping_handle_zero(&client, &failure);
    if (external && rc == 0) {
        // Nobody home is a diagnosis, not a test failure, when pinging a peer
        // we did not start.
        printf("SKIP binder_ping: handle 0 answered with a failure (0x%08x) -- "
               "is a context manager running?\n", (unsigned) failure);
        binder_close_dev(&client);
        return skipped(external);
    }
    check(rc == 1, "handle 0 replied to PING_TRANSACTION");
    if (rc == 0)
        printf("       got failure 0x%08x instead of BR_REPLY\n", (unsigned) failure);

    binder_close_dev(&client);
    if (server > 0) {
        int status = 0;
        waitpid(server, &status, 0);
        check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the ping server exited cleanly");
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
            printf("       server exit status %d\n", WEXITSTATUS(status));
    }

    return finish_suite("binder_ping");
}
