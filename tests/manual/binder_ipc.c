// binder_ipc: Android Binder IPC driver (/dev/binder, kernel/binder.c).
//
// Binder is the IPC every Android userspace component is built on: a process
// opens /dev/binder, mmaps a receive region out of it, and drives everything
// through BINDER_WRITE_READ, which carries a stream of BC_ commands out and a
// stream of BR_ returns back. This test speaks that protocol directly rather
// than through libbinder, so it can assert on the wire format.
//
// Covered:
//   basics       BINDER_VERSION reports protocol 8; the mmap is refused when
//                writable (userspace only ever reads it) and at a nonzero
//                offset; a second mmap on the same fd is EBUSY; an unknown
//                ioctl is ENOTTY.
//   ctx manager  BINDER_SET_CONTEXT_MGR claims handle 0, and claiming it twice
//                is EBUSY.
//   transaction  A synchronous call from a child process to handle 0 arrives
//                as BR_TRANSACTION with the payload intact and the sender's
//                pid/euid filled in; the reply comes back as BR_REPLY. This is
//                the single-copy path: the data must be readable through the
//                receiver's own mapping.
//   objects      A flat_binder_object sent as BINDER_TYPE_BINDER by its owner
//                arrives at the peer translated to BINDER_TYPE_HANDLE with a
//                usable handle -- binder's capability passing.
//   oneway       A TF_ONE_WAY transaction completes without a reply.
//   death        BC_REQUEST_DEATH_NOTIFICATION on a handle fires BR_DEAD_BINDER
//                when the owning process goes away. Run against /dev/vndbinder
//                so it also covers contexts being independent of each other.
//   binderfs     Mounting binderfs and creating a device with BINDER_CTL_ADD
//                makes a new node appear in the directory. SKIPped when the
//                mount is not permitted.
//
// Arch-neutral: binder's ABI is 64-bit on every guest, so the structs below
// are identical on i386 and x86_64.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "test_common.h"

#ifndef MS_NOSUID
#define MS_NOSUID 2
#endif

#define BINDER_DEV_MAJOR 249
#define BINDER_MAP_SIZE (128 * 1024)

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;

struct flat_binder_object {
    uint32_t type;
    uint32_t flags;
    union {
        binder_uintptr_t binder;
        uint32_t handle;
    };
    binder_uintptr_t cookie;
};

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_version {
    int32_t protocol_version;
};

struct binder_transaction_data {
    union {
        uint32_t handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_ptr_cookie {
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
};

struct binder_handle_cookie {
    uint32_t handle;
    binder_uintptr_t cookie;
} __attribute__((packed));

struct binderfs_device {
    char name[256];
    uint32_t major;
    uint32_t minor;
};

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_SET_CONTEXT_MGR  _IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)
#define BINDER_CTL_ADD          _IOWR('b', 1, struct binderfs_device)

enum {
    BR_ERROR = _IOR('r', 0, int32_t),
    BR_OK = _IO('r', 1),
    BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
    BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
    BR_DEAD_REPLY = _IO('r', 5),
    BR_TRANSACTION_COMPLETE = _IO('r', 6),
    BR_INCREFS = _IOR('r', 7, struct binder_ptr_cookie),
    BR_ACQUIRE = _IOR('r', 8, struct binder_ptr_cookie),
    BR_RELEASE = _IOR('r', 9, struct binder_ptr_cookie),
    BR_DECREFS = _IOR('r', 10, struct binder_ptr_cookie),
    BR_NOOP = _IO('r', 12),
    BR_SPAWN_LOOPER = _IO('r', 13),
    BR_DEAD_BINDER = _IOR('r', 15, binder_uintptr_t),
    BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR('r', 16, binder_uintptr_t),
    BR_FAILED_REPLY = _IO('r', 17),
};

enum {
    BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
    BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
    BC_FREE_BUFFER = _IOW('c', 3, binder_uintptr_t),
    BC_INCREFS = _IOW('c', 4, uint32_t),
    BC_ACQUIRE = _IOW('c', 5, uint32_t),
    BC_RELEASE = _IOW('c', 6, uint32_t),
    BC_DECREFS = _IOW('c', 7, uint32_t),
    BC_INCREFS_DONE = _IOW('c', 8, struct binder_ptr_cookie),
    BC_ACQUIRE_DONE = _IOW('c', 9, struct binder_ptr_cookie),
    BC_ENTER_LOOPER = _IO('c', 12),
    BC_REQUEST_DEATH_NOTIFICATION = _IOW('c', 14, struct binder_handle_cookie),
    BC_DEAD_BINDER_DONE = _IOW('c', 16, binder_uintptr_t),
};

#define BINDER_TYPE_BINDER 0x73622a85 /* B_PACK_CHARS('s','b','*',0x85) */
#define BINDER_TYPE_HANDLE 0x73682a85 /* B_PACK_CHARS('s','h','*',0x85) */

#define TF_ONE_WAY 0x01
#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100

#define SERVICE_CODE 0x2a
#define SERVICE_MAGIC UINT64_C(0x1234567890abcdef)
#define REPLY_MAGIC UINT64_C(0xfedcba0987654321)
#define SERVER_OBJECT_PTR UINT64_C(0xdeadbeef00001000)
#define SERVER_OBJECT_COOKIE UINT64_C(0xc0ffee0000002000)
#define DEATH_COOKIE UINT64_C(0x5150000000003000)

static void check(int cond, const char *what) {
    if (!cond)
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
    else
        test_logf("ok %s\n", what);
    if (!cond)
        failures_total++;
}

// A binder endpoint: the fd plus its receive mapping.
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
    b->map = NULL;
}

// One BINDER_WRITE_READ round trip. Returns 0 on success.
static int binder_wr(struct binder *b, void *write_buf, size_t write_size, void *read_buf,
                     size_t read_size, size_t *read_consumed) {
    struct binder_write_read bwr = {
        .write_size = write_size,
        .write_buffer = (binder_uintptr_t) (uintptr_t) write_buf,
        .read_size = read_size,
        .read_buffer = (binder_uintptr_t) (uintptr_t) read_buf,
    };
    if (ioctl(b->fd, BINDER_WRITE_READ, &bwr) < 0)
        return -1;
    if (read_consumed != NULL)
        *read_consumed = (size_t) bwr.read_consumed;
    return 0;
}

// How many bytes of payload follow a given BR_ code.
static ssize_t br_payload_size(uint32_t cmd) {
    switch (cmd) {
        case BR_NOOP:
        case BR_OK:
        case BR_TRANSACTION_COMPLETE:
        case BR_SPAWN_LOOPER:
        case BR_DEAD_REPLY:
        case BR_FAILED_REPLY:
            return 0;
        case BR_ERROR:
            return sizeof(int32_t);
        case BR_TRANSACTION:
        case BR_REPLY:
            return sizeof(struct binder_transaction_data);
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
            return sizeof(struct binder_ptr_cookie);
        case BR_DEAD_BINDER:
        case BR_CLEAR_DEATH_NOTIFICATION_DONE:
            return sizeof(binder_uintptr_t);
        default:
            return -1;
    }
}

// Walks a filled read buffer, invoking `handler` for each BR_ code. The
// handler returns nonzero to stop. Returns the handler's value, or 0 if the
// buffer ran out.
typedef int (*br_handler)(uint32_t cmd, const void *payload, void *ctx);

static int br_parse(const uint8_t *buf, size_t len, br_handler handler, void *ctx) {
    size_t off = 0;
    while (off + sizeof(uint32_t) <= len) {
        uint32_t cmd;
        memcpy(&cmd, buf + off, sizeof(cmd));
        off += sizeof(cmd);
        ssize_t payload = br_payload_size(cmd);
        if (payload < 0) {
            printf("FAIL unknown BR code 0x%08x\n", cmd);
            failures_total++;
            return -1;
        }
        if (off + (size_t) payload > len) {
            printf("FAIL truncated BR payload for 0x%08x\n", cmd);
            failures_total++;
            return -1;
        }
        int rc = handler(cmd, buf + off, ctx);
        off += (size_t) payload;
        if (rc != 0)
            return rc;
    }
    return 0;
}

// Answers the reference-counting requests a node's owner must acknowledge, so
// a serving process doesn't have to open-code it in every loop.
static void ack_refs(struct binder *b, uint32_t cmd, const void *payload) {
    if (cmd != BR_INCREFS && cmd != BR_ACQUIRE)
        return;
    struct {
        uint32_t cmd;
        struct binder_ptr_cookie pc;
    } __attribute__((packed)) reply;
    reply.cmd = (cmd == BR_INCREFS) ? BC_INCREFS_DONE : BC_ACQUIRE_DONE;
    memcpy(&reply.pc, payload, sizeof(reply.pc));
    (void) binder_wr(b, &reply, sizeof(reply), NULL, 0, NULL);
}

// ---------------------------------------------------------------------------
// Phase 1: single-process basics
// ---------------------------------------------------------------------------

// Where this run's binder devices live. Either /dev (nodes shipped by the
// rootfs or created with mknod) or a binderfs mount, which supplies its own
// device nodes and so works on a root where mknod isn't permitted -- and is
// how current Android gets its binder devices anyway.
static char binder_dir[128];
static int binderfs_mounted;

static const char *binder_dev_named(const char *name) {
    static char path[192];
    snprintf(path, sizeof(path), "%s/%s", binder_dir, name);
    return path;
}

// Mounts binderfs somewhere writable. Returns 0 on success.
static int try_mount_binderfs(void) {
    static const char *candidates[] = { "/dev/binderfs", "/mnt/binderfs", "/tmp/binderfs" };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (mkdir(candidates[i], 0755) != 0 && errno != EEXIST)
            continue;
        if (mount("binder", candidates[i], "binder", MS_NOSUID, NULL) != 0)
            continue;
        snprintf(binder_dir, sizeof(binder_dir), "%s", candidates[i]);
        binderfs_mounted = 1;
        return 0;
    }
    return -1;
}

// Picks the device directory for this run, preferring real /dev nodes so the
// classic path is what gets exercised when it is available.
static int binder_setup_devices(void) {
    snprintf(binder_dir, sizeof(binder_dir), "/dev");
    if (access("/dev/binder", F_OK) == 0)
        return 0;
    if (mknod("/dev/binder", S_IFCHR | 0666, makedev(BINDER_DEV_MAJOR, 0)) == 0) {
        (void) mknod("/dev/vndbinder", S_IFCHR | 0666, makedev(BINDER_DEV_MAJOR, 2));
        return 0;
    }
    int mknod_errno = errno;
    if (try_mount_binderfs() == 0) {
        test_logf("using binderfs at %s (mknod in /dev failed: %s)\n", binder_dir,
                  strerror(mknod_errno));
        return 0;
    }
    errno = mknod_errno;
    return -1;
}

static void test_basics(const char *dev) {
    int fd = open(dev, O_RDWR | O_CLOEXEC);
    check(fd >= 0, "open /dev/binder");
    if (fd < 0)
        return;

    struct binder_version ver = { .protocol_version = 0 };
    check(ioctl(fd, BINDER_VERSION, &ver) == 0, "BINDER_VERSION succeeds");
    check(ver.protocol_version == 8, "BINDER_VERSION reports protocol 8");

    // Userspace never writes the receive region; Linux rejects a writable map.
    void *bad = mmap(NULL, BINDER_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check(bad == MAP_FAILED && errno == EPERM, "writable mmap is EPERM");
    if (bad != MAP_FAILED)
        munmap(bad, BINDER_MAP_SIZE);

    bad = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 4096);
    check(bad == MAP_FAILED, "mmap at nonzero offset fails");
    if (bad != MAP_FAILED)
        munmap(bad, BINDER_MAP_SIZE);

    void *map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    check(map != MAP_FAILED, "read-only mmap succeeds");

    void *second = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    check(second == MAP_FAILED && errno == EBUSY, "second mmap on same fd is EBUSY");
    if (second != MAP_FAILED)
        munmap(second, BINDER_MAP_SIZE);

    uint32_t max = 8;
    check(ioctl(fd, BINDER_SET_MAX_THREADS, &max) == 0, "BINDER_SET_MAX_THREADS");

    int32_t unused = 0;
    check(ioctl(fd, _IOW('b', 99, int32_t), &unused) < 0 && errno == ENOTTY,
          "unknown binder ioctl is ENOTTY");

    if (map != MAP_FAILED)
        munmap(map, BINDER_MAP_SIZE);
    close(fd);
}

// ---------------------------------------------------------------------------
// Phase 2: a real transaction between two processes
// ---------------------------------------------------------------------------

struct server_ctx {
    struct binder *b;
    int saw_transaction;
    int replied;
    int oneway_seen;
};

static int server_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct server_ctx *ctx = vctx;

    if (cmd == BR_INCREFS || cmd == BR_ACQUIRE) {
        ack_refs(ctx->b, cmd, payload);
        return 0;
    }
    if (cmd != BR_TRANSACTION)
        return 0;

    struct binder_transaction_data tr;
    memcpy(&tr, payload, sizeof(tr));
    ctx->saw_transaction++;

    // The payload must be readable through our own mapping -- this is the
    // single copy landing in the receiver's region.
    uint64_t magic = 0;
    if (tr.data_size >= sizeof(magic))
        memcpy(&magic, (void *) (uintptr_t) tr.data.ptr.buffer, sizeof(magic));
    check(magic == SERVICE_MAGIC, "server sees the sender's payload");
    check(tr.code == SERVICE_CODE, "transaction code round-trips");
    check(tr.sender_pid > 0, "sender_pid is filled in");

    if (tr.flags & TF_ONE_WAY) {
        ctx->oneway_seen = 1;
        struct {
            uint32_t cmd;
            binder_uintptr_t buffer;
        } __attribute__((packed)) freebuf = { BC_FREE_BUFFER, tr.data.ptr.buffer };
        (void) binder_wr(ctx->b, &freebuf, sizeof(freebuf), NULL, 0, NULL);
        return 1;
    }

    // Reply with a magic word plus one of our own objects, which binder must
    // translate into a handle on the way to the caller.
    static struct {
        uint64_t magic;
        struct flat_binder_object obj;
    } reply_data;
    static binder_size_t reply_offsets[1];

    reply_data.magic = REPLY_MAGIC;
    reply_data.obj = (struct flat_binder_object) {
        .type = BINDER_TYPE_BINDER,
        .flags = FLAT_BINDER_FLAG_ACCEPTS_FDS,
        .binder = SERVER_OBJECT_PTR,
        .cookie = SERVER_OBJECT_COOKIE,
    };
    reply_offsets[0] = offsetof(typeof(reply_data), obj);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) out;
    memset(&out, 0, sizeof(out));
    out.cmd = BC_REPLY;
    out.tr.data_size = sizeof(reply_data);
    out.tr.offsets_size = sizeof(reply_offsets);
    out.tr.data.ptr.buffer = (binder_uintptr_t) (uintptr_t) &reply_data;
    out.tr.data.ptr.offsets = (binder_uintptr_t) (uintptr_t) reply_offsets;

    struct {
        uint32_t cmd;
        binder_uintptr_t buffer;
    } __attribute__((packed)) freebuf = { BC_FREE_BUFFER, tr.data.ptr.buffer };

    uint8_t writebuf[sizeof(out) + sizeof(freebuf)];
    memcpy(writebuf, &freebuf, sizeof(freebuf));
    memcpy(writebuf + sizeof(freebuf), &out, sizeof(out));

    check(binder_wr(ctx->b, writebuf, sizeof(writebuf), NULL, 0, NULL) == 0, "server BC_REPLY");
    ctx->replied = 1;
    return 1;
}

// Runs the context manager until it has served `want` transactions.
static void run_server(struct binder *b, int want, int *oneway_seen) {
    struct server_ctx ctx = { .b = b };
    uint32_t enter = BC_ENTER_LOOPER;
    (void) binder_wr(b, &enter, sizeof(enter), NULL, 0, NULL);

    while (ctx.saw_transaction < want) {
        uint8_t readbuf[512];
        size_t consumed = 0;
        if (binder_wr(b, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            check(0, "server BINDER_WRITE_READ");
            return;
        }
        br_parse(readbuf, consumed, server_handler, &ctx);
    }
    if (oneway_seen != NULL)
        *oneway_seen = ctx.oneway_seen;
}

struct client_ctx {
    struct binder *b;
    int got_reply;
    uint32_t translated_handle;
};

static int client_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct client_ctx *ctx = vctx;
    if (cmd == BR_FAILED_REPLY || cmd == BR_DEAD_REPLY) {
        check(0, "client got a failure instead of BR_REPLY");
        return 1;
    }
    if (cmd != BR_REPLY)
        return 0;

    struct binder_transaction_data tr;
    memcpy(&tr, payload, sizeof(tr));

    uint64_t magic = 0;
    if (tr.data_size >= sizeof(magic))
        memcpy(&magic, (void *) (uintptr_t) tr.data.ptr.buffer, sizeof(magic));
    check(magic == REPLY_MAGIC, "client sees the reply payload");

    // The object the server sent as BINDER_TYPE_BINDER must reach us as a
    // handle: we are not its owner.
    check(tr.offsets_size == sizeof(binder_size_t), "reply carries one object");
    if (tr.offsets_size == sizeof(binder_size_t)) {
        binder_size_t off;
        memcpy(&off, (void *) (uintptr_t) tr.data.ptr.offsets, sizeof(off));
        struct flat_binder_object obj;
        memcpy(&obj, (uint8_t *) (uintptr_t) tr.data.ptr.buffer + off, sizeof(obj));
        check(obj.type == BINDER_TYPE_HANDLE, "BINDER_TYPE_BINDER translated to HANDLE");
        check(obj.handle != 0, "translated handle is not the context manager's");
        ctx->translated_handle = obj.handle;
    }

    struct {
        uint32_t cmd;
        binder_uintptr_t buffer;
    } __attribute__((packed)) freebuf = { BC_FREE_BUFFER, tr.data.ptr.buffer };
    (void) binder_wr(ctx->b, &freebuf, sizeof(freebuf), NULL, 0, NULL);

    ctx->got_reply = 1;
    return 1;
}

// Sends one transaction to handle 0 and waits for the outcome.
static void client_call(struct binder *b, uint32_t flags, struct client_ctx *ctx) {
    static uint64_t payload;
    payload = SERVICE_MAGIC;

    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) out;
    memset(&out, 0, sizeof(out));
    out.cmd = BC_TRANSACTION;
    out.tr.target.handle = 0;
    out.tr.code = SERVICE_CODE;
    out.tr.flags = flags;
    out.tr.data_size = sizeof(payload);
    out.tr.data.ptr.buffer = (binder_uintptr_t) (uintptr_t) &payload;

    uint8_t readbuf[512];
    size_t consumed = 0;
    if (binder_wr(b, &out, sizeof(out), readbuf, sizeof(readbuf), &consumed) < 0) {
        check(0, "client BINDER_WRITE_READ");
        return;
    }
    br_parse(readbuf, consumed, client_handler, ctx);

    // A synchronous call may need a second pass: the first round trip often
    // returns only BR_NOOP + BR_TRANSACTION_COMPLETE, with the reply arriving
    // on the next read.
    while (!ctx->got_reply && !(flags & TF_ONE_WAY)) {
        consumed = 0;
        if (binder_wr(b, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            check(0, "client BINDER_WRITE_READ (reply wait)");
            return;
        }
        if (br_parse(readbuf, consumed, client_handler, ctx) < 0)
            return;
    }
}

static void test_transaction(const char *dev) {
    struct binder server = { .fd = -1 };
    if (binder_open_dev(&server, dev) < 0) {
        check(0, "server open+mmap");
        return;
    }

    int32_t zero = 0;
    if (ioctl(server.fd, BINDER_SET_CONTEXT_MGR, &zero) < 0) {
        // Something else already owns handle 0 in this context; the rest of
        // the phase can't run meaningfully.
        printf("SKIP transaction: context manager already claimed (errno=%d)\n", errno);
        binder_close_dev(&server);
        return;
    }
    check(1, "BINDER_SET_CONTEXT_MGR claims handle 0");
    check(ioctl(server.fd, BINDER_SET_CONTEXT_MGR, &zero) < 0 && errno == EBUSY,
          "second BINDER_SET_CONTEXT_MGR is EBUSY");

    int sync_pipe[2];
    check(pipe(sync_pipe) == 0, "sync pipe");

    pid_t child = fork();
    check(child >= 0, "fork client");
    if (child == 0) {
        close(sync_pipe[1]);
        char go;
        (void) read(sync_pipe[0], &go, 1);
        close(sync_pipe[0]);

        struct binder client = { .fd = -1 };
        if (binder_open_dev(&client, dev) < 0) {
            fflush(NULL);
            _exit(70);
        }

        struct client_ctx ctx = { .b = &client };
        client_call(&client, 0, &ctx);
        int ok = ctx.got_reply && ctx.translated_handle != 0;

        // And a oneway call, which must complete without any reply.
        struct client_ctx oneway = { .b = &client };
        client_call(&client, TF_ONE_WAY, &oneway);

        binder_close_dev(&client);
        // _exit skips stdio flushing, which would silently swallow this
        // child's check output; the parent only sees the exit status.
        fflush(NULL);
        _exit(ok ? (failures_total == 0 ? 0 : 71) : 72);
    }

    close(sync_pipe[0]);
    (void) write(sync_pipe[1], "g", 1);
    close(sync_pipe[1]);

    int oneway_seen = 0;
    run_server(&server, 2, &oneway_seen);
    check(oneway_seen, "server received the oneway transaction");

    int status = 0;
    check(waitpid(child, &status, 0) == child, "reap client");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client completed its call");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("       client exit status %d\n", WEXITSTATUS(status));

    binder_close_dev(&server);
}

// ---------------------------------------------------------------------------
// Phase 3: death notification, on a second context
// ---------------------------------------------------------------------------

struct death_ctx {
    int got_dead;
    binder_uintptr_t cookie;
};

static int death_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct death_ctx *ctx = vctx;
    if (cmd != BR_DEAD_BINDER)
        return 0;
    memcpy(&ctx->cookie, payload, sizeof(ctx->cookie));
    ctx->got_dead = 1;
    return 1;
}

static void test_death_notification(const char *dev) {
    if (access(dev, F_OK) != 0) {
        printf("SKIP death: no %s\n", dev);
        return;
    }

    int up[2], down[2];
    check(pipe(up) == 0 && pipe(down) == 0, "death sync pipes");

    pid_t child = fork();
    check(child >= 0, "fork death server");
    if (child == 0) {
        close(up[0]);
        close(down[1]);
        struct binder server = { .fd = -1 };
        if (binder_open_dev(&server, dev) < 0) {
            fflush(NULL);
            _exit(70);
        }
        int32_t zero = 0;
        if (ioctl(server.fd, BINDER_SET_CONTEXT_MGR, &zero) < 0) {
            fflush(NULL);
            _exit(71);
        }
        (void) write(up[1], "r", 1); // ready

        char go;
        (void) read(down[0], &go, 1); // wait to be told to die
        binder_close_dev(&server);
        fflush(NULL);
        _exit(0);
    }

    close(up[1]);
    close(down[0]);

    char ready = 0;
    check(read(up[0], &ready, 1) == 1 && ready == 'r', "death server became context manager");

    struct binder client = { .fd = -1 };
    if (binder_open_dev(&client, dev) < 0) {
        check(0, "death client open+mmap");
        (void) write(down[1], "d", 1);
        waitpid(child, NULL, 0);
        return;
    }

    // Take a reference on handle 0 and ask to be told when it dies.
    struct {
        uint32_t acquire_cmd;
        uint32_t handle;
        uint32_t death_cmd;
        struct binder_handle_cookie hc;
    } __attribute__((packed)) req;
    req.acquire_cmd = BC_ACQUIRE;
    req.handle = 0;
    req.death_cmd = BC_REQUEST_DEATH_NOTIFICATION;
    req.hc.handle = 0;
    req.hc.cookie = DEATH_COOKIE;

    uint8_t readbuf[512];
    size_t consumed = 0;
    check(binder_wr(&client, &req, sizeof(req), readbuf, sizeof(readbuf), &consumed) == 0,
          "client requests death notification");

    // Now let the server go away.
    (void) write(down[1], "d", 1);
    close(down[1]);
    int status = 0;
    check(waitpid(child, &status, 0) == child, "reap death server");

    struct death_ctx ctx = {};
    br_parse(readbuf, consumed, death_handler, &ctx);
    for (int i = 0; i < 20 && !ctx.got_dead; i++) {
        consumed = 0;
        if (binder_wr(&client, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        br_parse(readbuf, consumed, death_handler, &ctx);
    }

    check(ctx.got_dead, "BR_DEAD_BINDER delivered after the owner exited");
    check(ctx.cookie == DEATH_COOKIE, "BR_DEAD_BINDER carries the registered cookie");

    if (ctx.got_dead) {
        struct {
            uint32_t cmd;
            binder_uintptr_t cookie;
        } __attribute__((packed)) done = { BC_DEAD_BINDER_DONE, ctx.cookie };
        check(binder_wr(&client, &done, sizeof(done), NULL, 0, NULL) == 0, "BC_DEAD_BINDER_DONE");
    }

    binder_close_dev(&client);
    close(up[0]);
}

// ---------------------------------------------------------------------------
// Phase 4: binderfs
// ---------------------------------------------------------------------------

static void test_binderfs(void) {
    char mnt[128];
    int mounted_here = 0;
    if (binderfs_mounted) {
        // Already mounted during device setup; reuse it.
        snprintf(mnt, sizeof(mnt), "%s", binder_dir);
    } else {
        snprintf(mnt, sizeof(mnt), "/dev/binderfs");
        if (mkdir(mnt, 0755) != 0 && errno != EEXIST) {
            printf("SKIP binderfs: cannot create %s (errno=%d)\n", mnt, errno);
            return;
        }
        if (mount("binder", mnt, "binder", MS_NOSUID, NULL) != 0) {
            printf("SKIP binderfs: mount failed (errno=%d %s)\n", errno, strerror(errno));
            return;
        }
        mounted_here = 1;
    }
    check(1, "binderfs mounted");

    char control[256];
    snprintf(control, sizeof(control), "%s/binder-control", mnt);
    struct stat st;
    check(stat(control, &st) == 0 && S_ISCHR(st.st_mode), "binder-control is a char device");

    int ctl = open(control, O_RDWR | O_CLOEXEC);
    check(ctl >= 0, "open binder-control");
    if (ctl >= 0) {
        struct binderfs_device dev;
        memset(&dev, 0, sizeof(dev));
        snprintf(dev.name, sizeof(dev.name), "testbinder");
        check(ioctl(ctl, BINDER_CTL_ADD, &dev) == 0, "BINDER_CTL_ADD creates a device");
        check(dev.major == BINDER_DEV_MAJOR, "new device uses the binder major");
        check(dev.minor >= 4, "new device got a dynamic minor");

        char created[256];
        snprintf(created, sizeof(created), "%s/testbinder", mnt);
        check(stat(created, &st) == 0 && S_ISCHR(st.st_mode),
              "created device appears in binderfs");
        check(st.st_rdev == makedev(dev.major, dev.minor), "created device has the right rdev");

        // A second device with the same name must be refused.
        struct binderfs_device dup;
        memset(&dup, 0, sizeof(dup));
        snprintf(dup.name, sizeof(dup.name), "testbinder");
        check(ioctl(ctl, BINDER_CTL_ADD, &dup) < 0 && errno == EEXIST,
              "duplicate BINDER_CTL_ADD is EEXIST");

        // The new device is a working binder endpoint with its own context.
        int nb = open(created, O_RDWR | O_CLOEXEC);
        check(nb >= 0, "open the binderfs-created device");
        if (nb >= 0) {
            struct binder_version ver = {};
            check(ioctl(nb, BINDER_VERSION, &ver) == 0 && ver.protocol_version == 8,
                  "binderfs device answers BINDER_VERSION");
            int32_t zero = 0;
            check(ioctl(nb, BINDER_SET_CONTEXT_MGR, &zero) == 0,
                  "binderfs device has its own free context manager slot");
            close(nb);
        }
        close(ctl);
    }

    // Only tear down a mount this function established; the device-setup one
    // is still in use by the rest of the suite.
    if (mounted_here)
        (void) umount(mnt);
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    if (binder_setup_devices() < 0) {
        printf("SKIP binder_ipc: no binder device available (errno=%d %s)\n", errno,
               strerror(errno));
        return finish_suite("binder_ipc");
    }

    char binder_path[192], vndbinder_path[192];
    snprintf(binder_path, sizeof(binder_path), "%s", binder_dev_named("binder"));
    snprintf(vndbinder_path, sizeof(vndbinder_path), "%s", binder_dev_named("vndbinder"));
    test_logf("binder devices in %s\n", binder_dir);

    test_basics(binder_path);
    test_transaction(binder_path);
    test_death_notification(vndbinder_path);
    test_binderfs();

    return finish_suite("binder_ipc");
}
