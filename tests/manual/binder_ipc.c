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
//   secctx       A context manager claimed with BINDER_SET_CONTEXT_MGR_EXT and
//                FLAT_BINDER_FLAG_TXN_SECURITY_CTX receives BR_TRANSACTION_SEC_CTX
//                carrying the *sender's* SELinux context, in the receiver's own
//                mapping. Run against /dev/hwbinder.
//   state        /proc/ish/binder reports the live driver state -- which
//                context manager is registered, and which processes hold the
//                driver open.
//   poll         a receiver driven by epoll rather than a blocking read is
//                woken when a transaction arrives. This is how real Android
//                receives: servicemanager epolls the binder fd, so the poll
//                wakeup is the only thing that can wake it.
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
#include <sys/epoll.h>
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

struct binder_transaction_data_secctx {
    struct binder_transaction_data transaction_data;
    binder_uintptr_t secctx;
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
#define BINDER_SET_CONTEXT_MGR_EXT _IOW('b', 13, struct flat_binder_object)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)
#define BINDER_CTL_ADD          _IOWR('b', 1, struct binderfs_device)

enum {
    BR_ERROR = _IOR('r', 0, int32_t),
    BR_OK = _IO('r', 1),
    BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
    // Same nr as BR_TRANSACTION; the size in the encoding is what tells them
    // apart, so a receiver that asked for contexts gets a distinct code.
    BR_TRANSACTION_SEC_CTX = _IOR('r', 2, struct binder_transaction_data_secctx),
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
#define FLAT_BINDER_FLAG_TXN_SECURITY_CTX 0x1000

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
        case BR_TRANSACTION_SEC_CTX:
            return sizeof(struct binder_transaction_data_secctx);
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
        (void) mknod("/dev/hwbinder", S_IFCHR | 0666, makedev(BINDER_DEV_MAJOR, 1));
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

// Reads /proc/ish/binder. The driver state dump is the only way to tell the
// distinct causes of a hung transaction apart from inside the guest, so it has
// to actually reflect the driver rather than merely exist.
static int binder_state_contains(const char *needle) {
    int fd = open("/proc/ish/binder", O_RDONLY);
    if (fd < 0)
        return -1;
    static char buf[65536];
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

static void check_state_reports_manager(void) {
    char want[64];
    // The first question to ask about a hung call: is anyone listening on
    // handle 0, and is it who we think it is?
    snprintf(want, sizeof(want), "context binder: manager pid %d", (int) getpid());
    int found = binder_state_contains(want);
    if (found < 0) {
        test_logf("skip /proc/ish/binder (not present)\n");
        return;
    }
    check(found, "/proc/ish/binder names the context manager");

    snprintf(want, sizeof(want), "proc %d context binder", (int) getpid());
    check(binder_state_contains(want) == 1, "/proc/ish/binder lists our process");
    check(binder_state_contains("no processes have the driver open") == 0,
          "and does not claim the driver is unused");
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

    check_state_reports_manager();

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
// Phase 2b: a handle relayed through a third process
//
// This is the servicemanager shape, and it is precisely what the two-process
// phase above does NOT cover. There the object's owner replies to its own
// caller, so the driver only ever turns BINDER_TYPE_BINDER into a handle for
// one other process. What servicemanager does is hold a handle to somebody
// else's node and hand it on to a THIRD process -- HANDLE -> HANDLE between
// two processes that are both strangers to the node's owner -- after which the
// recipient has to be able to call that owner directly through the handle it
// was given.
//
// It earns its own phase because on a device `service check <name>` returns
// null for every service while `service list` works, and those two differ by
// exactly this: listing returns names out of servicemanager's own map, while
// checking has to pass a binder reference back through a reply.
// ---------------------------------------------------------------------------

#define RELAY_REGISTER_CODE 0x51
#define RELAY_LOOKUP_CODE 0x52
#define RELAY_CALL_CODE 0x53
#define PROVIDER_OBJECT_PTR UINT64_C(0xbeef000000004000)
#define PROVIDER_OBJECT_COOKIE UINT64_C(0xbeef000000005000)
#define RELAY_CALL_MAGIC UINT64_C(0x0f0f0f0f0000600d)
#define RELAY_REPLY_MAGIC UINT64_C(0xa1a1a1a100007001)

static void relay_free_buffer(struct binder *b, binder_uintptr_t buffer) {
    struct {
        uint32_t cmd;
        binder_uintptr_t buffer;
    } __attribute__((packed)) freebuf = { BC_FREE_BUFFER, buffer };
    (void) binder_wr(b, &freebuf, sizeof(freebuf), NULL, 0, NULL);
}

// Pulls the single flat_binder_object out of a transaction, if it carries one.
static int relay_get_object(const struct binder_transaction_data *tr,
                            struct flat_binder_object *out) {
    if (tr->offsets_size != sizeof(binder_size_t))
        return -1;
    binder_size_t off;
    memcpy(&off, (void *) (uintptr_t) tr->data.ptr.offsets, sizeof(off));
    memcpy(out, (uint8_t *) (uintptr_t) tr->data.ptr.buffer + off, sizeof(*out));
    return 0;
}

struct relay_mgr_ctx {
    struct binder *b;
    uint32_t provider_handle;
    int registered;
    int served_lookup;
};

static int relay_mgr_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct relay_mgr_ctx *ctx = vctx;
    if (cmd != BR_TRANSACTION)
        return 0;
    struct binder_transaction_data tr;
    memcpy(&tr, payload, sizeof(tr));

    if (tr.code == RELAY_REGISTER_CODE) {
        struct flat_binder_object obj;
        int got = relay_get_object(&tr, &obj) == 0;
        check(got, "manager: the register transaction carries one object");
        if (got) {
            check(obj.type == BINDER_TYPE_HANDLE,
                  "manager: the provider's own node arrives as a handle");
            ctx->provider_handle = obj.handle;
        }
        // Take a reference of our own BEFORE releasing the buffer: freeing it
        // drops the one the transaction granted. servicemanager does the same
        // thing through libbinder's refcounting, and without it the handle
        // stashed here would be dangling by the time anyone asked for it.
        struct {
            uint32_t cmd;
            uint32_t handle;
        } __attribute__((packed)) acquire = { BC_ACQUIRE, ctx->provider_handle };
        check(binder_wr(ctx->b, &acquire, sizeof(acquire), NULL, 0, NULL) >= 0,
              "manager: BC_ACQUIRE on the relayed handle");

        static uint64_t ack;
        ack = RELAY_REPLY_MAGIC;
        struct {
            uint32_t cmd;
            struct binder_transaction_data tr;
        } __attribute__((packed)) out;
        memset(&out, 0, sizeof(out));
        out.cmd = BC_REPLY;
        out.tr.data_size = sizeof(ack);
        out.tr.data.ptr.buffer = (binder_uintptr_t) (uintptr_t) &ack;

        relay_free_buffer(ctx->b, tr.data.ptr.buffer);
        (void) binder_wr(ctx->b, &out, sizeof(out), NULL, 0, NULL);
        ctx->registered = 1;
        return 1;
    }

    if (tr.code == RELAY_LOOKUP_CODE) {
        // The path under test: hand a handle we hold to a third process.
        static struct {
            uint64_t magic;
            struct flat_binder_object obj;
        } reply_data;
        static binder_size_t reply_offsets[1];

        reply_data.magic = RELAY_REPLY_MAGIC;
        memset(&reply_data.obj, 0, sizeof(reply_data.obj));
        reply_data.obj.type = BINDER_TYPE_HANDLE;
        reply_data.obj.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
        reply_data.obj.handle = ctx->provider_handle;
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

        relay_free_buffer(ctx->b, tr.data.ptr.buffer);
        check(binder_wr(ctx->b, &out, sizeof(out), NULL, 0, NULL) >= 0,
              "manager: a reply carrying a relayed handle is accepted");
        ctx->served_lookup = 1;
        return 1;
    }
    return 0;
}

// The provider: registers its own node with the manager, then answers calls
// that arrive on it -- from a process it has never heard of.
struct relay_provider_ctx {
    struct binder *b;
    int got_call;
    int registered_ack;
};

static int relay_provider_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct relay_provider_ctx *ctx = vctx;
    if (cmd == BR_FAILED_REPLY || cmd == BR_DEAD_REPLY)
        return -1;
    if (cmd == BR_REPLY) {
        struct binder_transaction_data tr;
        memcpy(&tr, payload, sizeof(tr));
        relay_free_buffer(ctx->b, tr.data.ptr.buffer);
        ctx->registered_ack = 1;
        return 1;
    }
    if (cmd != BR_TRANSACTION)
        return 0;

    struct binder_transaction_data tr;
    memcpy(&tr, payload, sizeof(tr));
    if (tr.code != RELAY_CALL_CODE)
        return 0;
    // Arriving here at all is the point: a stranger reached us through a
    // handle that only ever existed inside the manager.
    if (tr.target.ptr == PROVIDER_OBJECT_PTR)
        ctx->got_call = 1;

    static uint64_t reply;
    reply = RELAY_REPLY_MAGIC;
    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) out;
    memset(&out, 0, sizeof(out));
    out.cmd = BC_REPLY;
    out.tr.data_size = sizeof(reply);
    out.tr.data.ptr.buffer = (binder_uintptr_t) (uintptr_t) &reply;

    relay_free_buffer(ctx->b, tr.data.ptr.buffer);
    (void) binder_wr(ctx->b, &out, sizeof(out), NULL, 0, NULL);
    return 1;
}

// The client: asks the manager for the provider, then calls it directly.
struct relay_client_ctx {
    struct binder *b;
    uint32_t handle;
    int got_lookup_reply;
    int got_call_reply;
};

static int relay_client_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct relay_client_ctx *ctx = vctx;
    if (cmd == BR_FAILED_REPLY || cmd == BR_DEAD_REPLY || cmd == BR_ERROR)
        return -1;
    if (cmd != BR_REPLY)
        return 0;

    struct binder_transaction_data tr;
    memcpy(&tr, payload, sizeof(tr));
    if (!ctx->got_lookup_reply) {
        struct flat_binder_object obj;
        if (relay_get_object(&tr, &obj) == 0 && obj.type == BINDER_TYPE_HANDLE) {
            ctx->handle = obj.handle;
            // Acquire before the buffer goes back, or the handle is dead on
            // arrival: the reference the transaction granted belongs to the
            // buffer, and BC_FREE_BUFFER drops it. libbinder does exactly this
            // inside Parcel::readStrongBinder -> getStrongProxyForHandle, which
            // is why a real client never notices the rule exists. A transaction
            // sent on a handle whose strong count fell to zero comes back
            // BR_FAILED_REPLY, which is what this originally did.
            struct {
                uint32_t cmd;
                uint32_t handle;
            } __attribute__((packed)) acquire = { BC_ACQUIRE, ctx->handle };
            (void) binder_wr(ctx->b, &acquire, sizeof(acquire), NULL, 0, NULL);
        }
        ctx->got_lookup_reply = 1;
    } else {
        uint64_t magic = 0;
        if (tr.data_size >= sizeof(magic))
            memcpy(&magic, (void *) (uintptr_t) tr.data.ptr.buffer, sizeof(magic));
        if (magic == RELAY_REPLY_MAGIC)
            ctx->got_call_reply = 1;
    }
    relay_free_buffer(ctx->b, tr.data.ptr.buffer);
    return 1;
}

// Sends one synchronous transaction and pumps until its reply arrives.
static int relay_call(struct binder *b, uint32_t handle, uint32_t code,
                      void *data, size_t data_size, binder_size_t *offsets,
                      size_t offsets_size, br_handler handler, void *ctx,
                      const int *done) {
    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) out;
    memset(&out, 0, sizeof(out));
    out.cmd = BC_TRANSACTION;
    out.tr.target.handle = handle;
    out.tr.code = code;
    out.tr.data_size = data_size;
    out.tr.offsets_size = offsets_size;
    out.tr.data.ptr.buffer = (binder_uintptr_t) (uintptr_t) data;
    out.tr.data.ptr.offsets = (binder_uintptr_t) (uintptr_t) offsets;

    uint8_t readbuf[512];
    size_t consumed = 0;
    if (binder_wr(b, &out, sizeof(out), readbuf, sizeof(readbuf), &consumed) < 0)
        return -1;
    if (br_parse(readbuf, consumed, handler, ctx) < 0)
        return -1;
    while (!*done) {
        consumed = 0;
        if (binder_wr(b, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (br_parse(readbuf, consumed, handler, ctx) < 0)
            return -1;
    }
    return 0;
}

static void test_handle_relay(const char *dev) {
    struct binder mgr = { .fd = -1 };
    if (binder_open_dev(&mgr, dev) < 0) {
        check(0, "relay: manager open+mmap");
        return;
    }
    int32_t zero = 0;
    if (ioctl(mgr.fd, BINDER_SET_CONTEXT_MGR, &zero) < 0) {
        printf("SKIP handle relay: context manager already claimed (errno=%d)\n", errno);
        binder_close_dev(&mgr);
        return;
    }

    int prov_pipe[2], cli_pipe[2];
    check(pipe(prov_pipe) == 0 && pipe(cli_pipe) == 0, "relay: sync pipes");

    pid_t provider = fork();
    check(provider >= 0, "relay: fork provider");
    if (provider == 0) {
        close(prov_pipe[0]);
        close(cli_pipe[0]);
        close(cli_pipe[1]);
        struct binder b = { .fd = -1 };
        if (binder_open_dev(&b, dev) < 0) {
            fflush(NULL);
            _exit(70);
        }
        static struct {
            uint64_t magic;
            struct flat_binder_object obj;
        } reg;
        static binder_size_t reg_offsets[1];
        reg.magic = RELAY_CALL_MAGIC;
        memset(&reg.obj, 0, sizeof(reg.obj));
        reg.obj.type = BINDER_TYPE_BINDER;
        reg.obj.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
        reg.obj.binder = PROVIDER_OBJECT_PTR;
        reg.obj.cookie = PROVIDER_OBJECT_COOKIE;
        reg_offsets[0] = offsetof(typeof(reg), obj);

        struct relay_provider_ctx ctx = { .b = &b };
        int rc = relay_call(&b, 0, RELAY_REGISTER_CODE, &reg, sizeof(reg),
                            reg_offsets, sizeof(reg_offsets),
                            relay_provider_handler, &ctx, &ctx.registered_ack);
        // Registered: let the client go, then serve the call it makes.
        (void) write(prov_pipe[1], "g", 1);
        close(prov_pipe[1]);

        uint8_t readbuf[512];
        while (rc == 0 && !ctx.got_call) {
            size_t consumed = 0;
            if (binder_wr(&b, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
                if (errno == EINTR)
                    continue;
                rc = -1;
                break;
            }
            if (br_parse(readbuf, consumed, relay_provider_handler, &ctx) < 0)
                break;
        }
        binder_close_dev(&b);
        fflush(NULL);
        _exit(rc == 0 && ctx.got_call ? 0 : 73);
    }

    pid_t client = fork();
    check(client >= 0, "relay: fork client");
    if (client == 0) {
        close(prov_pipe[1]);
        close(cli_pipe[0]);
        char go;
        (void) read(prov_pipe[0], &go, 1);   // wait until the provider registered
        close(prov_pipe[0]);

        struct binder b = { .fd = -1 };
        if (binder_open_dev(&b, dev) < 0) {
            fflush(NULL);
            _exit(70);
        }
        static uint64_t ask;
        ask = RELAY_CALL_MAGIC;
        struct relay_client_ctx ctx = { .b = &b };
        int rc = relay_call(&b, 0, RELAY_LOOKUP_CODE, &ask, sizeof(ask), NULL, 0,
                            relay_client_handler, &ctx, &ctx.got_lookup_reply);
        int got_handle = rc == 0 && ctx.handle != 0;
        if (got_handle) {
            static uint64_t call;
            call = RELAY_CALL_MAGIC;
            rc = relay_call(&b, ctx.handle, RELAY_CALL_CODE, &call, sizeof(call),
                            NULL, 0, relay_client_handler, &ctx, &ctx.got_call_reply);
        }
        (void) write(cli_pipe[1], got_handle ? "h" : "x", 1);
        close(cli_pipe[1]);
        binder_close_dev(&b);
        fflush(NULL);
        _exit(got_handle && rc == 0 && ctx.got_call_reply ? 0 : 74);
    }

    close(prov_pipe[0]);
    close(prov_pipe[1]);
    close(cli_pipe[1]);

    // Serve both the registration and the lookup.
    struct relay_mgr_ctx ctx = { .b = &mgr };
    uint8_t readbuf[1024];
    while (!(ctx.registered && ctx.served_lookup)) {
        size_t consumed = 0;
        if (binder_wr(&mgr, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            check(0, "relay: manager BINDER_WRITE_READ");
            break;
        }
        if (br_parse(readbuf, consumed, relay_mgr_handler, &ctx) < 0)
            break;
    }
    check(ctx.registered, "relay: manager saw the registration");
    check(ctx.served_lookup, "relay: manager answered the lookup");

    char verdict = 0;
    (void) read(cli_pipe[0], &verdict, 1);
    close(cli_pipe[0]);
    check(verdict == 'h', "relay: the client received a usable handle");

    int status = 0;
    check(waitpid(provider, &status, 0) == provider, "relay: reap provider");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "relay: the provider was called by a process it never met");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("       provider exit status %d\n", WEXITSTATUS(status));

    status = 0;
    check(waitpid(client, &status, 0) == client, "relay: reap client");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "relay: the client called through the relayed handle");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("       client exit status %d\n", WEXITSTATUS(status));

    binder_close_dev(&mgr);
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
// Phase 4: the caller's SELinux context (BR_TRANSACTION_SEC_CTX)
// ---------------------------------------------------------------------------

// A node registered with FLAT_BINDER_FLAG_TXN_SECURITY_CTX is told who is
// calling it. servicemanager is why this exists: it decides every add/find
// against the caller's context, and taking it from the transaction is
// race-free in a way its getpidcon() fallback is not -- by the time it could
// look up /proc/<pid>/attr/current, the caller may have exited and had its pid
// reused by someone else.
#define CLIENT_CONTEXT "u:r:untrusted_app:s0"

struct secctx_ctx {
    struct binder *b;
    int saw;
    char seen[256];
};

static int secctx_handler(uint32_t cmd, const void *payload, void *vctx) {
    struct secctx_ctx *ctx = vctx;

    if (cmd == BR_INCREFS || cmd == BR_ACQUIRE) {
        ack_refs(ctx->b, cmd, payload);
        return 0;
    }
    if (cmd == BR_TRANSACTION) {
        // Silently downgrading would leave the receiver reading a secctx field
        // that was never written.
        check(0, "node asked for contexts but got a plain BR_TRANSACTION");
        return 1;
    }
    if (cmd != BR_TRANSACTION_SEC_CTX)
        return 0;

    struct binder_transaction_data_secctx trs;
    memcpy(&trs, payload, sizeof(trs));
    ctx->saw = 1;

    check(trs.secctx != 0, "the transaction carries a context pointer");
    if (trs.secctx != 0) {
        // It arrives through the same single copy as the payload, so it has to
        // land inside the receiver's own mapping.
        const char *p = (const char *) (uintptr_t) trs.secctx;
        const char *base = ctx->b->map;
        check(p >= base && p < base + BINDER_MAP_SIZE,
              "the context lies inside the receiver's mapping");
        if (p >= base && p < base + BINDER_MAP_SIZE)
            snprintf(ctx->seen, sizeof(ctx->seen), "%s", p);
    }

    uint64_t magic = 0;
    if (trs.transaction_data.data_size >= sizeof(magic))
        memcpy(&magic, (void *) (uintptr_t) trs.transaction_data.data.ptr.buffer,
               sizeof(magic));
    check(magic == SERVICE_MAGIC, "the payload survives alongside the context");

    struct {
        uint32_t cmd;
        binder_uintptr_t buffer;
    } __attribute__((packed)) freebuf = {
        BC_FREE_BUFFER, trs.transaction_data.data.ptr.buffer
    };
    (void) binder_wr(ctx->b, &freebuf, sizeof(freebuf), NULL, 0, NULL);
    return 1;
}

static int set_own_context(const char *ctx) {
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, ctx, strlen(ctx) + 1);
    close(fd);
    return n > 0 ? 0 : -1;
}

static void test_security_context(const char *dev) {
    if (access(dev, F_OK) != 0) {
        printf("SKIP secctx: no %s\n", dev);
        return;
    }
    if (access("/proc/self/attr/current", R_OK) != 0) {
        printf("SKIP secctx: no /proc/self/attr/current\n");
        return;
    }

    struct binder server = { .fd = -1 };
    if (binder_open_dev(&server, dev) < 0) {
        check(0, "secctx server open+mmap");
        return;
    }

    // The ext form of claiming handle 0 is the only way to ask for contexts:
    // it takes a flat_binder_object so the flags have somewhere to live.
    struct flat_binder_object mgr = {
        .type = BINDER_TYPE_BINDER,
        .flags = FLAT_BINDER_FLAG_TXN_SECURITY_CTX | FLAT_BINDER_FLAG_ACCEPTS_FDS,
    };
    if (ioctl(server.fd, BINDER_SET_CONTEXT_MGR_EXT, &mgr) < 0) {
        printf("SKIP secctx: context manager already claimed on %s (errno=%d)\n", dev, errno);
        binder_close_dev(&server);
        return;
    }
    check(1, "BINDER_SET_CONTEXT_MGR_EXT claims handle 0 asking for contexts");

    int sync_pipe[2];
    check(pipe(sync_pipe) == 0, "secctx sync pipe");

    pid_t child = fork();
    check(child >= 0, "fork secctx client");
    if (child == 0) {
        close(sync_pipe[1]);
        char go;
        (void) read(sync_pipe[0], &go, 1);
        close(sync_pipe[0]);

        // Relabel after the fork, so what the server sees can only have come
        // from this process rather than being inherited by both ends.
        if (set_own_context(CLIENT_CONTEXT) != 0) {
            fflush(NULL);
            _exit(73);
        }

        struct binder client = { .fd = -1 };
        if (binder_open_dev(&client, dev) < 0) {
            fflush(NULL);
            _exit(70);
        }
        struct client_ctx cctx = { .b = &client };
        client_call(&client, TF_ONE_WAY, &cctx);
        binder_close_dev(&client);
        fflush(NULL);
        _exit(failures_total == 0 ? 0 : 71);
    }

    close(sync_pipe[0]);
    (void) write(sync_pipe[1], "g", 1);
    close(sync_pipe[1]);

    struct secctx_ctx ctx = { .b = &server };
    uint8_t readbuf[512];
    for (int i = 0; i < 16 && !ctx.saw; i++) {
        size_t consumed = 0;
        if (binder_wr(&server, NULL, 0, readbuf, sizeof(readbuf), &consumed) < 0) {
            if (errno == EINTR)
                continue;
            check(0, "secctx server BINDER_WRITE_READ");
            break;
        }
        br_parse(readbuf, consumed, secctx_handler, &ctx);
    }

    check(ctx.saw, "the transaction arrived as BR_TRANSACTION_SEC_CTX");
    check(strcmp(ctx.seen, CLIENT_CONTEXT) == 0,
          "the context is the sender's, not the receiver's");
    if (ctx.saw && strcmp(ctx.seen, CLIENT_CONTEXT) != 0)
        printf("       saw \"%s\", wanted \"%s\"\n", ctx.seen, CLIENT_CONTEXT);

    int status = 0;
    check(waitpid(child, &status, 0) == child, "reap secctx client");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "secctx client completed");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("       client exit status %d\n", WEXITSTATUS(status));

    binder_close_dev(&server);
}

// ---------------------------------------------------------------------------
// Phase 5: delivery to a poll-driven receiver
// ---------------------------------------------------------------------------

// Every other phase blocks in BINDER_WRITE_READ, which is woken by notify() on
// the thread's own condition variable. Real Android does not: servicemanager
// drives an android::Looper and epolls the binder fd, so the ONLY thing that
// can wake it is the driver's poll wakeup. If that is ever dropped, a
// transaction sits in the queue and the receiver sleeps forever -- and no
// blocking-read test can tell.
static void test_poll_delivery(const char *dev) {
    if (access(dev, F_OK) != 0) {
        printf("SKIP poll: no %s\n", dev);
        return;
    }

    struct binder server = { .fd = -1 };
    if (binder_open_dev(&server, dev) < 0) {
        check(0, "poll server open+mmap");
        return;
    }
    int32_t zero = 0;
    if (ioctl(server.fd, BINDER_SET_CONTEXT_MGR, &zero) < 0) {
        printf("SKIP poll: context manager already claimed on %s (errno=%d)\n", dev, errno);
        binder_close_dev(&server);
        return;
    }

    // Enter the looper the way a real receiver does, then never issue a
    // blocking read: readiness has to arrive through poll alone.
    uint32_t enter = BC_ENTER_LOOPER;
    check(binder_wr(&server, &enter, sizeof(enter), NULL, 0, NULL) == 0, "poll server enters looper");

    int epfd = epoll_create1(0);
    check(epfd >= 0, "epoll_create1");
    struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = server.fd } };
    check(epfd >= 0 && epoll_ctl(epfd, EPOLL_CTL_ADD, server.fd, &ev) == 0, "epoll_ctl ADD binder fd");

    int sync_pipe[2];
    check(pipe(sync_pipe) == 0, "poll sync pipe");

    pid_t child = fork();
    check(child >= 0, "fork poll client");
    if (child == 0) {
        close(sync_pipe[1]);
        char go;
        (void) !read(sync_pipe[0], &go, 1);
        close(sync_pipe[0]);
        struct binder client = { .fd = -1 };
        if (binder_open_dev(&client, dev) < 0) {
            fflush(NULL);
            _exit(70);
        }
        struct client_ctx cctx = { .b = &client };
        client_call(&client, TF_ONE_WAY, &cctx);
        binder_close_dev(&client);
        fflush(NULL);
        _exit(0);
    }
    close(sync_pipe[0]);

    // Drain anything already pending, so the wakeup we are testing is caused
    // by the child's transaction and not by leftover setup traffic.
    struct epoll_event got;
    while (epoll_wait(epfd, &got, 1, 0) > 0) {
        uint8_t drain[512];
        size_t consumed = 0;
        if (binder_wr(&server, NULL, 0, drain, sizeof(drain), &consumed) < 0)
            break;
        if (consumed == 0)
            break;
    }

    (void) !write(sync_pipe[1], "g", 1);
    close(sync_pipe[1]);

    // Generous: this is a hang detector, not a latency measurement.
    int n = epoll_wait(epfd, &got, 1, 10000);
    check(n > 0, "the binder fd becomes readable when a transaction arrives");
    if (n <= 0)
        printf("       epoll_wait timed out: a poll wakeup was dropped\n");

    if (n > 0) {
        uint8_t readbuf[512];
        size_t consumed = 0;
        check(binder_wr(&server, NULL, 0, readbuf, sizeof(readbuf), &consumed) == 0,
              "the woken read returns");
        struct server_ctx sctx = { .b = &server };
        br_parse(readbuf, consumed, server_handler, &sctx);
        check(sctx.saw_transaction > 0, "and the transaction is actually there");
    }

    close(epfd);
    int status = 0;
    waitpid(child, &status, 0);
    binder_close_dev(&server);
}

// ---------------------------------------------------------------------------
// Phase 6: binderfs
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
    test_handle_relay(binder_path);
    test_death_notification(vndbinder_path);
    test_security_context(binder_dev_named("hwbinder"));
    test_poll_delivery(binder_dev_named("hwbinder"));
    test_binderfs();

    return finish_suite("binder_ipc");
}
