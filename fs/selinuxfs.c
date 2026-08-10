// selinuxfs -- a permissive SELinux stub.
//
// THIS ENFORCES NOTHING. It is not an implementation of SELinux and must never
// be mistaken for one: every access check answers "allowed", the policy load
// interface discards what it is given, and no process ever carries a real
// security context. iSH has no LSM and no way to mediate anything.
//
// It exists because Android userspace refuses to start without a security
// server to talk to, even when that server would permit everything. The very
// first thing servicemanager does is:
//
//     CHECK(selinux_status_open(true /*fallback*/) >= 0);
//
// CHECK is fatal. libselinux looks for /sys/fs/selinux/status, cannot find it,
// falls back to a NETLINK_SELINUX socket, cannot open that either, and returns
// negative -- so servicemanager aborts before reaching a single line of its own
// logic. logd, hwservicemanager, vold and init all do some version of the same
// dance. Presenting a filesystem that says "SELinux is present, and it is in
// permissive mode" is what gets them past it.
//
// Permissive is not a shortcut here, it is the honest description: a permissive
// SELinux kernel also allows everything and only logs. The difference is that a
// real one could be switched to enforcing; this one refuses, which is why
// writing 1 to `enforce` returns EINVAL rather than silently lying.
//
// Mount it the way Android does:
//     mount -t selinuxfs selinuxfs /sys/fs/selinux

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "fs/poll.h"
#include "fs/real.h"
#include "util/sync.h"

// include/uapi/linux/magic.h
#define SELINUX_MAGIC 0xf97cff8c

// The policy version we claim. Nothing parses a policy here, but libselinux
// compares this against what its own policy files were built for, so it has to
// be plausible and recent.
#define SELINUX_POLICYVERS "33"

// The shared page libselinux mmaps from `status`. Kept in sync with
// selinux_status_t in libselinux/src/procattr.c -- five u32s, and a sequence
// number that is even when the contents are stable.
struct selinux_status_page {
    uint32_t version;
    uint32_t sequence;
    uint32_t enforcing;
    uint32_t policyload;
    uint32_t deny_unknown;
};

// Entry ids. All non-negative so a lookup can return a negative errno without
// ambiguity -- iSH's _ENOENT is -2, and a -1/-2 sentinel pair would be
// indistinguishable from "not found". (binderfs learned this the hard way.)
enum {
    SELINUXFS_ROOT = 0,
    SELINUXFS_ENFORCE,
    SELINUXFS_POLICYVERS,
    SELINUXFS_DENY_UNKNOWN,
    SELINUXFS_MLS,
    SELINUXFS_CHECKREQPROT,
    SELINUXFS_STATUS,
    SELINUXFS_LOAD,
    SELINUXFS_NULL,
    SELINUXFS_ACCESS,
    SELINUXFS_COUNT,
};

static const char *const selinuxfs_names[SELINUXFS_COUNT] = {
    [SELINUXFS_ROOT] = "",
    [SELINUXFS_ENFORCE] = "enforce",
    [SELINUXFS_POLICYVERS] = "policyvers",
    [SELINUXFS_DENY_UNKNOWN] = "deny_unknown",
    [SELINUXFS_MLS] = "mls",
    [SELINUXFS_CHECKREQPROT] = "checkreqprot",
    [SELINUXFS_STATUS] = "status",
    [SELINUXFS_LOAD] = "load",
    [SELINUXFS_NULL] = "null",
    [SELINUXFS_ACCESS] = "access",
};

// Fixed contents of the scalar files. NULL means the file is not simply read.
static const char *const selinuxfs_contents[SELINUXFS_COUNT] = {
    [SELINUXFS_ENFORCE] = "0",
    [SELINUXFS_POLICYVERS] = SELINUX_POLICYVERS,
    [SELINUXFS_DENY_UNKNOWN] = "0",
    // MLS is on in every Android policy, and libselinux parses contexts
    // differently depending on this.
    [SELINUXFS_MLS] = "1",
    [SELINUXFS_CHECKREQPROT] = "0",
};

// The mmap-able status page, created once and shared by every opener. Backed
// by a host temp file so guest mappings are ordinary host mmaps, the same way
// ashmem and binder's receive region work.
static int selinuxfs_status_fd = -1;
static lock_t selinuxfs_status_lock = LOCK_INITIALIZER;

static int selinuxfs_status_host_fd(void) {
    lock(&selinuxfs_status_lock, 0);
    if (selinuxfs_status_fd < 0) {
        int fd = host_unlinked_tmpfd();
        if (fd < 0) {
            unlock(&selinuxfs_status_lock);
            return fd;
        }
        if (ftruncate(fd, PAGE_SIZE) < 0) {
            int err = errno_map();
            close(fd);
            unlock(&selinuxfs_status_lock);
            return err;
        }
        // sequence even == stable; enforcing 0 == permissive; no policy has
        // been loaded and unknown classes are allowed rather than denied.
        struct selinux_status_page page = {
            .version = 1,
            .sequence = 0,
            .enforcing = 0,
            .policyload = 0,
            .deny_unknown = 0,
        };
        if (pwrite(fd, &page, sizeof(page), 0) != (ssize_t) sizeof(page)) {
            int err = errno_map();
            close(fd);
            unlock(&selinuxfs_status_lock);
            return err;
        }
        selinuxfs_status_fd = fd;
    }
    int fd = selinuxfs_status_fd;
    unlock(&selinuxfs_status_lock);
    return fd;
}

// Per-open state. Only `access` needs any: libselinux writes a query and reads
// the verdict back from the same descriptor.
struct selinuxfs_open {
    int entry;
    char response[128];
    size_t response_len;
};

static const struct fd_ops selinuxfs_fdops;

static int selinuxfs_entry_of(struct fd *fd) {
    struct selinuxfs_open *open_state = fd->data;
    return open_state != NULL ? open_state->entry : SELINUXFS_ROOT;
}

static int selinuxfs_lookup(const char *path) {
    if (path[0] == '\0')
        return SELINUXFS_ROOT;
    if (path[0] != '/' || path[1] == '\0' || strchr(path + 1, '/') != NULL)
        return _ENOENT;
    for (int i = 1; i < SELINUXFS_COUNT; i++) {
        if (strcmp(path + 1, selinuxfs_names[i]) == 0)
            return i;
    }
    return _ENOENT;
}

static void selinuxfs_stat_entry(int entry, struct statbuf *stat) {
    *stat = (struct statbuf) {};
    stat->inode = entry + 1;
    stat->nlink = 1;
    if (entry == SELINUXFS_ROOT) {
        stat->mode = S_IFDIR | 0755;
        stat->nlink = 2;
        return;
    }
    // Everything is world-readable; the interfaces userspace writes to are
    // world-writable, matching a real selinuxfs.
    switch (entry) {
        case SELINUXFS_LOAD:
            stat->mode = S_IFREG | 0600;
            break;
        case SELINUXFS_ENFORCE:
        case SELINUXFS_CHECKREQPROT:
            stat->mode = S_IFREG | 0644;
            break;
        case SELINUXFS_ACCESS:
        case SELINUXFS_NULL:
            stat->mode = S_IFREG | 0666;
            break;
        case SELINUXFS_STATUS:
            stat->mode = S_IFREG | 0444;
            stat->size = PAGE_SIZE;
            break;
        default:
            stat->mode = S_IFREG | 0444;
            break;
    }
    const char *contents = selinuxfs_contents[entry];
    if (contents != NULL)
        stat->size = strlen(contents);
}

static struct fd *selinuxfs_open(struct mount *UNUSED(mount), const char *path, int UNUSED(flags),
                                 int UNUSED(mode)) {
    int entry = selinuxfs_lookup(path);
    if (entry < 0)
        return ERR_PTR(entry);
    struct fd *fd = fd_create(&selinuxfs_fdops);
    if (fd == NULL)
        return ERR_PTR(_ENOMEM);
    struct selinuxfs_open *open_state = calloc(1, sizeof(*open_state));
    if (open_state == NULL) {
        fd_close(fd);
        return ERR_PTR(_ENOMEM);
    }
    open_state->entry = entry;
    fd->data = open_state;
    return fd;
}

static int selinuxfs_close(struct fd *fd) {
    free(fd->data);
    fd->data = NULL;
    return 0;
}

static ssize_t selinuxfs_read(struct fd *fd, void *buf, size_t bufsize) {
    struct selinuxfs_open *open_state = fd->data;
    if (open_state == NULL)
        return _EINVAL;

    const char *src = NULL;
    size_t len = 0;
    switch (open_state->entry) {
        case SELINUXFS_ACCESS:
            // Whatever verdict the last write computed.
            src = open_state->response;
            len = open_state->response_len;
            break;
        case SELINUXFS_NULL:
            return 0; // /sys/fs/selinux/null is the SELinux /dev/null
        case SELINUXFS_STATUS: {
            // Readable as well as mmapable; libselinux prefers the mapping but
            // will fall back to reading it.
            int host_fd = selinuxfs_status_host_fd();
            if (host_fd < 0)
                return host_fd;
            ssize_t n = pread(host_fd, buf, bufsize, (off_t) fd->offset);
            if (n < 0)
                return errno_map();
            fd->offset += n;
            return n;
        }
        default:
            src = selinuxfs_contents[open_state->entry];
            if (src == NULL)
                return 0;
            len = strlen(src);
            break;
    }

    if (fd->offset >= len)
        return 0;
    size_t remaining = len - fd->offset;
    if (bufsize > remaining)
        bufsize = remaining;
    memcpy(buf, src + fd->offset, bufsize);
    fd->offset += bufsize;
    return (ssize_t) bufsize;
}

static ssize_t selinuxfs_write(struct fd *fd, const void *buf, size_t bufsize) {
    struct selinuxfs_open *open_state = fd->data;
    if (open_state == NULL)
        return _EINVAL;

    switch (open_state->entry) {
        case SELINUXFS_ACCESS: {
            // libselinux writes "scontext tcontext tclass requested" and reads
            // back "allowed decided auditallow auditdeny seqno flags".
            //
            // Everything is allowed, and everything is decided -- an undecided
            // bit would send libselinux back to ask again about a policy that
            // does not exist. auditallow/auditdeny are empty because there is
            // nothing to audit to.
            open_state->response_len = (size_t) snprintf(
                open_state->response, sizeof(open_state->response),
                "%x %x %x %x %u %x", 0xffffffff, 0xffffffff, 0, 0, 0u, 0);
            fd->offset = 0;
            return (ssize_t) bufsize;
        }

        case SELINUXFS_ENFORCE: {
            // Accept 0 (already permissive) and refuse anything else rather
            // than pretending to enforce a policy we cannot evaluate. A caller
            // that insists on enforcing deserves a hard error, not silence.
            char value[16];
            size_t n = bufsize < sizeof(value) - 1 ? bufsize : sizeof(value) - 1;
            memcpy(value, buf, n);
            value[n] = '\0';
            if (atoi(value) != 0)
                return _EINVAL;
            return (ssize_t) bufsize;
        }

        case SELINUXFS_LOAD:
            // A policy image. There is nothing here that could evaluate it, so
            // it is accepted and discarded -- reporting success matters
            // because init treats a failed policy load as fatal.
            return (ssize_t) bufsize;

        case SELINUXFS_CHECKREQPROT:
        case SELINUXFS_NULL:
            return (ssize_t) bufsize;

        default:
            return _EACCES;
    }
}

static int selinuxfs_mmap(struct fd *fd, struct mem *mem, page_t start, pages_t pages, off_t offset,
                          int prot, int flags) {
    struct selinuxfs_open *open_state = fd->data;
    if (open_state == NULL || open_state->entry != SELINUXFS_STATUS)
        return _ENODEV;
    // The status page is shared and must never be written by userspace.
    if (prot & P_WRITE)
        return _EPERM;
    int host_fd = selinuxfs_status_host_fd();
    if (host_fd < 0)
        return host_fd;
    return host_fd_mmap(host_fd, mem, start, pages, offset, prot, flags);
}

static int selinuxfs_poll(struct fd *UNUSED(fd)) {
    return POLL_READ | POLL_WRITE;
}

static int selinuxfs_readdir(struct fd *fd, struct dir_entry *entry) {
    if (selinuxfs_entry_of(fd) != SELINUXFS_ROOT)
        return _ENOTDIR;
    int index = (int) fd->offset + 1; // entry 0 is the root itself
    if (index >= SELINUXFS_COUNT)
        return 0;
    fd->offset = index;
    strcpy(entry->name, selinuxfs_names[index]);
    entry->inode = index + 1;
    entry->type = DT_REG;
    return 1;
}

static int selinuxfs_getpath(struct fd *fd, char *buf) {
    int entry = selinuxfs_entry_of(fd);
    if (entry == SELINUXFS_ROOT)
        strcpy(buf, "");
    else
        snprintf(buf, MAX_PATH, "/%s", selinuxfs_names[entry]);
    return 0;
}

static int selinuxfs_stat(struct mount *UNUSED(mount), const char *path, struct statbuf *stat) {
    int entry = selinuxfs_lookup(path);
    if (entry < 0)
        return entry;
    selinuxfs_stat_entry(entry, stat);
    return 0;
}

static int selinuxfs_fstat(struct fd *fd, struct statbuf *stat) {
    selinuxfs_stat_entry(selinuxfs_entry_of(fd), stat);
    return 0;
}

static int selinuxfs_statfs(struct mount *UNUSED(mount), struct statfsbuf *stat) {
    // is_selinux_enabled() checks the filesystem type, not just the path, so
    // this magic is what makes libselinux believe SELinux is present at all.
    stat->type = SELINUX_MAGIC;
    stat->namelen = 255;
    stat->bsize = PAGE_SIZE;
    return 0;
}

static int selinuxfs_fsetattr(struct fd *UNUSED(fd), struct attr UNUSED(attr)) {
    return _EPERM;
}

static int selinuxfs_setattr(struct mount *UNUSED(mount), const char *path, struct attr UNUSED(attr)) {
    int entry = selinuxfs_lookup(path);
    if (entry < 0)
        return entry;
    return _EPERM;
}

const struct fs_ops selinuxfs = {
    .name = "selinuxfs", .magic = SELINUX_MAGIC,
    .open = selinuxfs_open,
    .getpath = selinuxfs_getpath,
    .stat = selinuxfs_stat,
    .fstat = selinuxfs_fstat,
    .statfs = selinuxfs_statfs,
    .setattr = selinuxfs_setattr,
    .fsetattr = selinuxfs_fsetattr,
};

static const struct fd_ops selinuxfs_fdops = {
    .read = selinuxfs_read,
    .write = selinuxfs_write,
    .mmap = selinuxfs_mmap,
    .poll = selinuxfs_poll,
    .readdir = selinuxfs_readdir,
    .close = selinuxfs_close,
};
