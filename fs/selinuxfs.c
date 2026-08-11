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
    SELINUXFS_CLASS,
    SELINUXFS_COUNT,
    // Below the `class` directory. These have no entry in selinuxfs_names:
    // their names come from the path being looked up rather than a table,
    // because ANY class or permission name resolves here. See
    // selinuxfs_class_index() for why that is the correct behaviour for a
    // stub that permits everything.
    SELINUXFS_CLASS_SUBDIR,
    SELINUXFS_CLASS_INDEX,
    SELINUXFS_CLASS_PERMS_DIR,
    SELINUXFS_CLASS_PERM,
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
    [SELINUXFS_CLASS] = "class",
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
#define SELINUXFS_NAME_MAX 64

struct selinuxfs_open {
    int entry;
    char response[128];
    size_t response_len;
    // For entries under `class`, taken from the looked-up path: readdir and
    // getpath have no other way to know which class this is.
    char class_name[SELINUXFS_NAME_MAX];
    char perm_name[SELINUXFS_NAME_MAX];
};

static const struct fd_ops selinuxfs_fdops;

static int selinuxfs_entry_of(struct fd *fd) {
    struct selinuxfs_open *open_state = fd->data;
    return open_state != NULL ? open_state->entry : SELINUXFS_ROOT;
}

// The classes and permissions Android's userspace object managers check,
// with their real AOSP values so anything that reads them sees what a device
// would. Anything NOT listed here still resolves -- see selinuxfs_class_index.
struct selinuxfs_class {
    const char *name;
    unsigned index;
    const char *perms[8]; // NULL-terminated; bit value is 1 << position
};

static const struct selinuxfs_class selinuxfs_classes[] = {
    {"binder", 1, {"impersonate", "call", "set_context_mgr", "transfer", NULL}},
    {"service_manager", 2, {"add", "find", "list", NULL}},
    {"hwservice_manager", 3, {"add", "find", "list", NULL}},
    {"property_service", 4, {"set", NULL}},
};
#define SELINUXFS_CLASSES_LEN (sizeof(selinuxfs_classes) / sizeof(selinuxfs_classes[0]))

static const struct selinuxfs_class *selinuxfs_known_class(const char *name) {
    for (size_t i = 0; i < SELINUXFS_CLASSES_LEN; i++)
        if (strcmp(selinuxfs_classes[i].name, name) == 0)
            return &selinuxfs_classes[i];
    return NULL;
}

// A stable nonzero value for a name we do not have a table entry for. FNV-1a,
// folded into the low 15 bits so it fits security_class_t and can never be 0.
static unsigned selinuxfs_name_hash(const char *name) {
    uint32_t h = 2166136261u;
    for (const char *p = name; *p != '\0'; p++) {
        h ^= (unsigned char) *p;
        h *= 16777619u;
    }
    return (h & 0x7fff) | 0x4000; // nonzero, and out of the way of the table
}

// Every class name resolves, known or not, and this is deliberate.
//
// libselinux turns a class name into a number by reading class/<name>/index,
// and when that read fails it returns 0 and sets EINVAL. Callers do not treat
// that as "unknown class, carry on" -- servicemanager's actionAllowed() maps a
// failed selinux_check_access() straight to DENIED. So on a stub that permits
// everything, refusing to resolve a name converts "allowed" into "denied",
// which is the opposite of what this filesystem is for. It also means every
// class a future Android adds would break in the same silent way.
static unsigned selinuxfs_class_index(const char *name) {
    const struct selinuxfs_class *known = selinuxfs_known_class(name);
    return known != NULL ? known->index : selinuxfs_name_hash(name);
}

// Same reasoning for permission bits. Two unknown permissions of the same class
// can land on the same bit; that is harmless here because the access vector
// grants all 32 bits regardless, and nothing audits.
static unsigned selinuxfs_perm_value(const char *class_name, const char *perm) {
    const struct selinuxfs_class *known = selinuxfs_known_class(class_name);
    if (known != NULL) {
        for (int i = 0; known->perms[i] != NULL; i++)
            if (strcmp(known->perms[i], perm) == 0)
                return 1u << i;
    }
    return 1u << (selinuxfs_name_hash(perm) % 32);
}

// Copies one path component into buf. Returns false if it is empty or too long.
static bool selinuxfs_component(const char *start, size_t len, char *buf) {
    if (len == 0 || len >= SELINUXFS_NAME_MAX)
        return false;
    memcpy(buf, start, len);
    buf[len] = '\0';
    return true;
}

// Fills in class_name/perm_name when the path names something under `class`.
// Both may be NULL if the caller only wants the entry id.
static int selinuxfs_lookup_full(const char *path, char *class_name, char *perm_name) {
    if (class_name != NULL)
        class_name[0] = '\0';
    if (perm_name != NULL)
        perm_name[0] = '\0';

    if (path[0] == '\0')
        return SELINUXFS_ROOT;
    if (path[0] != '/')
        return _ENOENT;
    const char *p = path + 1;
    if (*p == '\0')
        return SELINUXFS_ROOT;

    static const char prefix[] = "class";
    size_t prefix_len = sizeof(prefix) - 1;
    if (strncmp(p, prefix, prefix_len) == 0 && (p[prefix_len] == '\0' || p[prefix_len] == '/')) {
        if (p[prefix_len] == '\0')
            return SELINUXFS_CLASS;
        const char *name = p + prefix_len + 1;
        const char *slash = strchr(name, '/');
        size_t name_len = slash != NULL ? (size_t) (slash - name) : strlen(name);
        char local[SELINUXFS_NAME_MAX];
        if (!selinuxfs_component(name, name_len, local))
            return _ENOENT;
        if (class_name != NULL)
            strcpy(class_name, local);
        if (slash == NULL)
            return SELINUXFS_CLASS_SUBDIR;

        const char *rest = slash + 1;
        if (strcmp(rest, "index") == 0)
            return SELINUXFS_CLASS_INDEX;
        if (strcmp(rest, "perms") == 0)
            return SELINUXFS_CLASS_PERMS_DIR;
        static const char perms[] = "perms/";
        if (strncmp(rest, perms, sizeof(perms) - 1) == 0) {
            const char *perm = rest + sizeof(perms) - 1;
            if (strchr(perm, '/') != NULL)
                return _ENOENT;
            char plocal[SELINUXFS_NAME_MAX];
            if (!selinuxfs_component(perm, strlen(perm), plocal))
                return _ENOENT;
            if (perm_name != NULL)
                strcpy(perm_name, plocal);
            return SELINUXFS_CLASS_PERM;
        }
        return _ENOENT;
    }

    if (strchr(p, '/') != NULL)
        return _ENOENT;
    for (int i = 1; i < SELINUXFS_COUNT; i++) {
        if (strcmp(p, selinuxfs_names[i]) == 0)
            return i;
    }
    return _ENOENT;
}

static int selinuxfs_lookup(const char *path) {
    return selinuxfs_lookup_full(path, NULL, NULL);
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
    if (entry == SELINUXFS_CLASS || entry == SELINUXFS_CLASS_SUBDIR ||
            entry == SELINUXFS_CLASS_PERMS_DIR) {
        stat->mode = S_IFDIR | 0555;
        stat->nlink = 2;
        return;
    }
    if (entry == SELINUXFS_CLASS_INDEX || entry == SELINUXFS_CLASS_PERM) {
        // Size is left at 0: the value is computed per open, and libselinux
        // reads these rather than sizing them.
        stat->mode = S_IFREG | 0444;
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
    char class_name[SELINUXFS_NAME_MAX], perm_name[SELINUXFS_NAME_MAX];
    int entry = selinuxfs_lookup_full(path, class_name, perm_name);
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
    strcpy(open_state->class_name, class_name);
    strcpy(open_state->perm_name, perm_name);
    // The class files have no fixed contents, so their value is rendered once
    // here and served from the same buffer the access verdict uses.
    if (entry == SELINUXFS_CLASS_INDEX) {
        open_state->response_len = (size_t) snprintf(
            open_state->response, sizeof(open_state->response), "%u",
            selinuxfs_class_index(class_name));
    } else if (entry == SELINUXFS_CLASS_PERM) {
        open_state->response_len = (size_t) snprintf(
            open_state->response, sizeof(open_state->response), "%u",
            selinuxfs_perm_value(class_name, perm_name));
    }
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
        case SELINUXFS_CLASS_INDEX:
        case SELINUXFS_CLASS_PERM:
            // Rendered at open time from the path.
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
    struct selinuxfs_open *open_state = fd->data;
    int which = selinuxfs_entry_of(fd);
    long index = (long) fd->offset;

    switch (which) {
        case SELINUXFS_ROOT: {
            index += 1; // entry 0 is the root itself
            if (index >= SELINUXFS_COUNT)
                return 0;
            fd->offset = (unsigned long) index;
            strcpy(entry->name, selinuxfs_names[index]);
            entry->inode = (unsigned) index + 1;
            entry->type = index == SELINUXFS_CLASS ? DT_DIR : DT_REG;
            return 1;
        }

        case SELINUXFS_CLASS: {
            // Only the classes we have a table entry for are listed. Any name
            // still resolves on lookup, but a directory listing has to be
            // finite, and these are the ones worth showing.
            if (index >= (long) SELINUXFS_CLASSES_LEN)
                return 0;
            fd->offset = (unsigned long) index + 1;
            strcpy(entry->name, selinuxfs_classes[index].name);
            entry->inode = selinuxfs_classes[index].index + 1000;
            entry->type = DT_DIR;
            return 1;
        }

        case SELINUXFS_CLASS_SUBDIR: {
            static const char *const children[] = {"index", "perms"};
            if (index >= 2)
                return 0;
            fd->offset = (unsigned long) index + 1;
            strcpy(entry->name, children[index]);
            entry->inode = 2000 + (unsigned) index;
            entry->type = index == 0 ? DT_REG : DT_DIR;
            return 1;
        }

        case SELINUXFS_CLASS_PERMS_DIR: {
            if (open_state == NULL)
                return 0;
            const struct selinuxfs_class *known =
                selinuxfs_known_class(open_state->class_name);
            // An unknown class has no enumerable permissions -- every name
            // resolves, so there is no list to give. Empty is the honest
            // answer, and nothing scans this directory.
            if (known == NULL || known->perms[index] == NULL)
                return 0;
            fd->offset = (unsigned long) index + 1;
            strcpy(entry->name, known->perms[index]);
            entry->inode = 3000 + (unsigned) index;
            entry->type = DT_REG;
            return 1;
        }

        default:
            return _ENOTDIR;
    }
}

static int selinuxfs_getpath(struct fd *fd, char *buf) {
    struct selinuxfs_open *open_state = fd->data;
    int entry = selinuxfs_entry_of(fd);
    switch (entry) {
        case SELINUXFS_ROOT:
            strcpy(buf, "");
            return 0;
        case SELINUXFS_CLASS_SUBDIR:
            snprintf(buf, MAX_PATH, "/class/%s", open_state->class_name);
            return 0;
        case SELINUXFS_CLASS_INDEX:
            snprintf(buf, MAX_PATH, "/class/%s/index", open_state->class_name);
            return 0;
        case SELINUXFS_CLASS_PERMS_DIR:
            snprintf(buf, MAX_PATH, "/class/%s/perms", open_state->class_name);
            return 0;
        case SELINUXFS_CLASS_PERM:
            snprintf(buf, MAX_PATH, "/class/%s/perms/%s", open_state->class_name,
                     open_state->perm_name);
            return 0;
        default:
            snprintf(buf, MAX_PATH, "/%s", selinuxfs_names[entry]);
            return 0;
    }
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
