// binderfs -- the filesystem Android mounts at /dev/binderfs to create binder
// devices at runtime.
//
// It is a tiny, entirely synthetic filesystem. The root directory contains one
// control node, `binder-control`, plus one character device per registered
// binder device. Writing a name into the control node with BINDER_CTL_ADD
// allocates a fresh minor (and with it a fresh binder context, meaning its own
// name registry and its own context manager) and makes a new device node
// appear in the directory.
//
// The device nodes themselves are ordinary character devices on BINDER_MAJOR,
// so opening one lands in fs/generic.c's S_ISCHR path -> dev_open -> the
// binder driver in kernel/binder.c. This file only has to describe the
// directory and report the right st_rdev.

#include <string.h>
#include <stdlib.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "kernel/binder.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "fs/devices.h"
#include "fs/poll.h"

#define BINDERFS_SUPER_MAGIC 0x6c6f6f70

#define BINDERFS_ROOT_INO 1
#define BINDERFS_CONTROL_INO 2
#define BINDERFS_DEVICE_INO(minor) ((minor) + 3)

// fd->fs_data holds which entry an open fd refers to. Entry ids are all
// non-negative so that a lookup can return a negative errno without ambiguity
// -- iSH's _ENOENT is -2, so a -1/-2 sentinel pair would be indistinguishable
// from "not found" (and was: stat("binder-control") reported ENOENT).
// 0..BINDER_MAX_MINORS-1 are device minors.
#define BINDERFS_ENTRY_ROOT (BINDER_MAX_MINORS)
#define BINDERFS_ENTRY_CONTROL (BINDER_MAX_MINORS + 1)

static const struct fd_ops binderfs_fdops;

static int binderfs_entry_of(struct fd *fd) {
    return (int) (intptr_t) fd->fs_data;
}

// Resolves a binderfs-relative path to an entry id, or _ENOENT.
static int binderfs_lookup(const char *path) {
    if (path[0] == '\0')
        return BINDERFS_ENTRY_ROOT;
    if (path[0] != '/' || path[1] == '\0' || strchr(path + 1, '/') != NULL)
        return _ENOENT;

    const char *name = path + 1;
    if (strcmp(name, "binder-control") == 0)
        return BINDERFS_ENTRY_CONTROL;

    for (int minor = 0; minor < BINDER_MAX_MINORS; minor++) {
        const char *dev_name = binder_minor_device_name(minor);
        if (dev_name != NULL && strcmp(dev_name, name) == 0)
            return minor;
    }
    return _ENOENT;
}

static bool binderfs_name_exists(const char *name) {
    if (strcmp(name, "binder-control") == 0)
        return true;
    for (int minor = 0; minor < BINDER_MAX_MINORS; minor++) {
        const char *dev_name = binder_minor_device_name(minor);
        if (dev_name != NULL && strcmp(dev_name, name) == 0)
            return true;
    }
    return false;
}

static void binderfs_stat_entry(int entry, struct statbuf *stat) {
    *stat = (struct statbuf) {};
    stat->nlink = 1;
    if (entry == BINDERFS_ENTRY_ROOT) {
        stat->mode = S_IFDIR | 0755;
        stat->inode = BINDERFS_ROOT_INO;
        stat->nlink = 2;
        return;
    }
    stat->mode = S_IFCHR | 0600;
    if (entry == BINDERFS_ENTRY_CONTROL) {
        stat->inode = BINDERFS_CONTROL_INO;
        stat->rdev = dev_make(BINDER_MAJOR, DEV_BINDER_CONTROL_MINOR);
    } else {
        stat->inode = BINDERFS_DEVICE_INO(entry);
        stat->rdev = dev_make(BINDER_MAJOR, entry);
        // Devices created through binderfs are world-usable; the standard
        // contexts keep Linux's 0666 on their /dev nodes.
        stat->mode = S_IFCHR | 0666;
    }
}

static struct fd *binderfs_open(struct mount *UNUSED(mount), const char *path, int UNUSED(flags),
                                int UNUSED(mode)) {
    int entry = binderfs_lookup(path);
    if (entry < 0)
        return ERR_PTR(entry);
    struct fd *fd = fd_create(&binderfs_fdops);
    if (fd == NULL)
        return ERR_PTR(_ENOMEM);
    fd->fs_data = (void *) (intptr_t) entry;
    return fd;
}

static int binderfs_getpath(struct fd *fd, char *buf) {
    int entry = binderfs_entry_of(fd);
    if (entry == BINDERFS_ENTRY_ROOT)
        strcpy(buf, "");
    else if (entry == BINDERFS_ENTRY_CONTROL)
        strcpy(buf, "/binder-control");
    else {
        const char *name = binder_minor_device_name(entry);
        snprintf(buf, MAX_PATH, "/%s", name != NULL ? name : "unknown");
    }
    return 0;
}

static int binderfs_stat(struct mount *UNUSED(mount), const char *path, struct statbuf *stat) {
    int entry = binderfs_lookup(path);
    if (entry < 0)
        return entry;
    binderfs_stat_entry(entry, stat);
    return 0;
}

static int binderfs_fstat(struct fd *fd, struct statbuf *stat) {
    binderfs_stat_entry(binderfs_entry_of(fd), stat);
    return 0;
}

static int binderfs_statfs(struct mount *UNUSED(mount), struct statfsbuf *stat) {
    stat->type = BINDERFS_SUPER_MAGIC;
    stat->namelen = BINDERFS_MAX_NAME;
    stat->bsize = PAGE_SIZE;
    return 0;
}

// binderfs is generated, not stored: attributes can be read but not set, and
// nothing can be created except through BINDER_CTL_ADD.
static int binderfs_setattr(struct mount *UNUSED(mount), const char *path, struct attr UNUSED(attr)) {
    int entry = binderfs_lookup(path);
    if (entry < 0)
        return entry;
    return _EPERM;
}

static int binderfs_fsetattr(struct fd *UNUSED(fd), struct attr UNUSED(attr)) {
    return _EPERM;
}

static int binderfs_readdir(struct fd *fd, struct dir_entry *entry) {
    if (binderfs_entry_of(fd) != BINDERFS_ENTRY_ROOT)
        return _ENOTDIR;

    // offset 0 is binder-control; 1..BINDER_MAX_MINORS are the device slots,
    // skipping the ones with nothing registered.
    unsigned long pos = fd->offset;
    if (pos == 0) {
        fd->offset = 1;
        strcpy(entry->name, "binder-control");
        entry->inode = BINDERFS_CONTROL_INO;
        entry->type = DT_CHR;
        return 1;
    }

    int minor = (int) pos - 1;
    while (minor < BINDER_MAX_MINORS && binder_minor_device_name(minor) == NULL)
        minor++;
    if (minor >= BINDER_MAX_MINORS)
        return 0;

    fd->offset = (unsigned long) minor + 2;
    snprintf(entry->name, sizeof(entry->name), "%s", binder_minor_device_name(minor));
    entry->inode = BINDERFS_DEVICE_INO(minor);
    entry->type = DT_CHR;
    return 1;
}

const struct fs_ops binderfs = {
    .name = "binder", .magic = BINDERFS_SUPER_MAGIC,
    .open = binderfs_open,
    .getpath = binderfs_getpath,
    .stat = binderfs_stat,
    .fstat = binderfs_fstat,
    .statfs = binderfs_statfs,
    .setattr = binderfs_setattr,
    .fsetattr = binderfs_fsetattr,
};

static const struct fd_ops binderfs_fdops = {
    .readdir = binderfs_readdir,
};

// ---------------------------------------------------------------------------
// The control device
// ---------------------------------------------------------------------------
//
// Reached by opening binder-control, which is a character device on
// (BINDER_MAJOR, DEV_BINDER_CONTROL_MINOR); kernel/binder.c's open routes that
// minor here rather than creating a binder_proc for it.

static ssize_t binderfs_control_ioctl_size(int cmd) {
    if (cmd == BINDER_CTL_ADD_)
        return sizeof(struct binderfs_device);
    return -1;
}

static int binderfs_control_ioctl(struct fd *UNUSED(fd), int cmd, void *arg) {
    if (cmd != BINDER_CTL_ADD_)
        return _EINVAL;
    struct binderfs_device *device = arg;

    // The name must be NUL-terminated within the field and non-empty, and
    // can't collide with the control node or an existing device.
    device->name[BINDERFS_MAX_NAME] = '\0';
    size_t len = strnlen(device->name, BINDERFS_MAX_NAME + 1);
    if (len == 0 || len > BINDERFS_MAX_NAME)
        return _EINVAL;
    if (strchr(device->name, '/') != NULL)
        return _EINVAL;
    if (binderfs_name_exists(device->name))
        return _EEXIST;

    int minor = binder_alloc_minor(device->name);
    if (minor < 0)
        return minor;

    device->major = BINDER_MAJOR;
    device->minor = (uint32_t) minor;
    return 0;
}

const struct fd_ops binderfs_control_ops = {
    .ioctl_size = binderfs_control_ioctl_size,
    .ioctl = binderfs_control_ioctl,
};
