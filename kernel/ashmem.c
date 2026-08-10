// Android anonymous shared memory (/dev/ashmem).
//
// The usage pattern userspace expects:
//
//     fd = open("/dev/ashmem", O_RDWR);
//     ioctl(fd, ASHMEM_SET_NAME, "my region");
//     ioctl(fd, ASHMEM_SET_SIZE, size);
//     p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
//     // ... then hand `fd` to another process over binder or SCM_RIGHTS,
//     // which mmaps it and sees the same memory.
//
// Backed by an unlinked host temp file, the same machinery memfd uses
// (kernel/memfd.c): guest mappings are host mmaps of that file, so the host
// kernel provides the sharing, coherence and MAP_PRIVATE copy-on-write for
// free. The cross-process part falls out of how iSH passes descriptors -- both
// processes end up holding the same struct fd, hence the same ashmem_state and
// the same host file, so their mappings are genuinely the same pages.
//
// On pinning: ASHMEM_UNPIN marks a range as discardable, letting the kernel
// reclaim it under memory pressure; ASHMEM_PIN returns whether that happened.
// We never reclaim, so pinning is bookkeeping: ranges are tracked so
// GET_PIN_STATUS answers correctly, and PIN always reports ASHMEM_NOT_PURGED.
// That is a legitimate implementation -- Linux only purges under pressure, and
// callers must cope with never being purged.

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "kernel/ashmem.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "fs/devices.h"
#include "fs/path.h"
#include "fs/poll.h"
#include "fs/real.h"
#include "util/list.h"
#include "util/sync.h"

// An unpinned (discardable) range. Kept sorted by offset and non-overlapping.
struct ashmem_range {
    struct list link;
    size_t start;
    size_t end; // exclusive
};

struct ashmem_state {
    char name[ASHMEM_NAME_LEN];
    int host_fd;         // -1 until the size is committed
    size_t size;
    unsigned long prot_mask;
    bool size_set;
    bool mapped;         // set on first mmap; freezes name and size
    struct list unpinned;
    lock_t lock;
};

static struct ashmem_state *ashmem_get(struct fd *fd) {
    return fd->data;
}

// Creates the backing file. Deferred until it is actually needed, because
// userspace always sets the size first and a region may never be mapped.
static int ashmem_ensure_backing(struct ashmem_state *state) {
    if (state->host_fd >= 0)
        return 0;
    if (!state->size_set)
        return _EINVAL; // Linux: mmap before ASHMEM_SET_SIZE is EINVAL
    int host_fd = host_unlinked_tmpfd();
    if (host_fd < 0)
        return host_fd;
    if (ftruncate(host_fd, state->size) < 0) {
        int err = errno_map();
        close(host_fd);
        return err;
    }
    state->host_fd = host_fd;
    return 0;
}

// ---------------------------------------------------------------------------
// Pin bookkeeping
// ---------------------------------------------------------------------------

// Resolves a struct ashmem_pin against the region. len == 0 means "to the
// end". Linux requires both offset and len to be page-aligned.
static int ashmem_pin_range(struct ashmem_state *state, struct ashmem_pin *pin,
                            size_t *start_out, size_t *end_out) {
    if (pin->offset % PAGE_SIZE != 0 || pin->len % PAGE_SIZE != 0)
        return _EINVAL;
    size_t start = pin->offset;
    size_t len = pin->len != 0 ? pin->len : (state->size > start ? state->size - start : 0);
    if (start > state->size || len > state->size - start)
        return _EINVAL;
    *start_out = start;
    *end_out = start + len;
    return 0;
}

// Marks [start, end) unpinned, merging with any adjacent or overlapping range.
static int ashmem_mark_unpinned(struct ashmem_state *state, size_t start, size_t end) {
    struct ashmem_range *range, *tmp;
    list_for_each_entry_safe(&state->unpinned, range, tmp, link) {
        if (range->end < start || range->start > end)
            continue; // disjoint, and not adjacent
        if (range->start < start)
            start = range->start;
        if (range->end > end)
            end = range->end;
        list_remove(&range->link);
        free(range);
    }
    struct ashmem_range *merged = malloc(sizeof(*merged));
    if (merged == NULL)
        return _ENOMEM;
    merged->start = start;
    merged->end = end;
    list_add_tail(&state->unpinned, &merged->link);
    return 0;
}

// Clears [start, end) from the unpinned set, splitting ranges that straddle it.
static int ashmem_mark_pinned(struct ashmem_state *state, size_t start, size_t end) {
    struct ashmem_range *range, *tmp;
    list_for_each_entry_safe(&state->unpinned, range, tmp, link) {
        if (range->end <= start || range->start >= end)
            continue; // disjoint
        if (range->start < start && range->end > end) {
            // The pinned span is strictly inside: keep both sides.
            struct ashmem_range *tail = malloc(sizeof(*tail));
            if (tail == NULL)
                return _ENOMEM;
            tail->start = end;
            tail->end = range->end;
            range->end = start;
            list_add_tail(&state->unpinned, &tail->link);
        } else if (range->start < start) {
            range->end = start;
        } else if (range->end > end) {
            range->start = end;
        } else {
            list_remove(&range->link);
            free(range);
        }
    }
    return 0;
}

// ASHMEM_IS_UNPINNED only if every page of the range is unpinned.
static int ashmem_query_pin_status(struct ashmem_state *state, size_t start, size_t end) {
    if (start == end)
        return ASHMEM_IS_PINNED;
    size_t covered = start;
    bool progress = true;
    while (covered < end && progress) {
        progress = false;
        struct ashmem_range *range;
        list_for_each_entry(&state->unpinned, range, link) {
            if (range->start <= covered && range->end > covered) {
                covered = range->end;
                progress = true;
                break;
            }
        }
    }
    return covered >= end ? ASHMEM_IS_UNPINNED : ASHMEM_IS_PINNED;
}

// ---------------------------------------------------------------------------
// fd operations
// ---------------------------------------------------------------------------

static int ashmem_open(int UNUSED(major), int minor, struct fd *fd) {
    // fs/dev.c dispatches MISC_MAJOR by minor; this is a belt-and-braces
    // check that we were handed our own.
    if (minor != DEV_ASHMEM_MINOR)
        return _ENXIO;
    struct ashmem_state *state = malloc(sizeof(*state));
    if (state == NULL)
        return _ENOMEM;
    *state = (struct ashmem_state) {
        .host_fd = -1,
        // Linux starts fully permissive and lets SET_PROT_MASK only take bits
        // away.
        .prot_mask = P_READ | P_WRITE | P_EXEC,
    };
    strcpy(state->name, ASHMEM_NAME_DEF);
    list_init(&state->unpinned);
    // lock_init takes a char[16]; a shorter string literal reads past its end.
    char lock_name[16] = "ashmem";
    lock_init(&state->lock, lock_name);
    fd->data = state;
    return 0;
}

static int ashmem_close(struct fd *fd) {
    struct ashmem_state *state = ashmem_get(fd);
    if (state == NULL)
        return 0;
    struct ashmem_range *range, *tmp;
    list_for_each_entry_safe(&state->unpinned, range, tmp, link) {
        list_remove(&range->link);
        free(range);
    }
    if (state->host_fd >= 0)
        close(state->host_fd);
    free(state);
    fd->data = NULL;
    return 0;
}

static int ashmem_mmap(struct fd *fd, struct mem *mem, page_t start, pages_t pages, off_t offset,
                       int prot, int flags) {
    struct ashmem_state *state = ashmem_get(fd);
    lock(&state->lock, 0);

    if (!state->size_set || state->size == 0) {
        unlock(&state->lock);
        return _EINVAL;
    }
    // A mapping may not ask for access the prot mask has taken away.
    if ((prot & ~(int) state->prot_mask) & (P_READ | P_WRITE | P_EXEC)) {
        unlock(&state->lock);
        return _EPERM;
    }
    int err = ashmem_ensure_backing(state);
    if (err < 0) {
        unlock(&state->lock);
        return err;
    }
    // Name and size are frozen once the region has been mapped.
    state->mapped = true;
    int host_fd = state->host_fd;
    unlock(&state->lock);

    return host_fd_mmap(host_fd, mem, start, pages, offset, prot, flags);
}

static ssize_t ashmem_read(struct fd *fd, void *buf, size_t bufsize) {
    struct ashmem_state *state = ashmem_get(fd);
    lock(&state->lock, 0);
    // Linux: reading before the size is set returns 0, not an error.
    if (!state->size_set) {
        unlock(&state->lock);
        return 0;
    }
    int err = ashmem_ensure_backing(state);
    if (err < 0) {
        unlock(&state->lock);
        return err;
    }
    if (fd->offset >= state->size) {
        unlock(&state->lock);
        return 0;
    }
    if (bufsize > state->size - fd->offset)
        bufsize = state->size - fd->offset;
    ssize_t n = pread(state->host_fd, buf, bufsize, (off_t) fd->offset);
    if (n < 0) {
        unlock(&state->lock);
        return errno_map();
    }
    fd->offset += n;
    unlock(&state->lock);
    return n;
}

static off_t_ ashmem_lseek(struct fd *fd, off_t_ off, int whence) {
    struct ashmem_state *state = ashmem_get(fd);
    lock(&state->lock, 0);
    if (!state->size_set) {
        unlock(&state->lock);
        return _EINVAL;
    }
    off_t_ base;
    switch (whence) {
        case LSEEK_SET: base = 0; break;
        case LSEEK_CUR: base = (off_t_) fd->offset; break;
        case LSEEK_END: base = (off_t_) state->size; break;
        default:
            unlock(&state->lock);
            return _EINVAL;
    }
    off_t_ result = base + off;
    if (result < 0) {
        unlock(&state->lock);
        return _EINVAL;
    }
    fd->offset = (unsigned long) result;
    unlock(&state->lock);
    return result;
}

static int ashmem_poll(struct fd *UNUSED(fd)) {
    return POLL_READ | POLL_WRITE;
}

static ssize_t ashmem_ioctl_size(int cmd) {
    switch (cmd) {
        case ASHMEM_SET_NAME_:
        case ASHMEM_GET_NAME_:
            return ASHMEM_NAME_LEN;
        case ASHMEM_PIN_:
        case ASHMEM_UNPIN_:
        case ASHMEM_GET_PIN_STATUS_:
            return sizeof(struct ashmem_pin);
        // These take their argument as a raw value, not a pointer -- ashmem's
        // ioctl numbers claim a payload type but the driver reads `arg`
        // directly. Both the 32- and 64-bit encodings mean the same thing.
        case ASHMEM_SET_SIZE_:
        case ASHMEM_SET_SIZE_32_:
        case ASHMEM_GET_SIZE_:
        case ASHMEM_SET_PROT_MASK_:
        case ASHMEM_SET_PROT_MASK_32_:
        case ASHMEM_GET_PROT_MASK_:
        case ASHMEM_PURGE_ALL_CACHES_:
            return 0;
        default:
            return -1;
    }
}

static int ashmem_ioctl(struct fd *fd, int cmd, void *arg) {
    struct ashmem_state *state = ashmem_get(fd);
    if (state == NULL)
        return _EINVAL;

    lock(&state->lock, 0);
    int ret;
    switch (cmd) {
        case ASHMEM_SET_NAME_: {
            if (state->mapped) {
                ret = _EINVAL;
                break;
            }
            // The guest buffer is ASHMEM_NAME_LEN bytes; it need not be
            // terminated, so terminate it ourselves.
            memcpy(state->name, arg, ASHMEM_NAME_LEN);
            state->name[ASHMEM_NAME_LEN - 1] = '\0';
            ret = 0;
            break;
        }

        case ASHMEM_GET_NAME_:
            memset(arg, 0, ASHMEM_NAME_LEN);
            strcpy(arg, state->name);
            ret = 0;
            break;

        case ASHMEM_SET_SIZE_:
        case ASHMEM_SET_SIZE_32_:
            if (state->mapped) {
                ret = _EINVAL;
                break;
            }
            state->size = (size_t) (unsigned long) arg;
            state->size_set = true;
            ret = 0;
            break;

        case ASHMEM_GET_SIZE_:
            ret = (int) state->size;
            break;

        case ASHMEM_SET_PROT_MASK_:
        case ASHMEM_SET_PROT_MASK_32_: {
            unsigned long requested = (unsigned long) arg;
            // Linux: the mask may only ever lose bits. Asking for one that has
            // already been dropped is EINVAL.
            if (requested & ~state->prot_mask) {
                ret = _EINVAL;
                break;
            }
            state->prot_mask = requested;
            ret = 0;
            break;
        }

        case ASHMEM_GET_PROT_MASK_:
            ret = (int) state->prot_mask;
            break;

        case ASHMEM_PIN_:
        case ASHMEM_UNPIN_:
        case ASHMEM_GET_PIN_STATUS_: {
            if (!state->size_set) {
                ret = _EINVAL;
                break;
            }
            size_t start, end;
            ret = ashmem_pin_range(state, arg, &start, &end);
            if (ret < 0)
                break;
            if (cmd == ASHMEM_PIN_) {
                ret = ashmem_mark_pinned(state, start, end);
                // Nothing is ever reclaimed here, so the caller's data is
                // always still there.
                if (ret == 0)
                    ret = ASHMEM_NOT_PURGED;
            } else if (cmd == ASHMEM_UNPIN_) {
                ret = ashmem_mark_unpinned(state, start, end);
            } else {
                ret = ashmem_query_pin_status(state, start, end);
            }
            break;
        }

        case ASHMEM_PURGE_ALL_CACHES_:
            // Returns how many pages were freed. We never purge, so none.
            ret = 0;
            break;

        default:
            ret = _EINVAL;
            break;
    }
    unlock(&state->lock);
    return ret;
}

struct dev_ops ashmem_dev = {
    .open = ashmem_open,
    .fd.read = ashmem_read,
    .fd.lseek = ashmem_lseek,
    .fd.mmap = ashmem_mmap,
    .fd.poll = ashmem_poll,
    .fd.ioctl_size = ashmem_ioctl_size,
    .fd.ioctl = ashmem_ioctl,
    .fd.close = ashmem_close,
};

void ashmem_create_device_node(void) {
    struct statbuf stat;
    dev_t_ dev = dev_make(MISC_MAJOR, DEV_ASHMEM_MINOR);
    int err = generic_statat(AT_PWD, "/dev/ashmem", &stat, AT_SYMLINK_NOFOLLOW_);
    if (err == _ENOENT) {
        generic_mknodat(AT_PWD, "/dev/ashmem", S_IFCHR | 0666, dev);
    } else if (err >= 0 && (!S_ISCHR(stat.mode) || stat.rdev != dev)) {
        generic_unlinkat(AT_PWD, "/dev/ashmem");
        generic_mknodat(AT_PWD, "/dev/ashmem", S_IFCHR | 0666, dev);
    }
}
