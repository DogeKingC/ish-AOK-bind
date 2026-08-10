// DMA-BUF heaps (/dev/dma_heap/*) and the dma-buf descriptors they allocate.
//
// The allocator that replaced ION in Android 12. Userspace does:
//
//     heap = open("/dev/dma_heap/system", O_RDONLY);
//     struct dma_heap_allocation_data data = { .len = n, .fd_flags = O_RDWR };
//     ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &data);
//     // data.fd is now a dma-buf: mmap it, or pass it to another process
//
// A dma-buf is a descriptor for a buffer, deliberately independent of whoever
// allocated it -- so the heap fd and the buffer fd have separate ioctl sets
// and separate ops. Both live in this file.
//
// Buffers are backed by unlinked host temp files, the same way ashmem and
// memfd are, which gives cross-process sharing for free: passing the
// descriptor hands the peer the same struct fd, hence the same host file, so
// both mappings are the same pages.
//
// What a real driver does that this cannot: DMA_BUF_IOCTL_SYNC exists to
// bracket CPU access with cache maintenance, so a device and the CPU see
// coherent data. There is no device here and the host kernel keeps our
// mappings coherent already, so sync validates its flags and returns. That is
// the honest behaviour for a CPU-only heap, not a stub -- Linux's own system
// heap does nothing else on a cache-coherent architecture.

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "kernel/dma_heap.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "fs/devices.h"
#include "fs/path.h"
#include "fs/poll.h"
#include "fs/real.h"
#include "util/sync.h"

// A guest asking for an absurd size would otherwise sit in ftruncate and then
// blow up at mmap time. Linux has no such cap, but Linux also has a real
// allocator behind it rather than a host file.
#define DMA_HEAP_MAX_ALLOC (1ULL << 30) // 1 GiB

struct dma_buf_state {
    int host_fd;
    size_t size;
    char name[DMA_BUF_NAME_LEN];
    lock_t lock;
};

static const struct fd_ops dma_buf_ops;

static struct dma_buf_state *dma_buf_get(struct fd *fd) {
    return fd->data;
}

// ---------------------------------------------------------------------------
// The dma-buf descriptor
// ---------------------------------------------------------------------------

static int dma_buf_mmap(struct fd *fd, struct mem *mem, page_t start, pages_t pages, off_t offset,
                        int prot, int flags) {
    struct dma_buf_state *state = dma_buf_get(fd);
    if (state == NULL)
        return _EINVAL;
    if (offset % PAGE_SIZE != 0)
        return _EINVAL;
    return host_fd_mmap(state->host_fd, mem, start, pages, offset, prot, flags);
}

// Linux: a dma-buf supports SEEK_END/SEEK_SET only, and SEEK_END is how
// userspace discovers the buffer's size without asking the heap.
static off_t_ dma_buf_lseek(struct fd *fd, off_t_ off, int whence) {
    struct dma_buf_state *state = dma_buf_get(fd);
    if (state == NULL)
        return _EINVAL;
    if (whence == LSEEK_END && off == 0)
        return (off_t_) state->size;
    if (whence == LSEEK_SET && off == 0) {
        fd->offset = 0;
        return 0;
    }
    return _EINVAL;
}

static int dma_buf_poll(struct fd *UNUSED(fd)) {
    // Real dma-bufs report fence completion through poll. Nothing here ever
    // has a pending fence, so the buffer is always ready.
    return POLL_READ | POLL_WRITE;
}

static ssize_t dma_buf_ioctl_size(int cmd) {
    switch (cmd) {
        case DMA_BUF_IOCTL_SYNC_:
            return sizeof(struct dma_buf_sync);
        case DMA_BUF_SET_NAME_A_:
        case DMA_BUF_SET_NAME_B_:
            return 0; // the argument is a pointer to a string, read directly
        default:
            return -1;
    }
}

static int dma_buf_ioctl(struct fd *fd, int cmd, void *arg) {
    struct dma_buf_state *state = dma_buf_get(fd);
    if (state == NULL)
        return _EINVAL;

    switch (cmd) {
        case DMA_BUF_IOCTL_SYNC_: {
            struct dma_buf_sync *sync = arg;
            if (sync->flags & ~(uint64_t) DMA_BUF_SYNC_VALID_FLAGS_MASK_)
                return _EINVAL;
            // Direction is mandatory: a sync that names neither read nor write
            // is meaningless, and Linux rejects it.
            if ((sync->flags & DMA_BUF_SYNC_RW_) == 0)
                return _EINVAL;
            // Nothing to do -- see the note at the top of this file.
            return 0;
        }

        case DMA_BUF_SET_NAME_A_:
        case DMA_BUF_SET_NAME_B_: {
            char name[DMA_BUF_NAME_LEN];
            if (user_read_string((guest_addr_t) (unsigned long) arg, name, sizeof(name)))
                return _EFAULT;
            lock(&state->lock, 0);
            memcpy(state->name, name, sizeof(name));
            state->name[DMA_BUF_NAME_LEN - 1] = '\0';
            unlock(&state->lock);
            return 0;
        }

        default:
            return _EINVAL;
    }
}

static int dma_buf_close(struct fd *fd) {
    struct dma_buf_state *state = dma_buf_get(fd);
    if (state == NULL)
        return 0;
    close(state->host_fd);
    free(state);
    fd->data = NULL;
    return 0;
}

static const struct fd_ops dma_buf_ops = {
    .mmap = dma_buf_mmap,
    .lseek = dma_buf_lseek,
    .poll = dma_buf_poll,
    .ioctl_size = dma_buf_ioctl_size,
    .ioctl = dma_buf_ioctl,
    .close = dma_buf_close,
    .anon_inode_class = "dmabuf",
};

// ---------------------------------------------------------------------------
// The heap device
// ---------------------------------------------------------------------------

// Allocates a buffer and installs a descriptor for it in the calling process.
// Returns the guest fd number, or a negative errno.
static int dma_heap_allocate(uint64_t len, uint32_t fd_flags) {
    if (len == 0 || len > DMA_HEAP_MAX_ALLOC)
        return _EINVAL;

    struct dma_buf_state *state = malloc(sizeof(*state));
    if (state == NULL)
        return _ENOMEM;
    *state = (struct dma_buf_state) { .host_fd = -1 };
    // Linux names a fresh dma-buf after the file it belongs to; userspace
    // renames it with DMA_BUF_SET_NAME.
    strcpy(state->name, "dmabuf");
    char lock_name[16] = "dma_buf";
    lock_init(&state->lock, lock_name);

    int host_fd = host_unlinked_tmpfd();
    if (host_fd < 0) {
        free(state);
        return host_fd;
    }
    // dma-buf sizes are page-multiples; the host file must cover the whole
    // rounded size or the tail page faults on access.
    size_t size = (size_t) BYTES_ROUND_UP(len);
    if (ftruncate(host_fd, size) < 0) {
        int err = errno_map();
        close(host_fd);
        free(state);
        return err;
    }
    state->host_fd = host_fd;
    state->size = size;

    struct fd *buf_fd = adhoc_fd_create(&dma_buf_ops);
    if (buf_fd == NULL) {
        close(host_fd);
        free(state);
        return _ENOMEM;
    }
    buf_fd->data = state;
    buf_fd->stat.mode = S_IFREG | 0600;
    buf_fd->stat.size = size;
    buf_fd->flags = fd_flags & (O_RDWR_ | O_WRONLY_);

    // f_install steals the reference, and destroys the fd on failure.
    fd_t installed = f_install(buf_fd, (int) fd_flags);
    if (installed < 0)
        return installed;
    return installed;
}

static ssize_t dma_heap_ioctl_size(int cmd) {
    if (cmd == DMA_HEAP_IOCTL_ALLOC_)
        return sizeof(struct dma_heap_allocation_data);
    return -1;
}

static int dma_heap_ioctl(struct fd *UNUSED(fd), int cmd, void *arg) {
    if (cmd != DMA_HEAP_IOCTL_ALLOC_)
        return _EINVAL;
    struct dma_heap_allocation_data *data = arg;

    if (data->fd_flags & ~(uint32_t) DMA_HEAP_VALID_FD_FLAGS_)
        return _EINVAL;
    if (data->heap_flags & ~DMA_HEAP_VALID_HEAP_FLAGS_)
        return _EINVAL;

    int installed = dma_heap_allocate(data->len, data->fd_flags);
    if (installed < 0)
        return installed;
    data->fd = (uint32_t) installed;
    return 0;
}

static int dma_heap_open(int UNUSED(major), int minor, struct fd *UNUSED(fd)) {
    // Every heap node behaves identically here: there is one pool of memory
    // and no cached/uncached distinction to make, so system and
    // system-uncached differ only in name. Android probes for both.
    if (minor != DEV_DMA_HEAP_SYSTEM_MINOR && minor != DEV_DMA_HEAP_UNCACHED_MINOR)
        return _ENXIO;
    return 0;
}

struct dev_ops dma_heap_dev = {
    .open = dma_heap_open,
    .fd.ioctl_size = dma_heap_ioctl_size,
    .fd.ioctl = dma_heap_ioctl,
};

void dma_heap_create_device_nodes(void) {
    static const struct {
        const char *path;
        int minor;
    } nodes[] = {
        { "/dev/dma_heap/system", DEV_DMA_HEAP_SYSTEM_MINOR },
        { "/dev/dma_heap/system-uncached", DEV_DMA_HEAP_UNCACHED_MINOR },
    };

    generic_mkdirat(AT_PWD, "/dev/dma_heap", 0755);
    for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        struct statbuf stat;
        dev_t_ dev = dev_make(MISC_MAJOR, nodes[i].minor);
        int err = generic_statat(AT_PWD, nodes[i].path, &stat, AT_SYMLINK_NOFOLLOW_);
        if (err == _ENOENT) {
            generic_mknodat(AT_PWD, nodes[i].path, S_IFCHR | 0666, dev);
        } else if (err >= 0 && (!S_ISCHR(stat.mode) || stat.rdev != dev)) {
            generic_unlinkat(AT_PWD, nodes[i].path);
            generic_mknodat(AT_PWD, nodes[i].path, S_IFCHR | 0666, dev);
        }
    }
}
