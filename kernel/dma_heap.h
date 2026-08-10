#ifndef KERNEL_DMA_HEAP_H
#define KERNEL_DMA_HEAP_H

#include "misc.h"
#include "kernel/ioctl_abi.h"

// DMA-BUF heaps (/dev/dma_heap/*) and the dma-buf descriptors they hand out.
//
// This is the allocator that replaced ION in Android 12. Userspace opens a
// heap, asks it for `len` bytes, and gets back a *new* file descriptor -- a
// dma-buf -- which can be mmapped and passed to another process. Graphics and
// media stacks use it for every buffer they share: gralloc, Codec2, camera.
//
// Two ABIs meet here, because a dma-buf is not tied to the heap that made it:
//
//   struct dma_heap_allocation_data + DMA_HEAP_IOCTL_ALLOC   on the heap fd
//   DMA_BUF_IOCTL_SYNC, DMA_BUF_SET_NAME                     on the dma-buf fd
//
// Transcribed from Linux's include/uapi/linux/dma-heap.h and
// include/uapi/linux/dma-buf.h.

// ---------------------------------------------------------------------------
// The heap device
// ---------------------------------------------------------------------------

// Flags for dma_heap_allocation_data.fd_flags -- the open(2) flags the
// returned descriptor is created with.
#define DMA_HEAP_VALID_FD_FLAGS_ (O_CLOEXEC_ | O_RDWR_ | O_RDONLY_ | O_WRONLY_)
// No heap_flags are defined yet; a nonzero value must be rejected so that
// future ones cannot be silently ignored.
#define DMA_HEAP_VALID_HEAP_FLAGS_ 0ULL

struct dma_heap_allocation_data {
    uint64_t len;        // size to allocate, in bytes
    uint32_t fd;         // out: the new dma-buf descriptor
    uint32_t fd_flags;   // flags to create it with
    uint64_t heap_flags; // heap-specific flags; none defined
};

#define DMA_HEAP_IOC_MAGIC 'H'
#define DMA_HEAP_IOCTL_ALLOC_ ISH_IOWR(DMA_HEAP_IOC_MAGIC, 0x0, struct dma_heap_allocation_data)

// ---------------------------------------------------------------------------
// The dma-buf descriptor
// ---------------------------------------------------------------------------

// CPU access bracketing. On a real system this is where cache maintenance
// happens before and after the CPU touches a buffer the device also sees.
#define DMA_BUF_SYNC_READ_ (1 << 0)
#define DMA_BUF_SYNC_WRITE_ (2 << 0)
#define DMA_BUF_SYNC_RW_ (DMA_BUF_SYNC_READ_ | DMA_BUF_SYNC_WRITE_)
#define DMA_BUF_SYNC_START_ (0 << 2)
#define DMA_BUF_SYNC_END_ (1 << 2)
#define DMA_BUF_SYNC_VALID_FLAGS_MASK_ (DMA_BUF_SYNC_RW_ | DMA_BUF_SYNC_END_)

#define DMA_BUF_NAME_LEN 32

struct dma_buf_sync {
    uint64_t flags;
};

#define DMA_BUF_BASE 'b'
#define DMA_BUF_IOCTL_SYNC_ ISH_IOW(DMA_BUF_BASE, 0, struct dma_buf_sync)
// The argument is a pointer to a NUL-terminated name. Linux encodes the
// pointer's own width into the number, so 32- and 64-bit userspace produce
// different values for the same call; both are accepted.
#define DMA_BUF_SET_NAME_A_ ISH_IOW_SIZE(DMA_BUF_BASE, 1, 4)
#define DMA_BUF_SET_NAME_B_ ISH_IOW_SIZE(DMA_BUF_BASE, 1, 8)

struct dev_ops;

// The character device behind every /dev/dma_heap/* node.
extern struct dev_ops dma_heap_dev;

// Creates /dev/dma_heap/ and the heap nodes inside it. Needs a mounted root
// and a current task, so it is called from the boot paths.
void dma_heap_create_device_nodes(void);

#endif
