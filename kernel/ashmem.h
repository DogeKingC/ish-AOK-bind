#ifndef KERNEL_ASHMEM_H
#define KERNEL_ASHMEM_H

#include "misc.h"
#include "kernel/ioctl_abi.h"

// Android anonymous shared memory (/dev/ashmem).
//
// The oldest and most widely used of Android's IPC primitives: open the
// device, name it, give it a size, mmap it, and pass the fd to another process
// (over binder or SCM_RIGHTS). Both sides then mmap the same memory. Almost
// every Android process uses it -- graphics buffers, parcelled data too large
// for a binder transaction, the property area, ART's zygote heap accounting.
//
// The ABI is transcribed from Linux's drivers/staging/android/uapi/ashmem.h.
// Two of its ioctl numbers are built from `size_t` and `unsigned long`, which
// are 4 bytes on our i386 guest and 8 on x86_64, so those commands arrive with
// two different encodings; both are accepted (Linux does the same through its
// compat_ioctl path, which is where COMPAT_ASHMEM_SET_SIZE comes from).

#define ASHMEM_NAME_LEN 256
#define ASHMEM_NAME_DEF "dev/ashmem"

// Return values for ASHMEM_PIN
#define ASHMEM_NOT_PURGED 0
#define ASHMEM_WAS_PURGED 1
// Return values for ASHMEM_GET_PIN_STATUS
#define ASHMEM_IS_UNPINNED 0
#define ASHMEM_IS_PINNED 1

struct ashmem_pin {
    uint32_t offset; // offset into the region, in bytes
    uint32_t len;    // length of the region, in bytes; 0 means "to the end"
};

#define __ASHMEMIOC 0x77

#define ASHMEM_SET_NAME_       ISH_IOW_SIZE(__ASHMEMIOC, 1, ASHMEM_NAME_LEN)
#define ASHMEM_GET_NAME_       ISH_IOR_SIZE(__ASHMEMIOC, 2, ASHMEM_NAME_LEN)
// size_t: 8 on a 64-bit guest, 4 on a 32-bit one. Both are real.
#define ASHMEM_SET_SIZE_       ISH_IOW_SIZE(__ASHMEMIOC, 3, 8)
#define ASHMEM_SET_SIZE_32_    ISH_IOW_SIZE(__ASHMEMIOC, 3, 4)
#define ASHMEM_GET_SIZE_       ISH_IO(__ASHMEMIOC, 4)
// unsigned long: likewise.
#define ASHMEM_SET_PROT_MASK_    ISH_IOW_SIZE(__ASHMEMIOC, 5, 8)
#define ASHMEM_SET_PROT_MASK_32_ ISH_IOW_SIZE(__ASHMEMIOC, 5, 4)
#define ASHMEM_GET_PROT_MASK_  ISH_IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN_            ISH_IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN_          ISH_IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS_ ISH_IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES_ ISH_IO(__ASHMEMIOC, 10)

struct dev_ops;

// The character device behind /dev/ashmem.
extern struct dev_ops ashmem_dev;

// Creates /dev/ashmem if it is missing or points at the wrong device. Needs a
// mounted root and a current task, so it is called from the boot paths.
void ashmem_create_device_node(void);

#endif
