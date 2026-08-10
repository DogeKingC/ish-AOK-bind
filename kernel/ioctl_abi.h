#ifndef KERNEL_IOCTL_ABI_H
#define KERNEL_IOCTL_ABI_H

#include <stdint.h>

// Linux's _IOC ioctl-number encoding, for drivers whose guest-visible ioctl
// numbers are built from struct sizes rather than being arbitrary constants
// (the Android drivers: binder, ashmem, dma-heap). The guest computes these
// from its own headers, so we have to reproduce the encoding exactly rather
// than pick our own values.

#define ISH_IOC_NRBITS 8
#define ISH_IOC_TYPEBITS 8
#define ISH_IOC_SIZEBITS 14
#define ISH_IOC_NRSHIFT 0
#define ISH_IOC_TYPESHIFT (ISH_IOC_NRSHIFT + ISH_IOC_NRBITS)
#define ISH_IOC_SIZESHIFT (ISH_IOC_TYPESHIFT + ISH_IOC_TYPEBITS)
#define ISH_IOC_DIRSHIFT (ISH_IOC_SIZESHIFT + ISH_IOC_SIZEBITS)
#define ISH_IOC_NONE 0U
#define ISH_IOC_WRITE 1U
#define ISH_IOC_READ 2U

// The result is deliberately a 32-bit *signed* int. The guest passes the
// command to ioctl(2) as a 32-bit value and struct fd_ops takes it as an int,
// so codes with the read bit set (0x80000000) arrive negative. Without the
// narrowing cast the sizeof() in ISH_IOR/ISH_IOW below would widen the whole
// expression to size_t, and a negative `cmd` promoted to 64 bits would never
// compare equal to the positive 64-bit constant -- every read-direction ioctl
// would silently fall through to ENOTTY. That was a real bug here once; do not
// remove the cast.
#define ISH_IOC(dir, type, nr, size) \
    ((int) (uint32_t) (((uint32_t) (dir) << ISH_IOC_DIRSHIFT) | \
                       ((uint32_t) (type) << ISH_IOC_TYPESHIFT) | \
                       ((uint32_t) (nr) << ISH_IOC_NRSHIFT) | \
                       ((uint32_t) (size) << ISH_IOC_SIZESHIFT)))

#define ISH_IO(type, nr) ISH_IOC(ISH_IOC_NONE, (type), (nr), 0)
#define ISH_IOR(type, nr, size) ISH_IOC(ISH_IOC_READ, (type), (nr), sizeof(size))
#define ISH_IOW(type, nr, size) ISH_IOC(ISH_IOC_WRITE, (type), (nr), sizeof(size))
#define ISH_IOWR(type, nr, size) \
    ISH_IOC(ISH_IOC_READ | ISH_IOC_WRITE, (type), (nr), sizeof(size))

// Same, but with the payload size given directly. Needed where the guest's
// type is a different width than ours, or differs between 32- and 64-bit
// guests (size_t, unsigned long) and both encodings must be accepted.
#define ISH_IOW_SIZE(type, nr, size) ISH_IOC(ISH_IOC_WRITE, (type), (nr), (size))
#define ISH_IOR_SIZE(type, nr, size) ISH_IOC(ISH_IOC_READ, (type), (nr), (size))
#define ISH_IOWR_SIZE(type, nr, size) \
    ISH_IOC(ISH_IOC_READ | ISH_IOC_WRITE, (type), (nr), (size))

#endif
