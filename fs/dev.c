#include "kernel/errno.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "fs/mem.h"
#include "fs/tty.h"
#include "fs/dyndev.h"
#include "fs/devices.h"
#include "kernel/binder.h"
#include "kernel/ashmem.h"
#include "kernel/dma_heap.h"
#include "app/RTCDevice.h"

// MISC_MAJOR is Linux's shared misc-device major: several unrelated drivers
// live under it, told apart only by minor.
static int misc_open(int major, int minor, struct fd *fd) {
    struct dev_ops *dev = NULL;
    switch (minor) {
        case DEV_ASHMEM_MINOR:
            dev = &ashmem_dev;
            break;
        case DEV_DMA_HEAP_SYSTEM_MINOR:
        case DEV_DMA_HEAP_UNCACHED_MINOR:
            dev = &dma_heap_dev;
            break;
    }
    if (dev == NULL)
        return _ENXIO;
    fd->ops = &dev->fd;
    if (!dev->open)
        return 0;
    return dev->open(major, minor, fd);
}

static struct dev_ops misc_dev = {
    .open = misc_open,
};

struct dev_ops *block_devs[256] = {
    // no block devices yet
};
struct dev_ops *char_devs[256] = {
    [MEM_MAJOR] = &mem_dev,
    [TTY_CONSOLE_MAJOR] = &tty_dev,
    [TTY_ALTERNATE_MAJOR] = &tty_dev,
    [TTY_PSEUDO_MASTER_MAJOR] = &tty_dev,
    [TTY_PSEUDO_SLAVE_MAJOR] = &tty_dev,
    [DEV_RTC_MAJOR] = &rtc_dev,
    [DYN_DEV_MAJOR] = &dyn_dev_char,
    [BINDER_MAJOR] = &binder_dev,
    [MISC_MAJOR] = &misc_dev,
};

int dev_open(int major, int minor, int type, struct fd *fd) {
    struct dev_ops *dev = (type == DEV_BLOCK ? block_devs : char_devs)[major];
    if (dev == NULL)
        return _ENXIO;
    fd->ops = &dev->fd;
    if (!dev->open)
        return 0;
    return dev->open(major, minor, fd);
}
