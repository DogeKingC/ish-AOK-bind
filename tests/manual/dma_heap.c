// dma_heap: DMA-BUF heaps (/dev/dma_heap/*, kernel/dma_heap.c).
//
// The allocator that replaced ION in Android 12. Open a heap, ask for bytes,
// get back a *new* descriptor -- a dma-buf -- which can be mmapped and passed
// to another process. Every Android graphics and media buffer comes from here.
//
// Covered:
//   heap        both standard heaps open; DMA_HEAP_IOCTL_ALLOC returns a
//               usable fd; a zero length, an unknown fd_flag and a nonzero
//               heap_flags are all rejected; an unknown ioctl is ENOTTY.
//   dma-buf     the returned fd mmaps and holds what is written; lseek
//               SEEK_END reports the (page-rounded) size, which is how
//               userspace discovers it; O_CLOEXEC in fd_flags is honoured.
//   sync        DMA_BUF_IOCTL_SYNC accepts START/END with a direction and
//               rejects unknown flags and a missing direction.
//   name        DMA_BUF_SET_NAME accepts a name.
//   sharing     the point of a dma-buf: send it to a child over SCM_RIGHTS,
//               both mmap it, and writes are visible both ways.
//   independence two allocations are distinct buffers, not aliases.
//
// Arch-neutral. Note DMA_BUF_SET_NAME encodes a pointer width into its ioctl
// number, so it differs between a 32- and 64-bit guest; the driver takes both.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

#include "test_common.h"

#define MISC_DEV_MAJOR 10
#define DMA_HEAP_SYSTEM_MINOR 56
#define DMA_HEAP_UNCACHED_MINOR 57

struct dma_heap_allocation_data {
    uint64_t len;
    uint32_t fd;
    uint32_t fd_flags;
    uint64_t heap_flags;
};

#define DMA_HEAP_IOC_MAGIC 'H'
#define DMA_HEAP_IOCTL_ALLOC _IOWR(DMA_HEAP_IOC_MAGIC, 0x0, struct dma_heap_allocation_data)

struct dma_buf_sync {
    uint64_t flags;
};

#define DMA_BUF_SYNC_READ (1 << 0)
#define DMA_BUF_SYNC_WRITE (2 << 0)
#define DMA_BUF_SYNC_RW (DMA_BUF_SYNC_READ | DMA_BUF_SYNC_WRITE)
#define DMA_BUF_SYNC_START (0 << 2)
#define DMA_BUF_SYNC_END (1 << 2)

#define DMA_BUF_BASE 'b'
#define DMA_BUF_IOCTL_SYNC _IOW(DMA_BUF_BASE, 0, struct dma_buf_sync)
#define DMA_BUF_SET_NAME _IOW(DMA_BUF_BASE, 1, const char *)

#define BUF_SIZE (8 * 4096)
#define PARENT_MAGIC 0x11223344U
#define CHILD_MAGIC 0x55667788U

static char heap_path[128];
static char uncached_path[128];

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

// Only the device numbers matter, so on a root where mknod in /dev is denied
// (a realfs root without CAP_MKNOD) put the nodes on a tmpfs instead.
static int setup_heaps(void) {
    snprintf(heap_path, sizeof(heap_path), "/dev/dma_heap/system");
    snprintf(uncached_path, sizeof(uncached_path), "/dev/dma_heap/system-uncached");
    if (access(heap_path, F_OK) == 0)
        return 0;

    (void) mkdir("/dev/dma_heap", 0755);
    if (mknod(heap_path, S_IFCHR | 0666, makedev(MISC_DEV_MAJOR, DMA_HEAP_SYSTEM_MINOR)) == 0) {
        (void) mknod(uncached_path, S_IFCHR | 0666,
                     makedev(MISC_DEV_MAJOR, DMA_HEAP_UNCACHED_MINOR));
        return 0;
    }

    int mknod_errno = errno;
    const char *dir = "/tmp/dma-heap-test";
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
        errno = mknod_errno;
        return -1;
    }
    if (mount("tmpfs", dir, "tmpfs", 0, NULL) != 0) {
        errno = mknod_errno;
        return -1;
    }
    snprintf(heap_path, sizeof(heap_path), "%s/system", dir);
    snprintf(uncached_path, sizeof(uncached_path), "%s/system-uncached", dir);
    if (mknod(heap_path, S_IFCHR | 0666, makedev(MISC_DEV_MAJOR, DMA_HEAP_SYSTEM_MINOR)) != 0)
        return -1;
    if (mknod(uncached_path, S_IFCHR | 0666,
              makedev(MISC_DEV_MAJOR, DMA_HEAP_UNCACHED_MINOR)) != 0)
        return -1;
    test_logf("using %s (mknod in /dev failed: %s)\n", heap_path, strerror(mknod_errno));
    return 0;
}

// Allocates one buffer. Returns its fd, or -1.
static int heap_alloc(int heap_fd, uint64_t len, uint32_t fd_flags) {
    struct dma_heap_allocation_data data;
    memset(&data, 0, sizeof(data));
    data.len = len;
    data.fd_flags = fd_flags;
    if (ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &data) < 0)
        return -1;
    return (int) data.fd;
}

static void test_heap_and_alloc(void) {
    int heap = open(heap_path, O_RDONLY | O_CLOEXEC);
    check(heap >= 0, "open the system heap");
    if (heap < 0)
        return;

    int uncached = open(uncached_path, O_RDONLY | O_CLOEXEC);
    check(uncached >= 0, "open the system-uncached heap");
    if (uncached >= 0)
        close(uncached);

    check(ioctl(heap, _IO(DMA_HEAP_IOC_MAGIC, 0x7f)) < 0 && errno == ENOTTY,
          "unknown heap ioctl is ENOTTY");

    // Rejections.
    struct dma_heap_allocation_data bad;
    memset(&bad, 0, sizeof(bad));
    bad.len = 0;
    check(ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &bad) < 0 && errno == EINVAL,
          "a zero-length allocation is EINVAL");

    memset(&bad, 0, sizeof(bad));
    bad.len = BUF_SIZE;
    bad.heap_flags = 1;
    check(ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &bad) < 0 && errno == EINVAL,
          "a nonzero heap_flags is EINVAL (no flags are defined)");

    memset(&bad, 0, sizeof(bad));
    bad.len = BUF_SIZE;
    bad.fd_flags = 0x40000000; // not a valid open flag here
    check(ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &bad) < 0 && errno == EINVAL,
          "an unknown fd_flag is EINVAL");

    // A real allocation.
    int buf = heap_alloc(heap, BUF_SIZE, O_RDWR | O_CLOEXEC);
    check(buf >= 0, "DMA_HEAP_IOCTL_ALLOC returns a descriptor");
    if (buf >= 0) {
        check(fcntl(buf, F_GETFD) & FD_CLOEXEC, "O_CLOEXEC in fd_flags is honoured");
        // SEEK_END is how userspace learns a dma-buf's size.
        check(lseek(buf, 0, SEEK_END) == BUF_SIZE, "lseek SEEK_END reports the size");

        volatile uint32_t *map = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, buf, 0);
        check(map != MAP_FAILED, "the dma-buf mmaps");
        if (map != MAP_FAILED) {
            map[0] = 0xcafebabe;
            check(map[0] == 0xcafebabe, "the mapping holds what was written");
            munmap((void *) map, BUF_SIZE);
        }

        // A non-page-multiple request is rounded up, like any real heap.
        int odd = heap_alloc(heap, 100, O_RDWR);
        check(odd >= 0, "an unaligned length allocates");
        if (odd >= 0) {
            check(lseek(odd, 0, SEEK_END) == 4096, "the size is rounded up to a page");
            close(odd);
        }

        close(buf);
    }

    // Two allocations must be separate buffers, not aliases of one.
    int a = heap_alloc(heap, BUF_SIZE, O_RDWR);
    int b = heap_alloc(heap, BUF_SIZE, O_RDWR);
    check(a >= 0 && b >= 0, "two allocations succeed");
    if (a >= 0 && b >= 0) {
        volatile uint32_t *ma = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, a, 0);
        volatile uint32_t *mb = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, b, 0);
        check(ma != MAP_FAILED && mb != MAP_FAILED, "both map");
        if (ma != MAP_FAILED && mb != MAP_FAILED) {
            ma[0] = 0xaaaaaaaa;
            mb[0] = 0xbbbbbbbb;
            check(ma[0] == 0xaaaaaaaa, "separate allocations do not alias");
            munmap((void *) ma, BUF_SIZE);
            munmap((void *) mb, BUF_SIZE);
        }
    }
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    close(heap);
}

static void test_sync_and_name(void) {
    int heap = open(heap_path, O_RDONLY | O_CLOEXEC);
    if (heap < 0) {
        check(0, "open heap for sync/name");
        return;
    }
    int buf = heap_alloc(heap, BUF_SIZE, O_RDWR);
    check(buf >= 0, "allocate for sync/name");
    if (buf < 0) {
        close(heap);
        return;
    }

    struct dma_buf_sync sync;
    sync.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW;
    check(ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync) == 0, "SYNC START with a direction");
    sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW;
    check(ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync) == 0, "SYNC END with a direction");

    // A sync naming neither read nor write is meaningless.
    sync.flags = DMA_BUF_SYNC_START;
    check(ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync) < 0 && errno == EINVAL,
          "SYNC with no direction is EINVAL");
    sync.flags = 0xff00;
    check(ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync) < 0 && errno == EINVAL,
          "SYNC with unknown flags is EINVAL");

    check(ioctl(buf, DMA_BUF_SET_NAME, "test-buffer") == 0, "DMA_BUF_SET_NAME");

    close(buf);
    close(heap);
}

static int send_fd(int sock, int fd) {
    char body = 'f';
    struct iovec iov = { .iov_base = &body, .iov_len = 1 };
    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.buf, .msg_controllen = sizeof(control.buf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static int recv_fd(int sock) {
    char body = 0;
    struct iovec iov = { .iov_base = &body, .iov_len = 1 };
    union { struct cmsghdr align; char buf[CMSG_SPACE(sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.buf, .msg_controllen = sizeof(control.buf),
    };
    if (recvmsg(sock, &msg, 0) != 1)
        return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS)
        return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

// A dma-buf exists to be shared: this is the behaviour that matters.
static void test_cross_process_sharing(void) {
    int heap = open(heap_path, O_RDONLY | O_CLOEXEC);
    if (heap < 0) {
        check(0, "open heap for sharing");
        return;
    }
    int buf = heap_alloc(heap, BUF_SIZE, O_RDWR);
    check(buf >= 0, "allocate a buffer to share");
    if (buf < 0) {
        close(heap);
        return;
    }

    volatile uint32_t *map = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, buf, 0);
    check(map != MAP_FAILED, "parent maps the buffer");
    if (map == MAP_FAILED) {
        close(buf);
        close(heap);
        return;
    }
    map[0] = PARENT_MAGIC;

    int sv[2], sync_pipe[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    check(pipe(sync_pipe) == 0, "sync pipe");

    pid_t child = fork();
    check(child >= 0, "fork");
    if (child == 0) {
        close(sv[0]);
        close(sync_pipe[0]);
        close(buf);
        close(heap);

        int received = recv_fd(sv[1]);
        if (received < 0)
            _exit(70);
        // The child learns the size from the buffer itself.
        if (lseek(received, 0, SEEK_END) != BUF_SIZE)
            _exit(71);
        volatile uint32_t *child_map = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                                            MAP_SHARED, received, 0);
        if (child_map == MAP_FAILED)
            _exit(72);
        if (child_map[0] != PARENT_MAGIC)
            _exit(73);
        child_map[1] = CHILD_MAGIC;

        char done = 'd';
        (void) write(sync_pipe[1], &done, 1);
        munmap((void *) child_map, BUF_SIZE);
        close(received);
        fflush(NULL);
        _exit(0);
    }

    close(sv[1]);
    close(sync_pipe[1]);
    check(send_fd(sv[0], buf) == 0, "send the dma-buf over SCM_RIGHTS");

    char done = 0;
    check(read(sync_pipe[0], &done, 1) == 1 && done == 'd', "child finished writing");
    check(map[1] == CHILD_MAGIC, "parent sees the child's write to the shared buffer");

    int status = 0;
    check(waitpid(child, &status, 0) == child, "reap child");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child saw the parent's write");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("       child exit status %d\n", WEXITSTATUS(status));

    close(sync_pipe[0]);
    close(sv[0]);
    munmap((void *) map, BUF_SIZE);
    close(buf);
    close(heap);
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    if (setup_heaps() < 0) {
        printf("SKIP dma_heap: no heap device available (errno=%d %s)\n", errno,
               strerror(errno));
        return finish_suite("dma_heap");
    }

    test_heap_and_alloc();
    test_sync_and_name();
    test_cross_process_sharing();

    return finish_suite("dma_heap");
}
