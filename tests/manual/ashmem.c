// ashmem: Android anonymous shared memory (/dev/ashmem, kernel/ashmem.c).
//
// The primitive nearly every Android process uses for bulk data: open the
// device, name it, size it, mmap it, then hand the fd to another process,
// which mmaps the same memory. This test drives it the way libcutils does.
//
// Covered:
//   lifecycle   SET_SIZE/GET_SIZE, SET_NAME/GET_NAME round-trip, and the
//               rule that both are frozen once the region has been mapped.
//   mapping     mmap before SET_SIZE is EINVAL; a mapped region is readable
//               and writable and reads back what was written; read(2) and
//               lseek(2) see the same bytes as the mapping.
//   sharing     THE point of ashmem: the fd is sent to a child over
//               SCM_RIGHTS, both sides mmap it, and a write on one side is
//               visible on the other. Also the reverse direction.
//   prot mask   SET_PROT_MASK can only remove access; re-adding a dropped bit
//               is EINVAL, and mapping beyond the mask is EPERM.
//   pinning     UNPIN/PIN/GET_PIN_STATUS bookkeeping, including a partial
//               re-pin inside an unpinned span. PIN reports ASHMEM_NOT_PURGED
//               because this implementation never reclaims.
//
// Arch-neutral, but note two of ashmem's ioctl numbers are built from size_t
// and unsigned long, so they differ between a 32- and 64-bit guest. The
// driver accepts both; this test naturally exercises whichever its own build
// produces.

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
#define ASHMEM_DEV_MINOR 55

#define ASHMEM_NAME_LEN 256

struct ashmem_pin {
    uint32_t offset;
    uint32_t len;
};

#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME         _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME         _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE         _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE         _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK    _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK    _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN              _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN            _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS   _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)

#define ASHMEM_NOT_PURGED 0
#define ASHMEM_IS_UNPINNED 0
#define ASHMEM_IS_PINNED 1

#define REGION_SIZE (16 * 4096)
#define CHILD_MAGIC 0x5a5a5a5aU
#define PARENT_MAGIC 0xa5a5a5a5U

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

// Which path to open. Normally /dev/ashmem, but only the node's device
// numbers actually matter -- a char device (10,55) anywhere opens ashmem. On a
// root where mknod in /dev is not permitted (a realfs root without CAP_MKNOD,
// e.g. the CLI build), fall back to a tmpfs we can create the node on.
static char ashmem_dev_path[128];

static int ashmem_setup_device(void) {
    snprintf(ashmem_dev_path, sizeof(ashmem_dev_path), "/dev/ashmem");
    if (access(ashmem_dev_path, F_OK) == 0)
        return 0;
    if (mknod(ashmem_dev_path, S_IFCHR | 0666,
              makedev(MISC_DEV_MAJOR, ASHMEM_DEV_MINOR)) == 0)
        return 0;

    int mknod_errno = errno;
    const char *dir = "/tmp/ashmem-test";
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
        errno = mknod_errno;
        return -1;
    }
    if (mount("tmpfs", dir, "tmpfs", 0, NULL) != 0) {
        errno = mknod_errno;
        return -1;
    }
    snprintf(ashmem_dev_path, sizeof(ashmem_dev_path), "%s/ashmem", dir);
    if (mknod(ashmem_dev_path, S_IFCHR | 0666,
              makedev(MISC_DEV_MAJOR, ASHMEM_DEV_MINOR)) != 0)
        return -1;
    test_logf("using %s (mknod in /dev failed: %s)\n", ashmem_dev_path,
              strerror(mknod_errno));
    return 0;
}

// Opens a sized, named region, ready to map.
static int ashmem_create(const char *name, size_t size) {
    int fd = open(ashmem_dev_path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (name != NULL) {
        char buf[ASHMEM_NAME_LEN];
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%s", name);
        if (ioctl(fd, ASHMEM_SET_NAME, buf) < 0) {
            close(fd);
            return -1;
        }
    }
    if (ioctl(fd, ASHMEM_SET_SIZE, size) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_lifecycle(void) {
    int fd = open(ashmem_dev_path, O_RDWR | O_CLOEXEC);
    check(fd >= 0, "open the ashmem device");
    if (fd < 0)
        return;

    // Mapping before a size is set has nothing to map.
    void *early = mmap(NULL, REGION_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    check(early == MAP_FAILED && errno == EINVAL, "mmap before SET_SIZE is EINVAL");
    if (early != MAP_FAILED)
        munmap(early, REGION_SIZE);

    char name[ASHMEM_NAME_LEN];
    memset(name, 0, sizeof(name));
    snprintf(name, sizeof(name), "test-region");
    check(ioctl(fd, ASHMEM_SET_NAME, name) == 0, "ASHMEM_SET_NAME");

    char readback[ASHMEM_NAME_LEN];
    memset(readback, 0, sizeof(readback));
    check(ioctl(fd, ASHMEM_GET_NAME, readback) == 0, "ASHMEM_GET_NAME");
    check(strcmp(readback, "test-region") == 0, "name round-trips");

    check(ioctl(fd, ASHMEM_SET_SIZE, (size_t) REGION_SIZE) == 0, "ASHMEM_SET_SIZE");
    check(ioctl(fd, ASHMEM_GET_SIZE) == REGION_SIZE, "ASHMEM_GET_SIZE reports it back");

    void *map = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "mmap after SET_SIZE");

    // Both are frozen once mapped.
    check(ioctl(fd, ASHMEM_SET_SIZE, (size_t) (REGION_SIZE * 2)) < 0 && errno == EINVAL,
          "SET_SIZE after mmap is EINVAL");
    check(ioctl(fd, ASHMEM_SET_NAME, name) < 0 && errno == EINVAL,
          "SET_NAME after mmap is EINVAL");

    if (map != MAP_FAILED) {
        // The mapping is real memory, and read(2) sees the same bytes.
        uint32_t value = 0xdeadbeef;
        memcpy(map, &value, sizeof(value));
        check(memcmp(map, &value, sizeof(value)) == 0, "mapping holds what was written");

        uint32_t via_read = 0;
        check(lseek(fd, 0, SEEK_SET) == 0, "lseek to start");
        check(read(fd, &via_read, sizeof(via_read)) == (ssize_t) sizeof(via_read), "read(2)");
        check(via_read == value, "read(2) sees the mapping's contents");
        check(lseek(fd, 0, SEEK_END) == REGION_SIZE, "SEEK_END is the region size");

        munmap(map, REGION_SIZE);
    }

    check(ioctl(fd, ASHMEM_PURGE_ALL_CACHES) >= 0, "ASHMEM_PURGE_ALL_CACHES");
    check(ioctl(fd, _IO(__ASHMEMIOC, 99)) < 0 && errno == ENOTTY, "unknown ioctl is ENOTTY");
    close(fd);
}

static void test_prot_mask(void) {
    int fd = ashmem_create("prot", REGION_SIZE);
    check(fd >= 0, "create region for prot mask");
    if (fd < 0)
        return;

    int mask = ioctl(fd, ASHMEM_GET_PROT_MASK);
    check(mask > 0 && (mask & PROT_WRITE), "default prot mask allows writing");

    // Drop write.
    check(ioctl(fd, ASHMEM_SET_PROT_MASK, (unsigned long) PROT_READ) == 0,
          "SET_PROT_MASK can remove write");
    check((ioctl(fd, ASHMEM_GET_PROT_MASK) & PROT_WRITE) == 0, "prot mask no longer has write");

    // ...and it cannot come back.
    check(ioctl(fd, ASHMEM_SET_PROT_MASK, (unsigned long) (PROT_READ | PROT_WRITE)) < 0 &&
              errno == EINVAL,
          "re-adding a dropped prot bit is EINVAL");

    void *map = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map == MAP_FAILED && errno == EPERM, "mapping beyond the prot mask is EPERM");
    if (map != MAP_FAILED)
        munmap(map, REGION_SIZE);

    void *ro = mmap(NULL, REGION_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    check(ro != MAP_FAILED, "mapping within the prot mask still works");
    if (ro != MAP_FAILED)
        munmap(ro, REGION_SIZE);
    close(fd);
}

static void test_pinning(void) {
    int fd = ashmem_create("pinning", REGION_SIZE);
    check(fd >= 0, "create region for pinning");
    if (fd < 0)
        return;

    struct ashmem_pin whole = { .offset = 0, .len = 0 }; // 0 == to the end
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &whole) == ASHMEM_IS_PINNED,
          "a fresh region is pinned");

    check(ioctl(fd, ASHMEM_UNPIN, &whole) == 0, "ASHMEM_UNPIN whole region");
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &whole) == ASHMEM_IS_UNPINNED,
          "whole region reads back unpinned");

    // Re-pin a slice out of the middle: the region as a whole is no longer
    // fully unpinned, but the slices either side still are.
    struct ashmem_pin middle = { .offset = 4096, .len = 4096 };
    check(ioctl(fd, ASHMEM_PIN, &middle) == ASHMEM_NOT_PURGED,
          "ASHMEM_PIN reports NOT_PURGED (nothing is ever reclaimed here)");
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &middle) == ASHMEM_IS_PINNED,
          "the re-pinned slice is pinned");
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &whole) == ASHMEM_IS_PINNED,
          "the whole region is no longer fully unpinned");

    struct ashmem_pin first = { .offset = 0, .len = 4096 };
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &first) == ASHMEM_IS_UNPINNED,
          "the slice before it is still unpinned");
    struct ashmem_pin third = { .offset = 8192, .len = 4096 };
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &third) == ASHMEM_IS_UNPINNED,
          "the slice after it is still unpinned");

    check(ioctl(fd, ASHMEM_PIN, &whole) == ASHMEM_NOT_PURGED, "re-pin everything");
    check(ioctl(fd, ASHMEM_GET_PIN_STATUS, &whole) == ASHMEM_IS_PINNED,
          "everything is pinned again");

    // Linux requires page alignment.
    struct ashmem_pin unaligned = { .offset = 1, .len = 4096 };
    check(ioctl(fd, ASHMEM_UNPIN, &unaligned) < 0 && errno == EINVAL,
          "an unaligned pin range is EINVAL");
    struct ashmem_pin past_end = { .offset = 0, .len = REGION_SIZE + 4096 };
    check(ioctl(fd, ASHMEM_UNPIN, &past_end) < 0 && errno == EINVAL,
          "a range past the end is EINVAL");

    close(fd);
}

// Sends one fd over a unix socket.
static int send_fd(int sock, int fd) {
    char body = 'f';
    struct iovec iov = { .iov_base = &body, .iov_len = 1 };
    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
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
    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
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

// The whole point of ashmem: the same memory on both sides of a passed fd.
static void test_cross_process_sharing(void) {
    int fd = ashmem_create("shared", REGION_SIZE);
    check(fd >= 0, "create region for sharing");
    if (fd < 0)
        return;

    volatile uint32_t *map = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(map != MAP_FAILED, "parent maps the region");
    if (map == MAP_FAILED) {
        close(fd);
        return;
    }
    map[0] = PARENT_MAGIC;

    int sv[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    int sync[2];
    check(pipe(sync) == 0, "sync pipe");

    pid_t child = fork();
    check(child >= 0, "fork");
    if (child == 0) {
        close(sv[0]);
        close(sync[0]);
        close(fd);

        int received = recv_fd(sv[1]);
        if (received < 0)
            _exit(70);
        // The child never learns the size from us -- it asks the region.
        int size = ioctl(received, ASHMEM_GET_SIZE);
        if (size != REGION_SIZE)
            _exit(71);
        volatile uint32_t *child_map = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
                                            MAP_SHARED, received, 0);
        if (child_map == MAP_FAILED)
            _exit(72);
        // Must see what the parent wrote before the handoff...
        if (child_map[0] != PARENT_MAGIC)
            _exit(73);
        // ...and its own write must become visible to the parent.
        child_map[1] = CHILD_MAGIC;

        char done = 'd';
        (void) write(sync[1], &done, 1);
        munmap((void *) child_map, REGION_SIZE);
        close(received);
        fflush(NULL);
        _exit(0);
    }

    close(sv[1]);
    close(sync[1]);
    check(send_fd(sv[0], fd) == 0, "send the ashmem fd over SCM_RIGHTS");

    char done = 0;
    check(read(sync[0], &done, 1) == 1 && done == 'd', "child finished writing");
    check(map[1] == CHILD_MAGIC, "parent sees the child's write to shared memory");

    int status = 0;
    check(waitpid(child, &status, 0) == child, "reap child");
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child saw the parent's write");
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        printf("       child exit status %d\n", WEXITSTATUS(status));

    close(sync[0]);
    close(sv[0]);
    munmap((void *) map, REGION_SIZE);
    close(fd);
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    if (ashmem_setup_device() < 0) {
        printf("SKIP ashmem: no ashmem device available (errno=%d %s)\n", errno,
               strerror(errno));
        return finish_suite("ashmem");
    }

    test_lifecycle();
    test_prot_mask();
    test_pinning();
    test_cross_process_sharing();

    return finish_suite("ashmem");
}
