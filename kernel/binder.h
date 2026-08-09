#ifndef KERNEL_BINDER_H
#define KERNEL_BINDER_H

#include "misc.h"

// Android Binder IPC driver.
//
// This header carries the guest-visible ABI (a transcription of Linux's
// include/uapi/linux/android/binder.h and binderfs.h) plus the handful of
// entry points the rest of iSH needs. The driver itself is kernel/binder.c.
//
// ABI note: modern Linux always builds binder with 64-bit binder_size_t and
// binder_uintptr_t, even for 32-bit userspace (the BINDER_IPC_32BIT variant is
// long dead), so every struct below has one layout shared by our i386 and
// x86_64 guests -- and, because every field is an explicit-width type laid out
// at a naturally 8-aligned offset, that layout is also what the 64-bit host
// compiler produces for these same declarations. binder.c static_asserts the
// sizes so a host padding surprise is a build error rather than a wire-format
// bug.

typedef uint64_t binder_size_t;
typedef uint64_t binder_uintptr_t;

// ---------------------------------------------------------------------------
// ioctl encoding
// ---------------------------------------------------------------------------
// Binder's ioctl numbers are _IOC-encoded, and the guest builds them from the
// struct sizes above, so we have to reproduce the encoding rather than pick
// arbitrary constants.

#define BINDER_IOC_NRBITS 8
#define BINDER_IOC_TYPEBITS 8
#define BINDER_IOC_SIZEBITS 14
#define BINDER_IOC_NRSHIFT 0
#define BINDER_IOC_TYPESHIFT (BINDER_IOC_NRSHIFT + BINDER_IOC_NRBITS)
#define BINDER_IOC_SIZESHIFT (BINDER_IOC_TYPESHIFT + BINDER_IOC_TYPEBITS)
#define BINDER_IOC_DIRSHIFT (BINDER_IOC_SIZESHIFT + BINDER_IOC_SIZEBITS)
#define BINDER_IOC_NONE 0U
#define BINDER_IOC_WRITE 1U
#define BINDER_IOC_READ 2U

// The result is deliberately a 32-bit *signed* int. The guest passes the
// command to ioctl(2) as a 32-bit value and struct fd_ops takes it as an int,
// so codes with the read bit set (0x80000000) arrive negative. Without the
// narrowing cast the sizeof() below would widen the whole expression to
// size_t, and a negative `cmd` promoted to 64 bits would never compare equal
// to the positive 64-bit constant -- every BR_-direction ioctl would silently
// fall through to ENOTTY.
#define BINDER_IOC(dir, type, nr, size) \
    ((int) (uint32_t) (((uint32_t) (dir) << BINDER_IOC_DIRSHIFT) | \
                       ((uint32_t) (type) << BINDER_IOC_TYPESHIFT) | \
                       ((uint32_t) (nr) << BINDER_IOC_NRSHIFT) | \
                       ((uint32_t) (size) << BINDER_IOC_SIZESHIFT)))
#define BINDER_IO(type, nr) BINDER_IOC(BINDER_IOC_NONE, (type), (nr), 0)
#define BINDER_IOR(type, nr, size) BINDER_IOC(BINDER_IOC_READ, (type), (nr), sizeof(size))
#define BINDER_IOW(type, nr, size) BINDER_IOC(BINDER_IOC_WRITE, (type), (nr), sizeof(size))
#define BINDER_IOWR(type, nr, size) \
    BINDER_IOC(BINDER_IOC_READ | BINDER_IOC_WRITE, (type), (nr), sizeof(size))

// ---------------------------------------------------------------------------
// Object types carried inline in a transaction's data buffer
// ---------------------------------------------------------------------------

#define B_PACK_CHARS(c1, c2, c3, c4) \
    ((((unsigned) (c1)) << 24) | (((unsigned) (c2)) << 16) | \
     (((unsigned) (c3)) << 8) | ((unsigned) (c4)))
#define B_TYPE_LARGE 0x85

enum {
    BINDER_TYPE_BINDER      = B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
    BINDER_TYPE_WEAK_BINDER = B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE),
    BINDER_TYPE_HANDLE      = B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
    BINDER_TYPE_WEAK_HANDLE = B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE),
    BINDER_TYPE_FD          = B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE),
    BINDER_TYPE_FDA         = B_PACK_CHARS('f', 'd', 'a', B_TYPE_LARGE),
    BINDER_TYPE_PTR         = B_PACK_CHARS('p', 't', '*', B_TYPE_LARGE),
};

enum {
    FLAT_BINDER_FLAG_PRIORITY_MASK = 0xff,
    FLAT_BINDER_FLAG_ACCEPTS_FDS = 0x100,
    FLAT_BINDER_FLAG_SCHED_POLICY_MASK = 3U << 9,
    FLAT_BINDER_FLAG_INHERIT_RT = 0x800,
    FLAT_BINDER_FLAG_TXN_SECURITY_CTX = 0x1000,
};

struct binder_object_header {
    uint32_t type;
};

struct flat_binder_object {
    struct binder_object_header hdr;
    uint32_t flags;
    union {
        binder_uintptr_t binder; // local object (BINDER_TYPE_BINDER)
        uint32_t handle;         // remote object (BINDER_TYPE_HANDLE)
    };
    binder_uintptr_t cookie;
};

struct binder_fd_object {
    struct binder_object_header hdr;
    uint32_t pad_flags;
    union {
        binder_uintptr_t pad_binder;
        uint32_t fd;
    };
    binder_uintptr_t cookie;
};

// Scatter-gather buffer (BINDER_TYPE_PTR): points at a second guest buffer
// that the driver copies into the target's transaction allocation alongside
// the main data block.
struct binder_buffer_object {
    struct binder_object_header hdr;
    uint32_t flags;
    binder_uintptr_t buffer;
    binder_size_t length;
    binder_size_t parent;
    binder_size_t parent_offset;
};

enum {
    BINDER_BUFFER_FLAG_HAS_PARENT = 0x01,
};

// An array of file descriptors embedded in a parent BINDER_TYPE_PTR buffer.
struct binder_fd_array_object {
    struct binder_object_header hdr;
    uint32_t pad;
    binder_size_t num_fds;
    binder_size_t parent;
    binder_size_t parent_offset;
};

// ---------------------------------------------------------------------------
// ioctl payloads
// ---------------------------------------------------------------------------

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_version {
    int32_t protocol_version;
};

// The 64-bit binder ABI. 32-bit guests get this too (see the ABI note above).
#define BINDER_CURRENT_PROTOCOL_VERSION 8

struct binder_node_debug_info {
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
    uint32_t has_strong_ref;
    uint32_t has_weak_ref;
};

struct binder_node_info_for_ref {
    uint32_t handle;
    uint32_t strong_count;
    uint32_t weak_count;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct binder_freeze_info {
    uint32_t pid;
    uint32_t enable;
    uint32_t timeout_ms;
};

struct binder_frozen_status_info {
    uint32_t pid;
    uint32_t sync_recv;
    uint32_t async_recv;
};

#define BINDER_WRITE_READ_          BINDER_IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_IDLE_TIMEOUT_    BINDER_IOW('b', 3, int64_t)
#define BINDER_SET_MAX_THREADS_     BINDER_IOW('b', 5, uint32_t)
#define BINDER_SET_IDLE_PRIORITY_   BINDER_IOW('b', 6, int32_t)
#define BINDER_SET_CONTEXT_MGR_     BINDER_IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT_         BINDER_IOW('b', 8, int32_t)
#define BINDER_VERSION_             BINDER_IOWR('b', 9, struct binder_version)
#define BINDER_GET_NODE_DEBUG_INFO_ BINDER_IOWR('b', 11, struct binder_node_debug_info)
#define BINDER_GET_NODE_INFO_FOR_REF_ BINDER_IOWR('b', 12, struct binder_node_info_for_ref)
#define BINDER_SET_CONTEXT_MGR_EXT_ BINDER_IOW('b', 13, struct flat_binder_object)
#define BINDER_FREEZE_              BINDER_IOW('b', 14, struct binder_freeze_info)
#define BINDER_GET_FROZEN_INFO_     BINDER_IOWR('b', 15, struct binder_frozen_status_info)
#define BINDER_ENABLE_ONEWAY_SPAM_DETECTION_ BINDER_IOW('b', 16, uint32_t)

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

enum transaction_flags {
    TF_ONE_WAY = 0x01,     // asynchronous, no reply expected
    TF_ROOT_OBJECT = 0x04, // contents are the component's root object
    TF_STATUS_CODE = 0x08, // contents are a 32-bit status code
    TF_ACCEPT_FDS = 0x10,  // the receiver allows file descriptors
    TF_CLEAR_BUF = 0x20,   // scrub the buffer on free
    TF_UPDATE_TXN = 0x40,  // supersede an undelivered oneway to the same node
};

struct binder_transaction_data {
    union {
        uint32_t handle;      // outgoing: target ref
        binder_uintptr_t ptr; // incoming: target node's guest pointer
    } target;
    binder_uintptr_t cookie;
    uint32_t code;
    uint32_t flags;
    dword_t sender_pid;
    dword_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;  // guest address of the data block
            binder_uintptr_t offsets; // guest address of the offsets array
        } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_transaction_data_secctx {
    struct binder_transaction_data transaction_data;
    binder_uintptr_t secctx;
};

struct binder_transaction_data_sg {
    struct binder_transaction_data transaction_data;
    binder_size_t buffers_size;
};

struct binder_ptr_cookie {
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
};

struct binder_handle_cookie {
    uint32_t handle;
    binder_uintptr_t cookie;
} __attribute__((packed));

struct binder_pri_desc {
    int32_t priority;
    uint32_t desc;
};

struct binder_pri_ptr_cookie {
    int32_t priority;
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
};

// Driver -> userspace return protocol (the BR_ codes written into read_buffer).
enum binder_driver_return_protocol {
    BR_ERROR = BINDER_IOR('r', 0, int32_t),
    BR_OK = BINDER_IO('r', 1),
    BR_TRANSACTION_SEC_CTX = BINDER_IOR('r', 2, struct binder_transaction_data_secctx),
    BR_TRANSACTION = BINDER_IOR('r', 2, struct binder_transaction_data),
    BR_REPLY = BINDER_IOR('r', 3, struct binder_transaction_data),
    BR_ACQUIRE_RESULT = BINDER_IOR('r', 4, int32_t),
    BR_DEAD_REPLY = BINDER_IO('r', 5),
    BR_TRANSACTION_COMPLETE = BINDER_IO('r', 6),
    BR_INCREFS = BINDER_IOR('r', 7, struct binder_ptr_cookie),
    BR_ACQUIRE = BINDER_IOR('r', 8, struct binder_ptr_cookie),
    BR_RELEASE = BINDER_IOR('r', 9, struct binder_ptr_cookie),
    BR_DECREFS = BINDER_IOR('r', 10, struct binder_ptr_cookie),
    BR_ATTEMPT_ACQUIRE = BINDER_IOR('r', 11, struct binder_pri_ptr_cookie),
    BR_NOOP = BINDER_IO('r', 12),
    BR_SPAWN_LOOPER = BINDER_IO('r', 13),
    BR_FINISHED = BINDER_IO('r', 14),
    BR_DEAD_BINDER = BINDER_IOR('r', 15, binder_uintptr_t),
    BR_CLEAR_DEATH_NOTIFICATION_DONE = BINDER_IOR('r', 16, binder_uintptr_t),
    BR_FAILED_REPLY = BINDER_IO('r', 17),
    BR_FROZEN_REPLY = BINDER_IO('r', 18),
    BR_ONEWAY_SPAM_SUSPECT = BINDER_IO('r', 19),
    BR_TRANSACTION_PENDING_FROZEN = BINDER_IO('r', 20),
};

// Userspace -> driver command protocol (the BC_ codes read from write_buffer).
enum binder_driver_command_protocol {
    BC_TRANSACTION = BINDER_IOW('c', 0, struct binder_transaction_data),
    BC_REPLY = BINDER_IOW('c', 1, struct binder_transaction_data),
    BC_ACQUIRE_RESULT = BINDER_IOW('c', 2, int32_t),
    BC_FREE_BUFFER = BINDER_IOW('c', 3, binder_uintptr_t),
    BC_INCREFS = BINDER_IOW('c', 4, uint32_t),
    BC_ACQUIRE = BINDER_IOW('c', 5, uint32_t),
    BC_RELEASE = BINDER_IOW('c', 6, uint32_t),
    BC_DECREFS = BINDER_IOW('c', 7, uint32_t),
    BC_INCREFS_DONE = BINDER_IOW('c', 8, struct binder_ptr_cookie),
    BC_ACQUIRE_DONE = BINDER_IOW('c', 9, struct binder_ptr_cookie),
    BC_ATTEMPT_ACQUIRE = BINDER_IOW('c', 10, struct binder_pri_desc),
    BC_REGISTER_LOOPER = BINDER_IO('c', 11),
    BC_ENTER_LOOPER = BINDER_IO('c', 12),
    BC_EXIT_LOOPER = BINDER_IO('c', 13),
    BC_REQUEST_DEATH_NOTIFICATION = BINDER_IOW('c', 14, struct binder_handle_cookie),
    BC_CLEAR_DEATH_NOTIFICATION = BINDER_IOW('c', 15, struct binder_handle_cookie),
    BC_DEAD_BINDER_DONE = BINDER_IOW('c', 16, binder_uintptr_t),
    BC_TRANSACTION_SG = BINDER_IOW('c', 17, struct binder_transaction_data_sg),
    BC_REPLY_SG = BINDER_IOW('c', 18, struct binder_transaction_data_sg),
};

// ---------------------------------------------------------------------------
// binderfs
// ---------------------------------------------------------------------------

#define BINDERFS_MAX_NAME 255

struct binderfs_device {
    char name[BINDERFS_MAX_NAME + 1];
    uint32_t major;
    uint32_t minor;
};

#define BINDER_CTL_ADD_ BINDER_IOWR('b', 1, struct binderfs_device)

// ---------------------------------------------------------------------------
// Entry points used by the rest of iSH
// ---------------------------------------------------------------------------

struct dev_ops;
struct fd_ops;
struct fs_ops;
struct task;

// The character device backing every binder context. Registered under
// BINDER_MAJOR at the minors in fs/devices.h.
extern struct dev_ops binder_dev;

// binderfs, and the ops for its BINDER_CTL_ADD control node (fs/binderfs.c).
extern const struct fs_ops binderfs;
extern const struct fd_ops binderfs_control_ops;

// Creates /dev/binder, /dev/hwbinder and /dev/vndbinder if they are missing or
// point at the wrong device. Needs a mounted root and a current task, so it is
// called from the boot paths rather than at registration time; the minor table
// and binderfs's filesystems-table entry are both static, so nothing else
// needs initializing. Idempotent, and a no-op on a root that cannot hold
// device nodes (binderfs supplies its own).
void binder_create_device_nodes(void);

// Called from do_exit so a task that dies mid-transaction releases its binder
// state (and its peers learn about it) without waiting for fd teardown.
void binder_task_exit(struct task *task);

// Allocates a minor for a new binderfs device named `name`. Returns the minor,
// or a negative errno. Used by binderfs's BINDER_CTL_ADD.
int binder_alloc_minor(const char *name);

// Name of the binder device at `minor`, or NULL if that minor is unused.
// Lets binderfs enumerate the directory without duplicating the registry.
const char *binder_minor_device_name(int minor);

#endif
