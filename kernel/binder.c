// Android Binder IPC driver.
//
// Binder is Android's synchronous, capability-passing IPC mechanism. A process
// opens /dev/binder (or /dev/hwbinder, /dev/vndbinder -- separate "contexts"
// with separate name registries), mmaps a receive buffer out of it, and then
// drives everything through a single ioctl, BINDER_WRITE_READ, which carries a
// stream of BC_ commands in one direction and a stream of BR_ returns in the
// other.
//
// The pieces:
//
//   binder_proc    one per open file description. Owns the mmap'd receive
//                  region, the process's nodes and refs, and a work queue.
//   binder_thread  one per guest task that has touched this fd. Owns the
//                  transaction stack (which makes nested/reentrant calls work)
//                  and a thread-directed work queue.
//   binder_node    a local object a process has published. Identified by the
//                  (ptr, cookie) pair userspace chose for it.
//   binder_ref     a handle held by one process onto another process's node.
//                  The handle number is the `desc` field; handle 0 is
//                  reserved for the context manager (servicemanager).
//   binder_buffer  an allocation inside the *target* process's mmap region.
//                  Transaction payloads are copied there once, and the target
//                  reads them in place -- the "single copy" in binder's
//                  single-copy IPC.
//
// How this maps onto iSH: the emulated kernel and the guest share a host
// address space, so the classic binder trick -- kernel and userspace holding
// two mappings of the same physical pages -- falls out naturally. Each
// binder_proc backs its region with an unlinked host temp file, maps it once
// for the guest (host_fd_mmap, read-only, as MAP_SHARED so kernel stores are
// visible) and once for the driver (proc->kernel_map, read-write). Copying a
// transaction means user_read()ing straight from the sender's guest memory
// into proc->kernel_map, after which the receiver can see it at
// proc->user_base + offset.
//
// Locking: one global lock covers every binder structure. Linux uses
// fine-grained per-proc/per-node locking because it cares about scaling to a
// whole phone's worth of IPC; here the simplicity is worth far more than the
// contention, and the one place we must sleep (a thread waiting for work) uses
// wait_for(), which drops the lock while blocked.

#include <string.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "kernel/task.h"
#include "kernel/binder.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "fs/devices.h"
#include "fs/poll.h"
#include "fs/path.h"
#include "fs/real.h"
#include "util/list.h"
#include "util/sync.h"

// The wire format is shared with real Android userspace, so a host padding
// surprise here would be a silent protocol break. Make it a build error.
_Static_assert(sizeof(struct flat_binder_object) == 24, "flat_binder_object ABI");
_Static_assert(sizeof(struct binder_fd_object) == 24, "binder_fd_object ABI");
_Static_assert(sizeof(struct binder_buffer_object) == 40, "binder_buffer_object ABI");
_Static_assert(sizeof(struct binder_fd_array_object) == 32, "binder_fd_array_object ABI");
_Static_assert(sizeof(struct binder_write_read) == 48, "binder_write_read ABI");
_Static_assert(sizeof(struct binder_transaction_data) == 64, "binder_transaction_data ABI");
_Static_assert(sizeof(struct binder_transaction_data_sg) == 72, "binder_transaction_data_sg ABI");
_Static_assert(sizeof(struct binder_ptr_cookie) == 16, "binder_ptr_cookie ABI");
_Static_assert(sizeof(struct binder_handle_cookie) == 12, "binder_handle_cookie ABI");

// Binder aligns everything to the 64-bit binder_uintptr_t, on every guest.
#define BINDER_ALIGN(n) (((n) + 7) & ~(size_t) 7)

// Linux caps a binder mapping at 4MB and reserves the top page.
#define BINDER_MAX_MAP_SIZE (4 * 1024 * 1024)

// A oneway transaction may occupy at most half the target's buffer, so a
// flood of async traffic can't starve synchronous calls.
#define BINDER_ASYNC_FRACTION 2

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

enum binder_work_type {
    BINDER_WORK_TRANSACTION = 1,
    BINDER_WORK_TRANSACTION_COMPLETE,
    BINDER_WORK_TRANSACTION_PENDING,
    BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT,
    BINDER_WORK_RETURN_ERROR,
    BINDER_WORK_NODE,
    BINDER_WORK_DEAD_BINDER,
    BINDER_WORK_DEAD_BINDER_AND_CLEAR,
    BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
};

struct binder_work {
    struct list link;
    enum binder_work_type type;
};

// A pending BR_ERROR/BR_FAILED_REPLY/BR_DEAD_REPLY for one thread. Embedded in
// the thread so reporting an error never needs an allocation that could fail.
struct binder_error {
    struct binder_work work;
    uint32_t cmd; // BR_OK when nothing is pending
};

struct binder_context {
    const char *name;
    struct binder_node *mgr_node; // handle 0
    uid_t_ mgr_uid;
    bool mgr_uid_valid;
};

struct binder_node {
    struct list proc_link;  // binder_proc.nodes
    struct binder_work work;
    bool has_work;

    struct binder_proc *proc; // NULL once the owner is gone
    struct binder_context *context;

    binder_uintptr_t ptr;
    binder_uintptr_t cookie;

    // Strong/weak accounting. "internal" counts refs held by other processes;
    // "local" counts refs the owner itself was told about via BR_ACQUIRE.
    int internal_strong_refs;
    int local_strong_refs;
    int local_weak_refs;
    int tmp_refs; // transient, keeps the node alive across an unlocked window

    bool has_strong_ref;
    bool has_weak_ref;
    bool pending_strong_ref;
    bool pending_weak_ref;

    uint32_t flags;
    bool accept_fds;
    bool txn_security_ctx;

    struct list refs;       // binder_ref.node_link
    struct list async_todo; // queued oneway transactions, one in flight at a time
    bool has_async_transaction;

    int debug_id;
};

struct binder_ref_death {
    struct binder_work work;
    binder_uintptr_t cookie;
};

struct binder_ref {
    struct list proc_link; // binder_proc.refs, ordered by desc
    struct list node_link; // binder_node.refs
    struct binder_proc *proc;
    struct binder_node *node;
    uint32_t desc;
    int strong;
    int weak;
    struct binder_ref_death *death;
};

struct binder_buffer {
    struct list link; // binder_proc.buffers, ordered by offset
    size_t offset;    // from the start of the mapping
    size_t size;      // total chunk size
    bool free;

    // Set while allocated:
    size_t data_size;
    size_t offsets_size;
    size_t extra_buffers_size;
    bool allow_user_free;
    bool async;
    bool clear_on_free;
    struct binder_transaction *transaction;
    struct binder_node *target_node;
};

// A file descriptor travelling inside a transaction. The sender's struct fd is
// retained at send time; the number is only allocated when the *receiver*
// dequeues the transaction, which is both what Linux does now and the only way
// we can call f_install (it installs into `current`).
struct binder_fd_fixup {
    struct list link;
    struct fd *file;
    size_t offset; // where in the target buffer the u32 fd goes
};

struct binder_transaction {
    struct binder_work work;
    struct binder_thread *from;
    struct binder_transaction *from_parent;
    struct binder_proc *to_proc;
    struct binder_thread *to_thread;
    struct binder_transaction *to_parent;
    bool need_reply;
    struct binder_buffer *buffer;
    uint32_t code;
    uint32_t flags;
    pid_t_ sender_pid;
    uid_t_ sender_euid;
    // Guest address, inside the target's own mapping, of the sender's SELinux
    // context -- or 0 when the target node did not ask for one. Non-zero is
    // what turns BR_TRANSACTION into BR_TRANSACTION_SEC_CTX at delivery.
    binder_uintptr_t security_ctx;
    struct list fd_fixups;
    int debug_id;
};

struct binder_thread {
    struct list proc_link;
    struct binder_proc *proc;
    pid_t_ pid;
    int looper;
    struct list todo;
    struct binder_transaction *transaction_stack;
    bool is_dead;
    bool waiting;
    bool wait_for_proc_work;
    cond_t wait;
    struct binder_error return_error;
    struct binder_error reply_error;
    unsigned tmp_ref;
};

// binder_thread.looper flags
#define BINDER_LOOPER_STATE_REGISTERED 0x01
#define BINDER_LOOPER_STATE_ENTERED    0x02
#define BINDER_LOOPER_STATE_EXITED     0x04
#define BINDER_LOOPER_STATE_INVALID    0x08
#define BINDER_LOOPER_STATE_WAITING    0x10
#define BINDER_LOOPER_STATE_POLL       0x20

struct binder_proc {
    struct list link; // binder_procs
    pid_t_ pid;       // tgid of whoever opened the device
    struct binder_context *context;
    struct fd *fd;    // owning fd, for poll wakeups; non-owning

    // Receive region.
    int host_fd;
    void *kernel_map;      // driver-side mapping (read-write)
    guest_addr_t user_base;
    size_t map_size;
    struct list buffers;   // binder_buffer, ordered by offset
    size_t free_async_space;

    struct list threads;
    struct list nodes;
    struct list refs;
    struct list todo;
    struct list delivered_death;

    int max_threads;
    int requested_threads;
    int requested_threads_started;
    int ready_threads;

    bool is_dead;
    bool oneway_spam_detection;
    bool frozen;
    bool sync_recv;
    bool async_recv;
    uint32_t outstanding_txns;
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static lock_t binder_lock = LOCK_INITIALIZER;
static struct list binder_procs = LIST_INITIALIZER(binder_procs);
// Number of live binder_procs. Read without the lock by binder_task_exit to
// keep do_exit free of binder cost on guests that never use it.
static atomic_int binder_live_procs;
static int binder_last_debug_id = 0;

static struct binder_context binder_contexts[] = {
    { .name = "binder" },
    { .name = "hwbinder" },
    { .name = "vndbinder" },
};

// Minor -> context. Minors 0-2 are the three standard contexts; 3 is
// binderfs's control device (routed to fs/binderfs.c by binder_open); 4 and up
// are allocated by binder_alloc_minor for binderfs-created devices, each of
// which gets a context of its own.
//
// Statically initialized so that opening /dev/binder works no matter which
// boot path got there first -- there is no ordering dependency on an init call.
static struct binder_context *binder_minor_context[BINDER_MAX_MINORS] = {
    [DEV_BINDER_MINOR] = &binder_contexts[0],
    [DEV_HWBINDER_MINOR] = &binder_contexts[1],
    [DEV_VNDBINDER_MINOR] = &binder_contexts[2],
};
static const char *binder_minor_name[BINDER_MAX_MINORS] = {
    [DEV_BINDER_MINOR] = "binder",
    [DEV_HWBINDER_MINOR] = "hwbinder",
    [DEV_VNDBINDER_MINOR] = "vndbinder",
};

static int binder_next_debug_id(void) {
    return ++binder_last_debug_id;
}

// ---------------------------------------------------------------------------
// Guest buffer cursors
// ---------------------------------------------------------------------------
//
// BINDER_WRITE_READ hands us two guest buffers: a command stream to consume
// and a return stream to fill. Both are tracked as (base, consumed, size), and
// the consumed counts must be written back even when we bail out partway, so
// userspace can resume exactly where we stopped.

struct binder_cursor {
    guest_addr_t base;
    size_t size;
    size_t consumed;
};

static int binder_cursor_get(struct binder_cursor *c, void *data, size_t size) {
    if (c->consumed + size > c->size)
        return _EINVAL;
    if (user_read(c->base + c->consumed, data, size))
        return _EFAULT;
    c->consumed += size;
    return 0;
}

static int binder_cursor_put(struct binder_cursor *c, const void *data, size_t size) {
    if (c->consumed + size > c->size)
        return _ENOSPC;
    if (user_write(c->base + c->consumed, data, size))
        return _EFAULT;
    c->consumed += size;
    return 0;
}

static int binder_cursor_put_cmd(struct binder_cursor *c, uint32_t cmd) {
    return binder_cursor_put(c, &cmd, sizeof(cmd));
}

static size_t binder_cursor_room(struct binder_cursor *c) {
    return c->size - c->consumed;
}

// ---------------------------------------------------------------------------
// Work queues
// ---------------------------------------------------------------------------

// Wakes every thread of `proc` that is parked waiting for process-level work.
// Called with binder_lock held.
static void binder_wakeup_proc(struct binder_proc *proc) {
    struct binder_thread *thread;
    list_for_each_entry(&proc->threads, thread, proc_link) {
        if (thread->waiting && thread->wait_for_proc_work)
            notify(&thread->wait);
    }
    if (proc->fd != NULL)
        poll_wakeup_trylock(proc->fd, POLL_READ);
}

static void binder_wakeup_thread(struct binder_thread *thread) {
    if (thread->waiting)
        notify(&thread->wait);
    if (thread->proc->fd != NULL)
        poll_wakeup_trylock(thread->proc->fd, POLL_READ);
}

static void binder_enqueue_thread_work(struct binder_thread *thread, struct binder_work *work) {
    list_add_tail(&thread->todo, &work->link);
    binder_wakeup_thread(thread);
}

static void binder_enqueue_proc_work(struct binder_proc *proc, struct binder_work *work) {
    list_add_tail(&proc->todo, &work->link);
    binder_wakeup_proc(proc);
}

// Picks where a transaction should land: a specific thread when we have one
// (a reply, or a reentrant call into a thread already blocked on us),
// otherwise the process queue for any looper to pick up.
static void binder_enqueue_work(struct binder_proc *proc, struct binder_thread *thread,
                                struct binder_work *work) {
    if (thread != NULL && !thread->is_dead)
        binder_enqueue_thread_work(thread, work);
    else
        binder_enqueue_proc_work(proc, work);
}

static struct binder_work *binder_dequeue_work(struct list *list) {
    if (list_empty(list))
        return NULL;
    struct binder_work *work = list_first_entry(list, struct binder_work, link);
    list_remove(&work->link);
    return work;
}

// ---------------------------------------------------------------------------
// Buffer allocator
// ---------------------------------------------------------------------------
//
// A simple first-fit allocator over the mmap'd region. proc->buffers holds
// every chunk, free and allocated, in offset order, so coalescing on free is a
// look at the immediate neighbours.

static void *binder_buffer_kaddr(struct binder_proc *proc, struct binder_buffer *buffer) {
    return (char *) proc->kernel_map + buffer->offset;
}

static binder_uintptr_t binder_buffer_uaddr(struct binder_proc *proc, struct binder_buffer *buffer) {
    return (binder_uintptr_t) (proc->user_base + buffer->offset);
}

static struct binder_buffer *binder_buffer_lookup(struct binder_proc *proc, binder_uintptr_t uaddr) {
    if (proc->kernel_map == NULL)
        return NULL;
    if (uaddr < proc->user_base || uaddr - proc->user_base >= proc->map_size)
        return NULL;
    size_t offset = (size_t) (uaddr - proc->user_base);
    struct binder_buffer *buffer;
    list_for_each_entry(&proc->buffers, buffer, link) {
        if (!buffer->free && buffer->offset == offset)
            return buffer;
    }
    return NULL;
}

static struct binder_buffer *binder_alloc_buf(struct binder_proc *proc, size_t data_size,
                                              size_t offsets_size, size_t extra_buffers_size,
                                              bool is_async) {
    if (proc->kernel_map == NULL)
        return NULL;

    size_t size = BINDER_ALIGN(data_size) + BINDER_ALIGN(offsets_size) +
                  BINDER_ALIGN(extra_buffers_size);
    if (size < data_size || size < offsets_size) // overflow
        return NULL;
    if (size == 0)
        size = 8;
    size = BINDER_ALIGN(size);
    if (size > proc->map_size)
        return NULL;

    // Cap async traffic so a flood of oneway calls can't consume the whole
    // region and stall synchronous ones.
    if (is_async && size > proc->free_async_space)
        return NULL;

    struct binder_buffer *best = NULL;
    struct binder_buffer *buffer;
    list_for_each_entry(&proc->buffers, buffer, link) {
        if (buffer->free && buffer->size >= size) {
            best = buffer;
            break;
        }
    }
    if (best == NULL)
        return NULL;

    // Split the chunk if the remainder is big enough to be useful.
    if (best->size >= size + 16) {
        struct binder_buffer *rest = malloc(sizeof(*rest));
        if (rest == NULL)
            return NULL;
        *rest = (struct binder_buffer) {
            .offset = best->offset + size,
            .size = best->size - size,
            .free = true,
        };
        list_add_after(&best->link, &rest->link);
        best->size = size;
    }

    best->free = false;
    best->data_size = data_size;
    best->offsets_size = offsets_size;
    best->extra_buffers_size = extra_buffers_size;
    best->allow_user_free = false;
    best->async = is_async;
    best->clear_on_free = false;
    best->transaction = NULL;
    best->target_node = NULL;

    if (is_async)
        proc->free_async_space -= size;

    memset(binder_buffer_kaddr(proc, best), 0, best->size);
    return best;
}

static void binder_free_buf_locked(struct binder_proc *proc, struct binder_buffer *buffer) {
    if (buffer->clear_on_free)
        memset(binder_buffer_kaddr(proc, buffer), 0, buffer->size);
    if (buffer->async)
        proc->free_async_space += buffer->size;

    buffer->free = true;
    buffer->transaction = NULL;
    buffer->target_node = NULL;

    // Coalesce with the neighbours.
    struct binder_buffer *next = list_next_entry(buffer, link);
    if (&next->link != &proc->buffers && next->free) {
        buffer->size += next->size;
        list_remove(&next->link);
        free(next);
    }
    struct binder_buffer *prev = list_entry(buffer->link.prev, struct binder_buffer, link);
    if (buffer->link.prev != &proc->buffers && prev->free) {
        prev->size += buffer->size;
        list_remove(&buffer->link);
        free(buffer);
    }
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

static struct binder_node *binder_get_node(struct binder_proc *proc, binder_uintptr_t ptr) {
    struct binder_node *node;
    list_for_each_entry(&proc->nodes, node, proc_link) {
        if (node->ptr == ptr)
            return node;
    }
    return NULL;
}

static struct binder_node *binder_new_node(struct binder_proc *proc, binder_uintptr_t ptr,
                                           binder_uintptr_t cookie, uint32_t flags) {
    struct binder_node *node = binder_get_node(proc, ptr);
    if (node != NULL)
        return node;
    node = malloc(sizeof(*node));
    if (node == NULL)
        return NULL;
    *node = (struct binder_node) {
        .proc = proc,
        .context = proc->context,
        .ptr = ptr,
        .cookie = cookie,
        .flags = flags,
        .accept_fds = (flags & FLAT_BINDER_FLAG_ACCEPTS_FDS) != 0,
        .txn_security_ctx = (flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX) != 0,
        .debug_id = binder_next_debug_id(),
    };
    node->work.type = BINDER_WORK_NODE;
    list_init(&node->refs);
    list_init(&node->async_todo);
    list_add_tail(&proc->nodes, &node->proc_link);
    return node;
}

static void binder_free_node(struct binder_node *node) {
    if (node->proc != NULL)
        list_remove(&node->proc_link);
    if (node->has_work)
        list_remove(&node->work.link);
    free(node);
}

// Tells the owning process about the strong/weak references other processes
// hold, via BR_INCREFS/BR_ACQUIRE/BR_RELEASE/BR_DECREFS. Userspace answers
// with BC_INCREFS_DONE/BC_ACQUIRE_DONE, which is what clears the pending bits.
static void binder_node_refresh_refs(struct binder_node *node) {
    if (node->proc == NULL || node->proc->is_dead)
        return;

    bool want_weak = node->internal_strong_refs > 0 || node->local_weak_refs > 0 ||
                     node->local_strong_refs > 0 || !list_empty(&node->refs);
    bool want_strong = node->internal_strong_refs > 0 || node->local_strong_refs > 0;

    bool need_work = false;
    if (want_weak && !node->has_weak_ref && !node->pending_weak_ref) {
        node->pending_weak_ref = true;
        need_work = true;
    }
    if (want_strong && !node->has_strong_ref && !node->pending_strong_ref) {
        node->pending_strong_ref = true;
        need_work = true;
    }
    if (!want_strong && node->has_strong_ref && !node->pending_strong_ref)
        need_work = true;
    if (!want_weak && node->has_weak_ref && !node->pending_weak_ref)
        need_work = true;

    if (need_work && !node->has_work) {
        node->has_work = true;
        binder_enqueue_proc_work(node->proc, &node->work);
    }
}

// Drops a node once nothing refers to it any more.
static void binder_node_maybe_free(struct binder_node *node) {
    if (node->tmp_refs > 0 || node->internal_strong_refs > 0 || node->local_strong_refs > 0 ||
        node->local_weak_refs > 0 || !list_empty(&node->refs) || node->has_work)
        return;
    if (node->has_strong_ref || node->has_weak_ref || node->pending_strong_ref ||
        node->pending_weak_ref)
        return;
    if (node->context != NULL && node->context->mgr_node == node)
        return;
    binder_free_node(node);
}

// ---------------------------------------------------------------------------
// Refs (handles)
// ---------------------------------------------------------------------------

static struct binder_ref *binder_get_ref(struct binder_proc *proc, uint32_t desc, bool need_strong) {
    struct binder_ref *ref;
    list_for_each_entry(&proc->refs, ref, proc_link) {
        if (ref->desc == desc) {
            if (need_strong && ref->strong == 0)
                return NULL;
            return ref;
        }
    }
    return NULL;
}

static struct binder_ref *binder_get_ref_for_node(struct binder_proc *proc, struct binder_node *node) {
    struct binder_ref *ref;
    list_for_each_entry(&proc->refs, ref, proc_link) {
        if (ref->node == node)
            return ref;
    }

    ref = malloc(sizeof(*ref));
    if (ref == NULL)
        return NULL;
    *ref = (struct binder_ref) { .proc = proc, .node = node };

    // The context manager is always handle 0; everyone else gets the lowest
    // free descriptor from 1 up.
    uint32_t desc = 1;
    if (node->context != NULL && node->context->mgr_node == node) {
        desc = 0;
    } else {
        struct binder_ref *other;
        list_for_each_entry(&proc->refs, other, proc_link) {
            if (other->desc == desc)
                desc++;
            else if (other->desc > desc)
                break;
        }
    }
    ref->desc = desc;

    // Keep proc->refs ordered by desc so the scan above works.
    struct binder_ref *pos;
    bool inserted = false;
    list_for_each_entry(&proc->refs, pos, proc_link) {
        if (pos->desc > desc) {
            list_add_before(&pos->proc_link, &ref->proc_link);
            inserted = true;
            break;
        }
    }
    if (!inserted)
        list_add_tail(&proc->refs, &ref->proc_link);

    list_add_tail(&node->refs, &ref->node_link);
    binder_node_refresh_refs(node);
    return ref;
}

static void binder_delete_ref(struct binder_ref *ref) {
    struct binder_node *node = ref->node;
    list_remove(&ref->proc_link);
    list_remove(&ref->node_link);
    if (ref->death != NULL) {
        list_remove(&ref->death->work.link);
        free(ref->death);
    }
    free(ref);
    if (node != NULL) {
        binder_node_refresh_refs(node);
        binder_node_maybe_free(node);
    }
}

static int binder_inc_ref(struct binder_ref *ref, bool strong) {
    if (strong) {
        if (ref->strong == 0)
            ref->node->internal_strong_refs++;
        ref->strong++;
    } else {
        ref->weak++;
    }
    binder_node_refresh_refs(ref->node);
    return 0;
}

static void binder_dec_ref(struct binder_ref *ref, bool strong) {
    if (strong) {
        if (ref->strong == 0)
            return;
        ref->strong--;
        if (ref->strong == 0 && ref->node != NULL)
            ref->node->internal_strong_refs--;
    } else {
        if (ref->weak == 0)
            return;
        ref->weak--;
    }
    if (ref->strong == 0 && ref->weak == 0) {
        binder_delete_ref(ref);
        return;
    }
    if (ref->node != NULL)
        binder_node_refresh_refs(ref->node);
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

static struct binder_thread *binder_get_thread(struct binder_proc *proc) {
    struct binder_thread *thread;
    list_for_each_entry(&proc->threads, thread, proc_link) {
        if (thread->pid == current->pid && !thread->is_dead)
            return thread;
    }
    thread = malloc(sizeof(*thread));
    if (thread == NULL)
        return NULL;
    *thread = (struct binder_thread) {
        .proc = proc,
        .pid = current->pid,
        .looper = BINDER_LOOPER_STATE_REGISTERED,
    };
    list_init(&thread->todo);
    cond_init(&thread->wait);
    thread->return_error.cmd = BR_OK;
    thread->return_error.work.type = BINDER_WORK_RETURN_ERROR;
    thread->reply_error.cmd = BR_OK;
    thread->reply_error.work.type = BINDER_WORK_RETURN_ERROR;
    list_add_tail(&proc->threads, &thread->proc_link);
    return thread;
}

static void binder_thread_free(struct binder_thread *thread);

// ---------------------------------------------------------------------------
// Releasing a transaction's contents
// ---------------------------------------------------------------------------

static void binder_free_transaction(struct binder_transaction *t);

// Walks the objects a delivered (or abandoned) buffer holds and drops the
// references the transaction took on the receiver's behalf.
static void binder_transaction_buffer_release(struct binder_proc *proc, struct binder_buffer *buffer,
                                              bool failed) {
    if (buffer->target_node != NULL) {
        struct binder_node *node = buffer->target_node;
        if (node->local_strong_refs > 0)
            node->local_strong_refs--;
        binder_node_refresh_refs(node);
        binder_node_maybe_free(node);
        buffer->target_node = NULL;
    }

    if (buffer->offsets_size == 0 || proc->kernel_map == NULL)
        return;

    char *data = binder_buffer_kaddr(proc, buffer);
    binder_size_t *offsets = (binder_size_t *) (data + BINDER_ALIGN(buffer->data_size));
    size_t count = buffer->offsets_size / sizeof(binder_size_t);

    for (size_t i = 0; i < count; i++) {
        size_t off = (size_t) offsets[i];
        if (off + sizeof(struct binder_object_header) > buffer->data_size)
            continue;
        struct binder_object_header *hdr = (struct binder_object_header *) (data + off);
        switch (hdr->type) {
            case BINDER_TYPE_BINDER:
            case BINDER_TYPE_WEAK_BINDER: {
                struct flat_binder_object *fp = (struct flat_binder_object *) hdr;
                struct binder_node *node = binder_get_node(proc, fp->binder);
                if (node == NULL)
                    break;
                if (hdr->type == BINDER_TYPE_BINDER) {
                    if (node->local_strong_refs > 0)
                        node->local_strong_refs--;
                } else if (node->local_weak_refs > 0) {
                    node->local_weak_refs--;
                }
                binder_node_refresh_refs(node);
                binder_node_maybe_free(node);
                break;
            }
            case BINDER_TYPE_HANDLE:
            case BINDER_TYPE_WEAK_HANDLE: {
                struct flat_binder_object *fp = (struct flat_binder_object *) hdr;
                struct binder_ref *ref = binder_get_ref(proc, fp->handle, false);
                if (ref != NULL)
                    binder_dec_ref(ref, hdr->type == BINDER_TYPE_HANDLE);
                break;
            }
            case BINDER_TYPE_FD:
                // The fd number belongs to the receiver once delivered; on a
                // failed delivery the fixup list still owns it and is cleaned
                // up by binder_free_transaction.
                break;
            default:
                break;
        }
    }
    (void) failed;
}

static void binder_release_fd_fixups(struct binder_transaction *t) {
    struct binder_fd_fixup *fixup, *tmp;
    list_for_each_entry_safe(&t->fd_fixups, fixup, tmp, link) {
        list_remove(&fixup->link);
        if (fixup->file != NULL)
            fd_close(fixup->file);
        free(fixup);
    }
}

static void binder_free_transaction(struct binder_transaction *t) {
    binder_release_fd_fixups(t);
    if (t->buffer != NULL) {
        t->buffer->transaction = NULL;
        if (t->to_proc != NULL && !t->buffer->allow_user_free) {
            binder_transaction_buffer_release(t->to_proc, t->buffer, true);
            binder_free_buf_locked(t->to_proc, t->buffer);
        }
        t->buffer = NULL;
    }
    if (t->to_proc != NULL && t->to_proc->outstanding_txns > 0)
        t->to_proc->outstanding_txns--;
    free(t);
}

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------

static void binder_send_failed_reply(struct binder_transaction *t, uint32_t error_code) {
    // Walk back up the transaction stack reporting failure to whoever is still
    // waiting for a reply.
    while (t != NULL) {
        struct binder_thread *target = t->from;
        if (target != NULL) {
            t->from = NULL;
            if (target->reply_error.cmd == BR_OK) {
                target->reply_error.cmd = error_code;
                binder_enqueue_thread_work(target, &target->reply_error.work);
            }
            return;
        }
        struct binder_transaction *next = t->from_parent;
        binder_free_transaction(t);
        t = next;
    }
}

// ---------------------------------------------------------------------------
// Object walking helpers
// ---------------------------------------------------------------------------

static size_t binder_object_size(uint32_t type) {
    switch (type) {
        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER:
        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE:
            return sizeof(struct flat_binder_object);
        case BINDER_TYPE_FD:
            return sizeof(struct binder_fd_object);
        case BINDER_TYPE_FDA:
            return sizeof(struct binder_fd_array_object);
        case BINDER_TYPE_PTR:
            return sizeof(struct binder_buffer_object);
        default:
            return 0;
    }
}

// ---------------------------------------------------------------------------
// The transaction path
// ---------------------------------------------------------------------------

static void binder_transaction(struct binder_proc *proc, struct binder_thread *thread,
                               struct binder_transaction_data *tr, bool reply,
                               size_t extra_buffers_size);

// Removes `t` from `thread`'s stack. Declared up here because the reply path
// needs it before the transaction is freed.
static void binder_pop_transaction_locked(struct binder_thread *thread,
                                          struct binder_transaction *t);

// Finds a thread in `target_proc` that is already blocked waiting for a reply
// from `thread`'s process, so a reentrant call goes back to the thread that is
// logically waiting for it rather than to a fresh looper.
static struct binder_thread *binder_find_reentrant_thread(struct binder_thread *thread,
                                                          struct binder_proc *target_proc) {
    struct binder_transaction *t = thread->transaction_stack;
    while (t != NULL) {
        if (t->from != NULL && t->from->proc == target_proc)
            return t->from;
        t = t->from_parent;
    }
    return NULL;
}

// Translates one object as it moves from the sender's address space into the
// target's buffer. `data` points at the object inside the target buffer (it
// has already been copied there), so edits here land in what the target sees.
static int binder_translate_object(struct binder_proc *proc, struct binder_proc *target_proc,
                                   struct binder_transaction *t, struct binder_object_header *hdr,
                                   struct binder_buffer *buffer, size_t object_offset,
                                   bool target_accepts_fds) {
    switch (hdr->type) {
        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER: {
            struct flat_binder_object *fp = (struct flat_binder_object *) hdr;
            struct binder_node *node = binder_get_node(proc, fp->binder);
            if (node == NULL) {
                node = binder_new_node(proc, fp->binder, fp->cookie, fp->flags);
                if (node == NULL)
                    return _ENOMEM;
            } else if (node->cookie != fp->cookie) {
                return _EINVAL;
            }
            struct binder_ref *ref = binder_get_ref_for_node(target_proc, node);
            if (ref == NULL)
                return _ENOMEM;
            binder_inc_ref(ref, hdr->type == BINDER_TYPE_BINDER);
            hdr->type = hdr->type == BINDER_TYPE_BINDER ? BINDER_TYPE_HANDLE
                                                        : BINDER_TYPE_WEAK_HANDLE;
            fp->binder = 0;
            fp->handle = ref->desc;
            fp->cookie = 0;
            return 0;
        }

        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE: {
            struct flat_binder_object *fp = (struct flat_binder_object *) hdr;
            bool strong = hdr->type == BINDER_TYPE_HANDLE;
            struct binder_ref *ref = binder_get_ref(proc, fp->handle, strong);
            if (ref == NULL || ref->node == NULL)
                return _EINVAL;
            struct binder_node *node = ref->node;
            if (node->proc == target_proc) {
                // Handing an object back to the process that owns it: the
                // target sees its own pointer, not a handle.
                hdr->type = strong ? BINDER_TYPE_BINDER : BINDER_TYPE_WEAK_BINDER;
                fp->binder = node->ptr;
                fp->cookie = node->cookie;
                if (strong)
                    node->local_strong_refs++;
                else
                    node->local_weak_refs++;
                binder_node_refresh_refs(node);
            } else {
                struct binder_ref *target_ref = binder_get_ref_for_node(target_proc, node);
                if (target_ref == NULL)
                    return _ENOMEM;
                binder_inc_ref(target_ref, strong);
                fp->binder = 0;
                fp->handle = target_ref->desc;
                fp->cookie = 0;
            }
            return 0;
        }

        case BINDER_TYPE_FD: {
            struct binder_fd_object *fp = (struct binder_fd_object *) hdr;
            if (!target_accepts_fds)
                return _EPERM;
            struct fd *file = f_get_retain((fd_t) fp->fd);
            if (file == NULL)
                return _EBADF;
            struct binder_fd_fixup *fixup = malloc(sizeof(*fixup));
            if (fixup == NULL) {
                fd_close(file);
                return _ENOMEM;
            }
            // Offset of the fd word inside the buffer, so the receiver can
            // patch in the number it ends up allocating.
            fixup->file = file;
            fixup->offset = object_offset + offsetof(struct binder_fd_object, fd);
            list_add_tail(&t->fd_fixups, &fixup->link);
            fp->fd = (uint32_t) -1;
            return 0;
        }

        case BINDER_TYPE_FDA: {
            struct binder_fd_array_object *fda = (struct binder_fd_array_object *) hdr;
            if (!target_accepts_fds)
                return _EPERM;
            // The fds live inside a BINDER_TYPE_PTR buffer that was already
            // copied in; parent/parent_offset locate them.
            char *data = binder_buffer_kaddr(target_proc, buffer);
            binder_size_t *offsets = (binder_size_t *) (data + BINDER_ALIGN(buffer->data_size));
            size_t count = buffer->offsets_size / sizeof(binder_size_t);
            if (fda->parent >= count)
                return _EINVAL;
            size_t parent_off = (size_t) offsets[fda->parent];
            if (parent_off + sizeof(struct binder_buffer_object) > buffer->data_size)
                return _EINVAL;
            struct binder_buffer_object *parent =
                (struct binder_buffer_object *) (data + parent_off);
            if (parent->hdr.type != BINDER_TYPE_PTR)
                return _EINVAL;

            size_t fd_bytes = (size_t) fda->num_fds * sizeof(uint32_t);
            if (fda->parent_offset > parent->length || fd_bytes > parent->length - fda->parent_offset)
                return _EINVAL;

            // parent->buffer already points at the copy inside the target's
            // region; turn it back into a driver-side pointer.
            size_t parent_data_off = (size_t) (parent->buffer - binder_buffer_uaddr(target_proc, buffer));
            if (parent_data_off + parent->length > buffer->size)
                return _EINVAL;
            uint32_t *fds = (uint32_t *) (data + parent_data_off + fda->parent_offset);

            for (size_t i = 0; i < (size_t) fda->num_fds; i++) {
                struct fd *file = f_get_retain((fd_t) fds[i]);
                if (file == NULL)
                    return _EBADF;
                struct binder_fd_fixup *fixup = malloc(sizeof(*fixup));
                if (fixup == NULL) {
                    fd_close(file);
                    return _ENOMEM;
                }
                fixup->file = file;
                fixup->offset = parent_data_off + (size_t) fda->parent_offset + i * sizeof(uint32_t);
                list_add_tail(&t->fd_fixups, &fixup->link);
                fds[i] = (uint32_t) -1;
            }
            return 0;
        }

        default:
            return _EINVAL;
    }
}

// Copies a BINDER_TYPE_PTR's payload into the buffer's scatter-gather area and
// repoints the object at the copy. `sg_used` tracks how much of that area is
// spoken for.
static int binder_translate_sg_buffer(struct binder_proc *target_proc, struct binder_buffer *buffer,
                                      struct binder_buffer_object *bp, size_t sg_base,
                                      size_t *sg_used) {
    size_t length = (size_t) bp->length;
    size_t aligned = BINDER_ALIGN(length);
    if (aligned < length || *sg_used + aligned > buffer->extra_buffers_size)
        return _EINVAL;

    char *data = binder_buffer_kaddr(target_proc, buffer);
    size_t dest_off = sg_base + *sg_used;
    if (length > 0 && user_read((guest_addr_t) bp->buffer, data + dest_off, length))
        return _EFAULT;

    // If this buffer hangs off a parent, patch the parent's pointer field so
    // the receiver's pointer graph stays internally consistent.
    if (bp->flags & BINDER_BUFFER_FLAG_HAS_PARENT) {
        binder_size_t *offsets = (binder_size_t *) (data + BINDER_ALIGN(buffer->data_size));
        size_t count = buffer->offsets_size / sizeof(binder_size_t);
        if (bp->parent >= count)
            return _EINVAL;
        size_t parent_off = (size_t) offsets[bp->parent];
        if (parent_off + sizeof(struct binder_buffer_object) > buffer->data_size)
            return _EINVAL;
        struct binder_buffer_object *parent = (struct binder_buffer_object *) (data + parent_off);
        if (parent->hdr.type != BINDER_TYPE_PTR)
            return _EINVAL;
        if (bp->parent_offset + sizeof(binder_uintptr_t) > parent->length)
            return _EINVAL;
        size_t parent_data_off =
            (size_t) (parent->buffer - binder_buffer_uaddr(target_proc, buffer));
        if (parent_data_off + parent->length > buffer->size)
            return _EINVAL;
        binder_uintptr_t *slot =
            (binder_uintptr_t *) (data + parent_data_off + (size_t) bp->parent_offset);
        *slot = binder_buffer_uaddr(target_proc, buffer) + dest_off;
    }

    bp->buffer = binder_buffer_uaddr(target_proc, buffer) + dest_off;
    *sg_used += aligned;
    return 0;
}

static void binder_transaction(struct binder_proc *proc, struct binder_thread *thread,
                               struct binder_transaction_data *tr, bool reply,
                               size_t extra_buffers_size) {
    struct binder_proc *target_proc = NULL;
    struct binder_thread *target_thread = NULL;
    struct binder_node *target_node = NULL;
    struct binder_transaction *in_reply_to = NULL;
    uint32_t return_error = BR_FAILED_REPLY;

    if (reply) {
        in_reply_to = thread->transaction_stack;
        if (in_reply_to == NULL || in_reply_to->to_thread != thread)
            goto err_no_context;
        thread->transaction_stack = in_reply_to->to_parent;
        target_thread = in_reply_to->from;
        if (target_thread == NULL || target_thread->transaction_stack != in_reply_to) {
            in_reply_to->from = NULL;
            return_error = BR_DEAD_REPLY;
            goto err_dead;
        }
        target_proc = target_thread->proc;
    } else {
        if (tr->target.handle != 0) {
            struct binder_ref *ref = binder_get_ref(proc, tr->target.handle, true);
            if (ref == NULL || ref->node == NULL)
                goto err_no_context;
            target_node = ref->node;
        } else {
            target_node = proc->context->mgr_node;
            if (target_node == NULL)
                goto err_no_context;
        }
        if (target_node->proc == NULL) {
            return_error = BR_DEAD_REPLY;
            goto err_dead;
        }
        target_proc = target_node->proc;
        if (target_proc->is_dead) {
            return_error = BR_DEAD_REPLY;
            goto err_dead;
        }
        if (target_proc->frozen) {
            return_error = (tr->flags & TF_ONE_WAY) ? BR_TRANSACTION_PENDING_FROZEN
                                                    : BR_FROZEN_REPLY;
            goto err_dead;
        }
        if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack != NULL)
            target_thread = binder_find_reentrant_thread(thread, target_proc);
        target_node->tmp_refs++;
    }

    bool is_async = (tr->flags & TF_ONE_WAY) != 0;

    struct binder_transaction *t = malloc(sizeof(*t));
    if (t == NULL)
        goto err_alloc;
    *t = (struct binder_transaction) {
        .from = is_async ? NULL : thread,
        .to_proc = target_proc,
        .to_thread = target_thread,
        .code = tr->code,
        .flags = tr->flags,
        .sender_pid = current->tgid,
        .sender_euid = current->euid,
        .need_reply = !is_async && !reply,
        .debug_id = binder_next_debug_id(),
    };
    t->work.type = BINDER_WORK_TRANSACTION;
    list_init(&t->fd_fixups);

    // A completion notice for the sender. Embedded work items would be
    // simpler, but a thread can have several in flight.
    struct binder_work *tcomplete = malloc(sizeof(*tcomplete));
    if (tcomplete == NULL) {
        free(t);
        goto err_alloc;
    }
    tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;

    // Validate the caller's sizes before trusting them for arithmetic.
    if (tr->data_size > BINDER_MAX_MAP_SIZE || tr->offsets_size > BINDER_MAX_MAP_SIZE ||
        extra_buffers_size > BINDER_MAX_MAP_SIZE ||
        tr->offsets_size % sizeof(binder_size_t) != 0) {
        free(tcomplete);
        free(t);
        goto err_bad_data;
    }

    // A node registered with FLAT_BINDER_FLAG_TXN_SECURITY_CTX is asking to be
    // told who is calling it. servicemanager is the reason this exists: it
    // decides every add/find against the caller's context, and reading it here
    // is race-free in a way its getpidcon() fallback is not -- by the time it
    // could look up /proc/<pid>/attr/current, the caller may have exited and
    // the pid been reused.
    char secctx[TASK_SECURITY_CONTEXT_MAX];
    size_t secctx_size = 0;
    if (target_node != NULL && target_node->txn_security_ctx) {
        lock(&current->general_lock, 0);
        strcpy(secctx, current->security.current);
        unlock(&current->general_lock);
        if (secctx[0] == '\0')
            strcpy(secctx, TASK_SECURITY_DEFAULT_CONTEXT);
        secctx_size = strlen(secctx) + 1; // the receiver reads a C string
    }

    // The context lives past the scatter-gather area, at the very end of the
    // buffer. Allocating for it here but leaving buffer->extra_buffers_size at
    // the size the sender declared is deliberate: that field is the bound
    // binder_translate_sg_buffer() allocates against, so a sender cannot grow
    // its sg buffers into the context and overwrite it.
    size_t secctx_padded = BINDER_ALIGN(secctx_size);
    struct binder_buffer *buffer = binder_alloc_buf(target_proc, (size_t) tr->data_size,
                                                    (size_t) tr->offsets_size,
                                                    extra_buffers_size + secctx_padded,
                                                    is_async);
    if (buffer == NULL) {
        free(tcomplete);
        free(t);
        goto err_alloc;
    }
    buffer->extra_buffers_size = extra_buffers_size;
    t->buffer = buffer;
    buffer->transaction = t;
    buffer->target_node = target_node;
    buffer->clear_on_free = (tr->flags & TF_CLEAR_BUF) != 0;
    if (target_node != NULL)
        target_node->local_strong_refs++;

    char *data = binder_buffer_kaddr(target_proc, buffer);
    size_t offsets_base = BINDER_ALIGN((size_t) tr->data_size);
    size_t sg_base = offsets_base + BINDER_ALIGN((size_t) tr->offsets_size);

    if (secctx_size > 0) {
        // Straight after the sg area, which ends at sg_base + the declared
        // extra_buffers_size. binder_alloc_buf padded each region to
        // BINDER_ALIGN, and secctx_padded is a multiple of it, so this lands
        // inside the allocation.
        size_t secctx_off = sg_base + BINDER_ALIGN(extra_buffers_size);
        memcpy(data + secctx_off, secctx, secctx_size);
        t->security_ctx = binder_buffer_uaddr(target_proc, buffer) + secctx_off;
    }

    // The single copy: sender's guest memory straight into the target's region.
    if (tr->data_size > 0 &&
        user_read((guest_addr_t) tr->data.ptr.buffer, data, (size_t) tr->data_size))
        goto err_copy;
    if (tr->offsets_size > 0 &&
        user_read((guest_addr_t) tr->data.ptr.offsets, data + offsets_base,
                  (size_t) tr->offsets_size))
        goto err_copy;

    bool target_accepts_fds = reply ? true
                                    : (target_node != NULL && target_node->accept_fds);
    if (tr->flags & TF_ACCEPT_FDS)
        target_accepts_fds = true;

    binder_size_t *offsets = (binder_size_t *) (data + offsets_base);
    size_t count = (size_t) tr->offsets_size / sizeof(binder_size_t);
    size_t sg_used = 0;
    size_t last_end = 0;

    for (size_t i = 0; i < count; i++) {
        size_t off = (size_t) offsets[i];
        // Offsets must be aligned, in range, and strictly ascending -- the
        // ascending check is what stops two objects from overlapping and
        // letting a second pass reinterpret bytes the first pass validated.
        //
        // The alignment is 4, not 8, and this is deliberate: Parcel packs its
        // contents to 4 bytes, so an object only ever inherits the alignment
        // of whatever was written before it. libbinder's `checkService` reply
        // is a single int32 status followed by the binder, putting the object
        // at offset 4. Linux uses IS_ALIGNED(offset, sizeof(u32)) here for the
        // same reason. Requiring the buffer's own 8-byte alignment instead
        // rejects that reply -- and only that kind of reply, which is why it
        // read as "every checkService fails while addService and listServices
        // work".
        if (off % 4 != 0 || off < last_end ||
            off + sizeof(struct binder_object_header) > (size_t) tr->data_size)
            goto err_bad_offset;
        struct binder_object_header *hdr = (struct binder_object_header *) (data + off);
        size_t obj_size = binder_object_size(hdr->type);
        if (obj_size == 0 || off + obj_size > (size_t) tr->data_size)
            goto err_bad_offset;
        last_end = off + obj_size;

        if (hdr->type == BINDER_TYPE_PTR) {
            int err = binder_translate_sg_buffer(target_proc, buffer,
                                                 (struct binder_buffer_object *) hdr, sg_base,
                                                 &sg_used);
            if (err < 0)
                goto err_bad_offset;
        } else {
            int err = binder_translate_object(proc, target_proc, t, hdr, buffer, off,
                                              target_accepts_fds);
            if (err < 0)
                goto err_bad_offset;
        }
    }

    // Hand the receiver the addresses in its own address space.
    t->buffer->data_size = (size_t) tr->data_size;
    t->buffer->offsets_size = (size_t) tr->offsets_size;

    if (reply) {
        binder_pop_transaction_locked(target_thread, in_reply_to);
        binder_enqueue_thread_work(target_thread, &t->work);
        binder_free_transaction(in_reply_to);
    } else if (!is_async) {
        t->need_reply = true;
        t->from_parent = thread->transaction_stack;
        thread->transaction_stack = t;
        // t->to_parent is filled in by the receiver in binder_thread_read,
        // where the receiving thread's stack is the one that matters.
        binder_enqueue_work(target_proc, target_thread, &t->work);
    } else {
        // Only one oneway transaction per node is in flight at a time; the
        // rest queue on the node and are released as each buffer is freed.
        if (target_node != NULL && target_node->has_async_transaction) {
            list_add_tail(&target_node->async_todo, &t->work.link);
        } else {
            if (target_node != NULL)
                target_node->has_async_transaction = true;
            binder_enqueue_proc_work(target_proc, &t->work);
        }
    }
    target_proc->outstanding_txns++;

    if (target_node != NULL && !reply)
        target_node->tmp_refs--;

    binder_enqueue_thread_work(thread, tcomplete);
    if (proc->oneway_spam_detection && is_async &&
        target_proc->free_async_space < (target_proc->map_size / BINDER_ASYNC_FRACTION) / 4)
        tcomplete->type = BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT;
    return;

err_copy:
err_bad_offset:
    binder_release_fd_fixups(t);
    binder_transaction_buffer_release(target_proc, buffer, true);
    binder_free_buf_locked(target_proc, buffer);
    free(tcomplete);
    free(t);
    if (target_node != NULL && !reply)
        target_node->tmp_refs--;
    goto err_report;

err_bad_data:
err_alloc:
    if (target_node != NULL && !reply)
        target_node->tmp_refs--;
    goto err_report;

err_dead:
err_no_context:
err_report:
    if (reply && in_reply_to != NULL) {
        // We already popped it; hand the failure back down the stack.
        binder_send_failed_reply(in_reply_to, return_error);
    } else if (thread->return_error.cmd == BR_OK) {
        thread->return_error.cmd = return_error;
        binder_enqueue_thread_work(thread, &thread->return_error.work);
    }
}

// Removes `t` from `thread`'s stack. Split out because the reply path needs it
// before the transaction is freed.
static void binder_pop_transaction_locked(struct binder_thread *thread,
                                          struct binder_transaction *t) {
    if (thread != NULL && thread->transaction_stack == t)
        thread->transaction_stack = t->to_parent;
    t->from = NULL;
}

// ---------------------------------------------------------------------------
// BC_ command stream
// ---------------------------------------------------------------------------

static int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
                               struct binder_cursor *cursor) {
    while (binder_cursor_room(cursor) >= sizeof(uint32_t)) {
        if (thread->return_error.cmd != BR_OK)
            break;

        uint32_t cmd;
        int err = binder_cursor_get(cursor, &cmd, sizeof(cmd));
        if (err < 0)
            return err;

        switch (cmd) {
            case BC_INCREFS:
            case BC_ACQUIRE:
            case BC_RELEASE:
            case BC_DECREFS: {
                uint32_t target;
                err = binder_cursor_get(cursor, &target, sizeof(target));
                if (err < 0)
                    return err;
                bool strong = cmd == BC_ACQUIRE || cmd == BC_RELEASE;
                bool increment = cmd == BC_INCREFS || cmd == BC_ACQUIRE;

                if (target == 0 && increment && proc->context->mgr_node != NULL) {
                    // Bootstrapping a reference to the context manager.
                    struct binder_ref *ref =
                        binder_get_ref_for_node(proc, proc->context->mgr_node);
                    if (ref == NULL)
                        return _ENOMEM;
                    binder_inc_ref(ref, strong);
                    break;
                }
                struct binder_ref *ref = binder_get_ref(proc, target, false);
                if (ref == NULL)
                    break; // Linux logs and ignores a bogus handle here
                if (increment)
                    binder_inc_ref(ref, strong);
                else
                    binder_dec_ref(ref, strong);
                break;
            }

            case BC_INCREFS_DONE:
            case BC_ACQUIRE_DONE: {
                struct binder_ptr_cookie pc;
                err = binder_cursor_get(cursor, &pc, sizeof(pc));
                if (err < 0)
                    return err;
                struct binder_node *node = binder_get_node(proc, pc.ptr);
                if (node == NULL || node->cookie != pc.cookie)
                    break;
                if (cmd == BC_ACQUIRE_DONE) {
                    node->pending_strong_ref = false;
                    node->has_strong_ref = true;
                } else {
                    node->pending_weak_ref = false;
                    node->has_weak_ref = true;
                }
                binder_node_refresh_refs(node);
                binder_node_maybe_free(node);
                break;
            }

            case BC_FREE_BUFFER: {
                binder_uintptr_t data_ptr;
                err = binder_cursor_get(cursor, &data_ptr, sizeof(data_ptr));
                if (err < 0)
                    return err;
                struct binder_buffer *buffer = binder_buffer_lookup(proc, data_ptr);
                if (buffer == NULL || !buffer->allow_user_free)
                    break;

                struct binder_node *node = buffer->target_node;
                bool was_async = buffer->async;
                buffer->allow_user_free = false;
                if (buffer->transaction != NULL) {
                    buffer->transaction->buffer = NULL;
                    buffer->transaction = NULL;
                }
                binder_transaction_buffer_release(proc, buffer, false);
                binder_free_buf_locked(proc, buffer);

                // Releasing an async buffer lets the next queued oneway
                // transaction for that node through.
                if (was_async && node != NULL) {
                    if (!list_empty(&node->async_todo)) {
                        struct binder_work *w = binder_dequeue_work(&node->async_todo);
                        binder_enqueue_proc_work(proc, w);
                    } else {
                        node->has_async_transaction = false;
                    }
                }
                break;
            }

            case BC_TRANSACTION:
            case BC_REPLY: {
                struct binder_transaction_data tr;
                err = binder_cursor_get(cursor, &tr, sizeof(tr));
                if (err < 0)
                    return err;
                binder_transaction(proc, thread, &tr, cmd == BC_REPLY, 0);
                break;
            }

            case BC_TRANSACTION_SG:
            case BC_REPLY_SG: {
                struct binder_transaction_data_sg tr;
                err = binder_cursor_get(cursor, &tr, sizeof(tr));
                if (err < 0)
                    return err;
                binder_transaction(proc, thread, &tr.transaction_data, cmd == BC_REPLY_SG,
                                   (size_t) tr.buffers_size);
                break;
            }

            case BC_REGISTER_LOOPER:
                if (proc->requested_threads == 0) {
                    thread->looper |= BINDER_LOOPER_STATE_INVALID;
                } else {
                    proc->requested_threads--;
                    proc->requested_threads_started++;
                    thread->looper |= BINDER_LOOPER_STATE_REGISTERED;
                }
                break;

            case BC_ENTER_LOOPER:
                if (thread->looper & BINDER_LOOPER_STATE_REGISTERED)
                    thread->looper &= ~BINDER_LOOPER_STATE_REGISTERED;
                thread->looper |= BINDER_LOOPER_STATE_ENTERED;
                break;

            case BC_EXIT_LOOPER:
                thread->looper |= BINDER_LOOPER_STATE_EXITED;
                break;

            case BC_REQUEST_DEATH_NOTIFICATION:
            case BC_CLEAR_DEATH_NOTIFICATION: {
                struct binder_handle_cookie hc;
                err = binder_cursor_get(cursor, &hc, sizeof(hc));
                if (err < 0)
                    return err;
                struct binder_ref *ref = binder_get_ref(proc, hc.handle, false);
                if (ref == NULL)
                    break;

                if (cmd == BC_REQUEST_DEATH_NOTIFICATION) {
                    if (ref->death != NULL)
                        break; // already registered
                    struct binder_ref_death *death = malloc(sizeof(*death));
                    if (death == NULL)
                        return _ENOMEM;
                    death->work.type = BINDER_WORK_DEAD_BINDER;
                    death->cookie = hc.cookie;
                    ref->death = death;
                    // Registering against an already-dead node fires straight
                    // away, which is what libbinder relies on to avoid a race
                    // between linkToDeath and the peer's exit.
                    if (ref->node == NULL || ref->node->proc == NULL)
                        binder_enqueue_thread_work(thread, &death->work);
                } else {
                    struct binder_ref_death *death = ref->death;
                    if (death == NULL || death->cookie != hc.cookie)
                        break;
                    ref->death = NULL;
                    death->work.type = BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
                    binder_enqueue_thread_work(thread, &death->work);
                }
                break;
            }

            case BC_DEAD_BINDER_DONE: {
                binder_uintptr_t cookie;
                err = binder_cursor_get(cursor, &cookie, sizeof(cookie));
                if (err < 0)
                    return err;
                struct binder_ref_death *death, *tmp;
                list_for_each_entry_safe(&proc->delivered_death, death, tmp, work.link) {
                    if (death->cookie == cookie) {
                        list_remove(&death->work.link);
                        free(death);
                        break;
                    }
                }
                break;
            }

            case BC_ATTEMPT_ACQUIRE:
            case BC_ACQUIRE_RESULT:
                // Removed from the protocol years ago; Linux returns EINVAL.
                return _EINVAL;

            default:
                return _EINVAL;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// BR_ return stream
// ---------------------------------------------------------------------------

static bool binder_has_work(struct binder_thread *thread, bool do_proc_work) {
    if (!list_empty(&thread->todo))
        return true;
    if (thread->return_error.cmd != BR_OK)
        return true;
    if (do_proc_work && !list_empty(&thread->proc->todo))
        return true;
    return false;
}

// Delivers the file descriptors a transaction carries. Runs in the receiving
// task's context, which is exactly why the fd numbers are allocated here and
// not at send time.
static int binder_apply_fd_fixups(struct binder_proc *proc, struct binder_transaction *t) {
    struct binder_fd_fixup *fixup, *tmp;
    int err = 0;

    list_for_each_entry_safe(&t->fd_fixups, fixup, tmp, link) {
        if (err < 0)
            break;
        fd_t installed = f_install(fixup->file, 0); // steals the reference
        fixup->file = NULL;
        if (installed < 0) {
            err = installed;
            break;
        }
        uint32_t value = (uint32_t) installed;
        memcpy((char *) binder_buffer_kaddr(proc, t->buffer) + fixup->offset, &value,
               sizeof(value));
        list_remove(&fixup->link);
        free(fixup);
    }

    if (err < 0) {
        // Undo the ones that made it in, so a partial delivery doesn't leave
        // stray descriptors in the receiver.
        binder_release_fd_fixups(t);
        return err;
    }
    return 0;
}

static int binder_thread_read(struct binder_proc *proc, struct binder_thread *thread,
                              struct binder_cursor *cursor, bool non_block) {
    int err;

    if (cursor->consumed == 0) {
        err = binder_cursor_put_cmd(cursor, BR_NOOP);
        if (err < 0)
            return err;
    }

    for (;;) {
        // A thread only takes process-level work when it isn't in the middle
        // of a transaction of its own; otherwise it must stay available to
        // handle the reply it is waiting for.
        bool do_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo);
        thread->wait_for_proc_work = do_proc_work;

        if (do_proc_work) {
            // Ask for another looper if we're about to run out.
            if (proc->requested_threads == 0 && proc->ready_threads == 0 &&
                proc->requested_threads_started < proc->max_threads &&
                (thread->looper & (BINDER_LOOPER_STATE_REGISTERED | BINDER_LOOPER_STATE_ENTERED)) &&
                binder_cursor_room(cursor) >= sizeof(uint32_t)) {
                proc->requested_threads++;
                err = binder_cursor_put_cmd(cursor, BR_SPAWN_LOOPER);
                if (err < 0)
                    return err;
            }
        }

        struct binder_work *work = NULL;
        if (thread->return_error.cmd != BR_OK) {
            work = &thread->return_error.work;
            list_remove(&work->link);
        } else if (!list_empty(&thread->todo)) {
            work = binder_dequeue_work(&thread->todo);
        } else if (do_proc_work) {
            work = binder_dequeue_work(&proc->todo);
        }

        if (work == NULL) {
            if (cursor->consumed > sizeof(uint32_t) || non_block)
                return 0;
            // Nothing to do: park until someone queues work for us.
            //
            // wait_for drops binder_lock while blocked, so the thread (and the
            // process) can be torn down underneath us -- by BINDER_THREAD_EXIT
            // on another task, or by the last close of the fd. tmp_ref tells
            // binder_thread_release to leave the structure allocated for us to
            // find is_dead on, and hands us the job of freeing it.
            thread->waiting = true;
            thread->tmp_ref++;
            thread->looper |= BINDER_LOOPER_STATE_WAITING;
            if (do_proc_work)
                proc->ready_threads++;
            err = wait_for(&thread->wait, &binder_lock, NULL);
            if (do_proc_work && proc->ready_threads > 0)
                proc->ready_threads--;
            thread->looper &= ~BINDER_LOOPER_STATE_WAITING;
            thread->waiting = false;
            thread->tmp_ref--;

            if (thread->is_dead) {
                if (thread->tmp_ref == 0) {
                    cond_destroy(&thread->wait);
                    free(thread);
                }
                return _EBADF;
            }
            if (err < 0)
                return err; // _EINTR
            continue;
        }

        switch (work->type) {
            case BINDER_WORK_RETURN_ERROR: {
                struct binder_error *e = list_entry(work, struct binder_error, work);
                uint32_t cmd = e->cmd;
                e->cmd = BR_OK;
                if (binder_cursor_room(cursor) < sizeof(cmd)) {
                    e->cmd = cmd;
                    binder_enqueue_thread_work(thread, work);
                    return 0;
                }
                err = binder_cursor_put_cmd(cursor, cmd);
                if (err < 0)
                    return err;
                break;
            }

            case BINDER_WORK_TRANSACTION_COMPLETE:
            case BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT: {
                uint32_t cmd = work->type == BINDER_WORK_TRANSACTION_COMPLETE
                                   ? BR_TRANSACTION_COMPLETE
                                   : BR_ONEWAY_SPAM_SUSPECT;
                if (binder_cursor_room(cursor) < sizeof(cmd)) {
                    binder_enqueue_thread_work(thread, work);
                    return 0;
                }
                err = binder_cursor_put_cmd(cursor, cmd);
                free(work);
                if (err < 0)
                    return err;
                break;
            }

            case BINDER_WORK_TRANSACTION_PENDING: {
                if (binder_cursor_room(cursor) < sizeof(uint32_t)) {
                    binder_enqueue_thread_work(thread, work);
                    return 0;
                }
                err = binder_cursor_put_cmd(cursor, BR_TRANSACTION_PENDING_FROZEN);
                free(work);
                if (err < 0)
                    return err;
                break;
            }

            case BINDER_WORK_NODE: {
                struct binder_node *node = list_entry(work, struct binder_node, work);
                node->has_work = false;

                struct binder_ptr_cookie pc = { .ptr = node->ptr, .cookie = node->cookie };
                bool want_weak = node->internal_strong_refs > 0 || node->local_weak_refs > 0 ||
                                 node->local_strong_refs > 0 || !list_empty(&node->refs);
                bool want_strong = node->internal_strong_refs > 0 || node->local_strong_refs > 0;

                // Order matters: weak up, strong up, strong down, weak down.
                uint32_t cmds[4];
                int ncmds = 0;
                if (node->pending_weak_ref)
                    cmds[ncmds++] = BR_INCREFS;
                if (node->pending_strong_ref)
                    cmds[ncmds++] = BR_ACQUIRE;
                if (!want_strong && node->has_strong_ref && !node->pending_strong_ref) {
                    cmds[ncmds++] = BR_RELEASE;
                    node->has_strong_ref = false;
                }
                if (!want_weak && node->has_weak_ref && !node->pending_weak_ref) {
                    cmds[ncmds++] = BR_DECREFS;
                    node->has_weak_ref = false;
                }

                if (binder_cursor_room(cursor) < ncmds * (sizeof(uint32_t) + sizeof(pc))) {
                    node->has_work = true;
                    binder_enqueue_proc_work(proc, work);
                    return 0;
                }
                for (int i = 0; i < ncmds; i++) {
                    err = binder_cursor_put_cmd(cursor, cmds[i]);
                    if (err < 0)
                        return err;
                    err = binder_cursor_put(cursor, &pc, sizeof(pc));
                    if (err < 0)
                        return err;
                }
                binder_node_maybe_free(node);
                break;
            }

            case BINDER_WORK_DEAD_BINDER:
            case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
            case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
                struct binder_ref_death *death = list_entry(work, struct binder_ref_death, work);
                bool is_clear = work->type == BINDER_WORK_CLEAR_DEATH_NOTIFICATION;
                uint32_t cmd = is_clear ? BR_CLEAR_DEATH_NOTIFICATION_DONE : BR_DEAD_BINDER;
                if (binder_cursor_room(cursor) < sizeof(cmd) + sizeof(death->cookie)) {
                    binder_enqueue_thread_work(thread, work);
                    return 0;
                }
                err = binder_cursor_put_cmd(cursor, cmd);
                if (err < 0)
                    return err;
                binder_uintptr_t cookie = death->cookie;
                err = binder_cursor_put(cursor, &cookie, sizeof(cookie));
                if (err < 0)
                    return err;

                if (is_clear) {
                    free(death);
                } else {
                    // Held until BC_DEAD_BINDER_DONE so the cookie stays valid
                    // while userspace processes the notification.
                    list_add_tail(&proc->delivered_death, &death->work.link);
                }
                break;
            }

            case BINDER_WORK_TRANSACTION: {
                struct binder_transaction *t = list_entry(work, struct binder_transaction, work);
                struct binder_node *target_node = t->buffer != NULL ? t->buffer->target_node : NULL;

                struct binder_transaction_data tr = {
                    .code = t->code,
                    .flags = t->flags,
                    .sender_pid = t->sender_pid,
                    .sender_euid = t->sender_euid,
                };
                uint32_t cmd;
                if (target_node != NULL) {
                    tr.target.ptr = target_node->ptr;
                    tr.cookie = target_node->cookie;
                    // The sender's context, if the node asked to be told.
                    // BR_TRANSACTION_SEC_CTX carries a wider struct, so the
                    // command code is what tells the receiver how much to read.
                    cmd = t->security_ctx != 0 ? BR_TRANSACTION_SEC_CTX : BR_TRANSACTION;
                } else {
                    tr.target.ptr = 0;
                    tr.cookie = 0;
                    cmd = BR_REPLY;
                }

                size_t tr_size = cmd == BR_TRANSACTION_SEC_CTX
                    ? sizeof(struct binder_transaction_data_secctx) : sizeof(tr);
                if (binder_cursor_room(cursor) < sizeof(cmd) + tr_size) {
                    binder_enqueue_thread_work(thread, work);
                    return 0;
                }

                if (t->buffer != NULL) {
                    err = binder_apply_fd_fixups(proc, t);
                    if (err < 0) {
                        // Report the failure to both ends rather than handing
                        // over a buffer with holes in it.
                        uint32_t fail = BR_FAILED_REPLY;
                        binder_transaction_buffer_release(proc, t->buffer, true);
                        binder_free_buf_locked(proc, t->buffer);
                        t->buffer = NULL;
                        if (t->from != NULL)
                            binder_send_failed_reply(t, fail);
                        else
                            binder_free_transaction(t);
                        if (binder_cursor_room(cursor) >= sizeof(fail)) {
                            err = binder_cursor_put_cmd(cursor, fail);
                            if (err < 0)
                                return err;
                        }
                        break;
                    }

                    tr.data_size = t->buffer->data_size;
                    tr.offsets_size = t->buffer->offsets_size;
                    tr.data.ptr.buffer = binder_buffer_uaddr(proc, t->buffer);
                    tr.data.ptr.offsets =
                        tr.data.ptr.buffer + BINDER_ALIGN(t->buffer->data_size);
                    t->buffer->allow_user_free = true;
                }

                err = binder_cursor_put_cmd(cursor, cmd);
                if (err < 0)
                    return err;
                if (cmd == BR_TRANSACTION_SEC_CTX) {
                    struct binder_transaction_data_secctx trs = {
                        .transaction_data = tr,
                        .secctx = t->security_ctx,
                    };
                    err = binder_cursor_put(cursor, &trs, sizeof(trs));
                } else {
                    err = binder_cursor_put(cursor, &tr, sizeof(tr));
                }
                if (err < 0)
                    return err;

                if (t->need_reply) {
                    // Push onto this thread's stack so the eventual BC_REPLY
                    // can find its way back.
                    t->to_parent = thread->transaction_stack;
                    t->to_thread = thread;
                    thread->transaction_stack = t;
                } else {
                    if (t->buffer != NULL)
                        t->buffer->transaction = NULL;
                    binder_free_transaction(t);
                }
                return 0; // one transaction per read, like Linux
            }

            default:
                break;
        }

        if (binder_cursor_room(cursor) < sizeof(uint32_t))
            return 0;
    }
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

static void binder_thread_release(struct binder_proc *proc, struct binder_thread *thread) {
    if (thread->is_dead)
        return; // already torn down; a parked reader still owns the memory
    thread->is_dead = true;

    // Fail every transaction this thread was part of, in either direction.
    struct binder_transaction *t = thread->transaction_stack;
    while (t != NULL) {
        struct binder_transaction *next;
        if (t->to_thread == thread) {
            next = t->to_parent;
            t->to_thread = NULL;
            binder_send_failed_reply(t, BR_DEAD_REPLY);
        } else {
            next = t->from_parent;
            t->from = NULL;
        }
        t = next;
    }
    thread->transaction_stack = NULL;

    struct binder_work *work;
    while ((work = binder_dequeue_work(&thread->todo)) != NULL) {
        switch (work->type) {
            case BINDER_WORK_TRANSACTION: {
                struct binder_transaction *tr = list_entry(work, struct binder_transaction, work);
                binder_send_failed_reply(tr, BR_DEAD_REPLY);
                break;
            }
            case BINDER_WORK_TRANSACTION_COMPLETE:
            case BINDER_WORK_TRANSACTION_PENDING:
            case BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT:
                free(work);
                break;
            case BINDER_WORK_RETURN_ERROR:
                break; // embedded in the thread
            default:
                break;
        }
    }

    list_remove(&thread->proc_link);
    list_init(&thread->proc_link);
    notify(&thread->wait);

    // A thread parked in binder_thread_read holds a tmp_ref; it frees the
    // structure once it wakes and sees is_dead.
    if (thread->tmp_ref == 0) {
        cond_destroy(&thread->wait);
        free(thread);
    }
    (void) proc;
}

static void binder_thread_free(struct binder_thread *thread) {
    binder_thread_release(thread->proc, thread);
}

static void binder_deferred_release(struct binder_proc *proc) {
    proc->is_dead = true;

    if (proc->context->mgr_node != NULL && proc->context->mgr_node->proc == proc) {
        proc->context->mgr_node = NULL;
        proc->context->mgr_uid_valid = false;
    }

    struct binder_thread *thread, *thread_tmp;
    list_for_each_entry_safe(&proc->threads, thread, thread_tmp, proc_link) {
        binder_thread_release(proc, thread);
    }

    // Every process holding a handle on one of our nodes learns the object is
    // gone -- this is what makes linkToDeath work.
    struct binder_node *node, *node_tmp;
    list_for_each_entry_safe(&proc->nodes, node, node_tmp, proc_link) {
        list_remove(&node->proc_link);
        node->proc = NULL;

        struct binder_ref *ref;
        list_for_each_entry(&node->refs, ref, node_link) {
            if (ref->death == NULL)
                continue;
            ref->death->work.type = BINDER_WORK_DEAD_BINDER;
            binder_enqueue_proc_work(ref->proc, &ref->death->work);
            ref->death = NULL;
        }

        if (list_empty(&node->refs)) {
            if (node->has_work)
                list_remove(&node->work.link);
            free(node);
        } else {
            // Kept alive as a tombstone until the last handle goes away.
            node->has_work = false;
            list_init(&node->proc_link);
        }
    }

    struct binder_ref *ref, *ref_tmp;
    list_for_each_entry_safe(&proc->refs, ref, ref_tmp, proc_link) {
        struct binder_node *target = ref->node;
        list_remove(&ref->proc_link);
        list_remove(&ref->node_link);
        if (ref->death != NULL) {
            list_remove(&ref->death->work.link);
            free(ref->death);
        }
        free(ref);
        if (target != NULL) {
            if (target->proc != NULL) {
                if (target->internal_strong_refs > 0)
                    target->internal_strong_refs--;
                binder_node_refresh_refs(target);
                binder_node_maybe_free(target);
            } else if (list_empty(&target->refs)) {
                free(target); // last handle on a dead node
            }
        }
    }

    struct binder_work *work;
    while ((work = binder_dequeue_work(&proc->todo)) != NULL) {
        switch (work->type) {
            case BINDER_WORK_TRANSACTION: {
                struct binder_transaction *t = list_entry(work, struct binder_transaction, work);
                binder_send_failed_reply(t, BR_DEAD_REPLY);
                break;
            }
            case BINDER_WORK_TRANSACTION_COMPLETE:
            case BINDER_WORK_TRANSACTION_PENDING:
            case BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT:
                free(work);
                break;
            default:
                break;
        }
    }

    struct binder_ref_death *death, *death_tmp;
    list_for_each_entry_safe(&proc->delivered_death, death, death_tmp, work.link) {
        list_remove(&death->work.link);
        free(death);
    }

    struct binder_buffer *buffer, *buffer_tmp;
    list_for_each_entry_safe(&proc->buffers, buffer, buffer_tmp, link) {
        list_remove(&buffer->link);
        free(buffer);
    }

    if (proc->kernel_map != NULL)
        munmap(proc->kernel_map, proc->map_size);
    if (proc->host_fd >= 0)
        close(proc->host_fd);

    list_remove(&proc->link);
    atomic_fetch_sub(&binder_live_procs, 1);
    free(proc);
}

// ---------------------------------------------------------------------------
// fd operations
// ---------------------------------------------------------------------------

static struct binder_proc *binder_proc_get(struct fd *fd) {
    return fd->data;
}

static int binder_open(int UNUSED(major), int minor, struct fd *fd) {
    if (minor < 0 || minor >= BINDER_MAX_MINORS)
        return _ENODEV;
    // binderfs's control node shares our major but is not a binder endpoint:
    // it only answers BINDER_CTL_ADD, and has no proc, mapping or threads.
    if (minor == DEV_BINDER_CONTROL_MINOR) {
        fd->ops = &binderfs_control_ops;
        return 0;
    }
    struct binder_context *context = binder_minor_context[minor];
    if (context == NULL)
        return _ENODEV;

    struct binder_proc *proc = malloc(sizeof(*proc));
    if (proc == NULL)
        return _ENOMEM;
    *proc = (struct binder_proc) {
        .pid = current->tgid,
        .context = context,
        .fd = fd,
        .host_fd = -1,
        .max_threads = 15,
    };
    list_init(&proc->buffers);
    list_init(&proc->threads);
    list_init(&proc->nodes);
    list_init(&proc->refs);
    list_init(&proc->todo);
    list_init(&proc->delivered_death);

    lock(&binder_lock, 0);
    list_add_tail(&binder_procs, &proc->link);
    atomic_fetch_add(&binder_live_procs, 1);
    unlock(&binder_lock);

    fd->data = proc;
    return 0;
}

static int binder_close(struct fd *fd) {
    struct binder_proc *proc = binder_proc_get(fd);
    if (proc == NULL)
        return 0;
    lock(&binder_lock, 0);
    proc->fd = NULL;
    binder_deferred_release(proc);
    unlock(&binder_lock);
    fd->data = NULL;
    return 0;
}

static int binder_mmap(struct fd *fd, struct mem *mem, page_t start, pages_t pages, off_t offset,
                       int prot, int UNUSED(flags)) {
    struct binder_proc *proc = binder_proc_get(fd);
    if (proc == NULL)
        return _EINVAL;
    // Linux refuses a writable binder mapping outright: userspace reads
    // transaction data, the driver is the only writer.
    if (prot & P_WRITE)
        return _EPERM;
    if (offset != 0)
        return _EINVAL;

    size_t size = (size_t) pages << PAGE_BITS;
    if (size == 0)
        return _EINVAL;
    if (size > BINDER_MAX_MAP_SIZE)
        size = BINDER_MAX_MAP_SIZE;

    lock(&binder_lock, 0);
    if (proc->kernel_map != NULL) {
        unlock(&binder_lock);
        return _EBUSY; // one mapping per open, as on Linux
    }

    int host_fd = host_unlinked_tmpfd();
    if (host_fd < 0) {
        unlock(&binder_lock);
        return host_fd;
    }
    if (ftruncate(host_fd, size) < 0) {
        int err = errno_map();
        close(host_fd);
        unlock(&binder_lock);
        return err;
    }

    // The driver's own read-write view of the region.
    void *kernel_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, host_fd, 0);
    if (kernel_map == MAP_FAILED) {
        int err = errno_map();
        close(host_fd);
        unlock(&binder_lock);
        return err;
    }

    // The guest's view. It asked for MAP_PRIVATE (libbinder always does), but
    // a private mapping would copy-on-write away from the pages the driver
    // writes into. Since the guest mapping is read-only anyway, mapping it
    // shared is observationally identical and is what makes the "single copy"
    // visible on both sides -- the same thing Linux achieves by inserting its
    // own pages into the vma.
    int err = host_fd_mmap(host_fd, mem, start, pages, 0, P_READ, MMAP_SHARED);
    if (err < 0) {
        munmap(kernel_map, size);
        close(host_fd);
        unlock(&binder_lock);
        return err;
    }

    proc->host_fd = host_fd;
    proc->kernel_map = kernel_map;
    proc->user_base = (guest_addr_t) start << PAGE_BITS;
    proc->map_size = size;
    proc->free_async_space = size / BINDER_ASYNC_FRACTION;

    struct binder_buffer *buffer = malloc(sizeof(*buffer));
    if (buffer == NULL) {
        munmap(kernel_map, size);
        close(host_fd);
        proc->kernel_map = NULL;
        proc->host_fd = -1;
        unlock(&binder_lock);
        return _ENOMEM;
    }
    *buffer = (struct binder_buffer) { .offset = 0, .size = size, .free = true };
    list_add_tail(&proc->buffers, &buffer->link);

    unlock(&binder_lock);
    return 0;
}

static int binder_poll(struct fd *fd) {
    struct binder_proc *proc = binder_proc_get(fd);
    if (proc == NULL)
        return POLL_ERR;
    int events = 0;
    lock(&binder_lock, 0);
    struct binder_thread *thread = binder_get_thread(proc);
    if (thread != NULL) {
        thread->looper |= BINDER_LOOPER_STATE_POLL;
        bool do_proc_work = thread->transaction_stack == NULL && list_empty(&thread->todo);
        if (binder_has_work(thread, do_proc_work))
            events |= POLL_READ;
    }
    unlock(&binder_lock);
    return events;
}

static int binder_do_write_read(struct binder_proc *proc, struct binder_thread *thread,
                                struct binder_write_read *bwr, bool non_block) {
    int ret = 0;

    if (bwr->write_size > 0) {
        struct binder_cursor cursor = {
            .base = (guest_addr_t) bwr->write_buffer,
            .size = (size_t) bwr->write_size,
            .consumed = (size_t) bwr->write_consumed,
        };
        if (cursor.consumed > cursor.size)
            return _EINVAL;
        ret = binder_thread_write(proc, thread, &cursor);
        bwr->write_consumed = cursor.consumed;
        if (ret < 0) {
            bwr->read_consumed = 0;
            return ret;
        }
    }

    if (bwr->read_size > 0) {
        struct binder_cursor cursor = {
            .base = (guest_addr_t) bwr->read_buffer,
            .size = (size_t) bwr->read_size,
            .consumed = (size_t) bwr->read_consumed,
        };
        if (cursor.consumed > cursor.size)
            return _EINVAL;
        ret = binder_thread_read(proc, thread, &cursor, non_block);
        bwr->read_consumed = cursor.consumed;
        // A partially-filled read buffer is still a successful read; only
        // report the error when we produced nothing at all.
        if (ret < 0 && cursor.consumed > sizeof(uint32_t))
            ret = 0;
        if (!list_empty(&proc->todo))
            binder_wakeup_proc(proc);
    }

    return ret;
}

static ssize_t binder_ioctl_size(int cmd) {
    switch (cmd) {
        case BINDER_WRITE_READ_:
            return sizeof(struct binder_write_read);
        case BINDER_SET_MAX_THREADS_:
        case BINDER_ENABLE_ONEWAY_SPAM_DETECTION_:
            return sizeof(uint32_t);
        case BINDER_SET_IDLE_TIMEOUT_:
            return sizeof(int64_t);
        case BINDER_SET_IDLE_PRIORITY_:
        case BINDER_SET_CONTEXT_MGR_:
        case BINDER_THREAD_EXIT_:
            return sizeof(int32_t);
        case BINDER_VERSION_:
            return sizeof(struct binder_version);
        case BINDER_GET_NODE_DEBUG_INFO_:
            return sizeof(struct binder_node_debug_info);
        case BINDER_GET_NODE_INFO_FOR_REF_:
            return sizeof(struct binder_node_info_for_ref);
        case BINDER_SET_CONTEXT_MGR_EXT_:
            return sizeof(struct flat_binder_object);
        case BINDER_FREEZE_:
            return sizeof(struct binder_freeze_info);
        case BINDER_GET_FROZEN_INFO_:
            return sizeof(struct binder_frozen_status_info);
        default:
            return -1;
    }
}

static int binder_set_context_mgr(struct binder_proc *proc, binder_uintptr_t ptr,
                                  binder_uintptr_t cookie, uint32_t flags) {
    struct binder_context *context = proc->context;
    if (context->mgr_node != NULL)
        return _EBUSY;
    if (context->mgr_uid_valid) {
        if (context->mgr_uid != current->euid)
            return _EPERM;
    } else {
        context->mgr_uid = current->euid;
        context->mgr_uid_valid = true;
    }

    struct binder_node *node = binder_new_node(proc, ptr, cookie, flags);
    if (node == NULL)
        return _ENOMEM;
    node->local_weak_refs++;
    node->local_strong_refs++;
    node->has_strong_ref = true;
    node->has_weak_ref = true;
    context->mgr_node = node;
    return 0;
}

static int binder_ioctl(struct fd *fd, int cmd, void *arg) {
    struct binder_proc *proc = binder_proc_get(fd);
    if (proc == NULL)
        return _EINVAL;

    bool non_block = (fd_getflags(fd) & O_NONBLOCK_) != 0;

    lock(&binder_lock, 0);
    if (proc->is_dead) {
        unlock(&binder_lock);
        return _EBADF;
    }

    struct binder_thread *thread = binder_get_thread(proc);
    if (thread == NULL) {
        unlock(&binder_lock);
        return _ENOMEM;
    }

    int ret;
    switch (cmd) {
        case BINDER_VERSION_: {
            struct binder_version *ver = arg;
            ver->protocol_version = BINDER_CURRENT_PROTOCOL_VERSION;
            ret = 0;
            break;
        }

        case BINDER_WRITE_READ_:
            ret = binder_do_write_read(proc, thread, arg, non_block);
            break;

        case BINDER_SET_MAX_THREADS_: {
            uint32_t max = *(uint32_t *) arg;
            if (max > 4096) {
                ret = _EINVAL;
                break;
            }
            proc->max_threads = (int) max;
            ret = 0;
            break;
        }

        case BINDER_SET_CONTEXT_MGR_:
            ret = binder_set_context_mgr(proc, 0, 0, 0);
            break;

        case BINDER_SET_CONTEXT_MGR_EXT_: {
            struct flat_binder_object *fbo = arg;
            ret = binder_set_context_mgr(proc, fbo->binder, fbo->cookie, fbo->flags);
            break;
        }

        case BINDER_THREAD_EXIT_:
            binder_thread_free(thread);
            ret = 0;
            break;

        case BINDER_SET_IDLE_TIMEOUT_:
        case BINDER_SET_IDLE_PRIORITY_:
            // Accepted and ignored, exactly as in Linux -- there is no binder
            // scheduler policy to apply here.
            ret = 0;
            break;

        case BINDER_ENABLE_ONEWAY_SPAM_DETECTION_:
            proc->oneway_spam_detection = *(uint32_t *) arg != 0;
            ret = 0;
            break;

        case BINDER_GET_NODE_DEBUG_INFO_: {
            struct binder_node_debug_info *info = arg;
            // Walks this process's nodes in ptr order: userspace passes back
            // the previous ptr to get the next one, 0 to start.
            struct binder_node *best = NULL;
            struct binder_node *node;
            list_for_each_entry(&proc->nodes, node, proc_link) {
                if (node->ptr > info->ptr && (best == NULL || node->ptr < best->ptr))
                    best = node;
            }
            if (best == NULL) {
                *info = (struct binder_node_debug_info) {};
            } else {
                info->ptr = best->ptr;
                info->cookie = best->cookie;
                info->has_strong_ref = best->has_strong_ref;
                info->has_weak_ref = best->has_weak_ref;
            }
            ret = 0;
            break;
        }

        case BINDER_GET_NODE_INFO_FOR_REF_: {
            struct binder_node_info_for_ref *info = arg;
            if (info->strong_count != 0 || info->weak_count != 0 || info->reserved1 != 0 ||
                info->reserved2 != 0 || info->reserved3 != 0) {
                ret = _EINVAL;
                break;
            }
            struct binder_ref *ref = binder_get_ref(proc, info->handle, false);
            if (ref == NULL || ref->node == NULL) {
                ret = _EINVAL;
                break;
            }
            info->strong_count = ref->node->local_strong_refs + ref->node->internal_strong_refs;
            info->weak_count = ref->node->local_weak_refs;
            ret = 0;
            break;
        }

        case BINDER_FREEZE_: {
            struct binder_freeze_info *info = arg;
            ret = _EINVAL;
            struct binder_proc *target;
            list_for_each_entry(&binder_procs, target, link) {
                if (target->pid != (pid_t_) info->pid || target->context != proc->context)
                    continue;
                target->frozen = info->enable != 0;
                if (!target->frozen) {
                    target->sync_recv = false;
                    target->async_recv = false;
                    binder_wakeup_proc(target);
                }
                ret = 0;
            }
            break;
        }

        case BINDER_GET_FROZEN_INFO_: {
            struct binder_frozen_status_info *info = arg;
            ret = _EINVAL;
            struct binder_proc *target;
            list_for_each_entry(&binder_procs, target, link) {
                if (target->pid != (pid_t_) info->pid || target->context != proc->context)
                    continue;
                info->sync_recv = target->sync_recv;
                info->async_recv = target->async_recv;
                ret = 0;
            }
            break;
        }

        default:
            ret = _EINVAL;
            break;
    }

    unlock(&binder_lock);
    return ret;
}

static int binder_flush(struct fd *fd) {
    struct binder_proc *proc = binder_proc_get(fd);
    if (proc == NULL)
        return 0;
    // Wake every parked looper so a process shutting down doesn't sit in
    // BINDER_WRITE_READ forever.
    lock(&binder_lock, 0);
    struct binder_thread *thread;
    list_for_each_entry(&proc->threads, thread, proc_link) {
        notify(&thread->wait);
    }
    unlock(&binder_lock);
    return 0;
}

struct dev_ops binder_dev = {
    .open = binder_open,
    .fd.mmap = binder_mmap,
    .fd.poll = binder_poll,
    .fd.ioctl_size = binder_ioctl_size,
    .fd.ioctl = binder_ioctl,
    .fd.fsync = binder_flush,
    .fd.close = binder_close,
};

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void binder_task_exit(struct task *task) {
    // do_exit calls this for every task on the system, so on a guest that
    // never touches binder (the overwhelmingly common case) it must not cost a
    // lock acquisition. The count is only ever incremented under binder_lock
    // by a process that has already opened the device.
    if (atomic_load(&binder_live_procs) == 0)
        return;

    lock(&binder_lock, 0);
    struct binder_proc *proc;
    list_for_each_entry(&binder_procs, proc, link) {
        struct binder_thread *thread, *tmp;
        list_for_each_entry_safe(&proc->threads, thread, tmp, proc_link) {
            if (thread->pid == task->pid)
                binder_thread_release(proc, thread);
        }
    }
    unlock(&binder_lock);
}

int binder_alloc_minor(const char *name) {
    lock(&binder_lock, 0);
    for (int minor = BINDER_FIRST_DYNAMIC_MINOR; minor < BINDER_MAX_MINORS; minor++) {
        if (binder_minor_context[minor] != NULL)
            continue;
        struct binder_context *context = calloc(1, sizeof(*context));
        char *copy = strdup(name);
        if (context == NULL || copy == NULL) {
            free(context);
            free(copy);
            unlock(&binder_lock);
            return _ENOMEM;
        }
        context->name = copy;
        binder_minor_context[minor] = context;
        binder_minor_name[minor] = copy;
        unlock(&binder_lock);
        return minor;
    }
    unlock(&binder_lock);
    return _ENOSPC;
}

const char *binder_minor_device_name(int minor) {
    if (minor < 0 || minor >= BINDER_MAX_MINORS)
        return NULL;
    return binder_minor_name[minor];
}

void binder_create_device_nodes(void) {
    static const struct {
        const char *path;
        int minor;
    } nodes[] = {
        { "/dev/binder", DEV_BINDER_MINOR },
        { "/dev/hwbinder", DEV_HWBINDER_MINOR },
        { "/dev/vndbinder", DEV_VNDBINDER_MINOR },
    };
    for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        struct statbuf stat;
        dev_t_ dev = dev_make(BINDER_MAJOR, nodes[i].minor);
        int err = generic_statat(AT_PWD, nodes[i].path, &stat, AT_SYMLINK_NOFOLLOW_);
        if (err == _ENOENT) {
            generic_mknodat(AT_PWD, nodes[i].path, S_IFCHR | 0666, dev);
        } else if (err >= 0 && (!S_ISCHR(stat.mode) || stat.rdev != dev)) {
            generic_unlinkat(AT_PWD, nodes[i].path);
            generic_mknodat(AT_PWD, nodes[i].path, S_IFCHR | 0666, dev);
        }
    }
}

// ---------------------------------------------------------------------------
// State dump (/proc/ish/binder)
// ---------------------------------------------------------------------------

// Linux exposes this through debugfs; we hang it off /proc/ish because it is an
// introspection aid rather than a Linux interface anyone codes against.
//
// It exists because "the call hangs" is otherwise unanswerable from the guest.
// A transaction to handle 0 that never returns has a handful of distinct
// causes -- no context manager registered, a manager whose process died, no
// thread waiting to take proc work, work sitting queued that nobody dequeued,
// a reply that cannot find its way back up a transaction stack -- and they are
// indistinguishable from the outside. Each one is visible here.

static const char *binder_looper_state(int looper) {
    if (looper & BINDER_LOOPER_STATE_EXITED)
        return "exited";
    if (looper & BINDER_LOOPER_STATE_INVALID)
        return "invalid";
    if (looper & BINDER_LOOPER_STATE_ENTERED)
        return "entered";
    if (looper & BINDER_LOOPER_STATE_REGISTERED)
        return "registered";
    return "none";
}

static size_t binder_list_count(struct list *list) {
    size_t n = 0;
    struct list *item;
    list_for_each(list, item)
        n++;
    return n;
}

int binder_show_state(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    lock(&binder_lock, 0);

    for (size_t i = 0; i < sizeof(binder_contexts) / sizeof(binder_contexts[0]); i++) {
        struct binder_context *context = &binder_contexts[i];
        // The first question to ask about a hung transaction: is anyone
        // actually listening on handle 0?
        if (context->mgr_node == NULL) {
            proc_printf(buf, "context %s: no context manager\n", context->name);
            continue;
        }
        struct binder_proc *mgr = context->mgr_node->proc;
        proc_printf(buf, "context %s: manager pid %d%s\n", context->name,
                    mgr != NULL ? (int) mgr->pid : -1,
                    mgr == NULL ? " (owner is gone)" : "");
        proc_printf(buf, "  secctx %s\n",
                    context->mgr_node->txn_security_ctx ? "yes" : "no");
    }

    struct binder_proc *proc;
    list_for_each_entry(&binder_procs, proc, link) {
        proc_printf(buf, "proc %d context %s%s%s\n", (int) proc->pid,
                    proc->context != NULL ? proc->context->name : "?",
                    proc->is_dead ? " dead" : "", proc->frozen ? " frozen" : "");
        // Work parked on the process rather than a thread is waiting for ANY
        // thread to come and take it; if this is nonzero while every thread
        // below is idle, the wakeup is what went wrong.
        proc_printf(buf, "  todo %zu  outstanding %u  ready_threads %d  max_threads %d\n",
                    binder_list_count(&proc->todo), proc->outstanding_txns,
                    proc->ready_threads, proc->max_threads);

        struct binder_thread *thread;
        list_for_each_entry(&proc->threads, thread, proc_link) {
            proc_printf(buf, "  thread %d: looper %s%s%s todo %zu",
                        (int) thread->pid, binder_looper_state(thread->looper),
                        thread->waiting ? " waiting" : "",
                        thread->wait_for_proc_work ? " for-proc-work" : "",
                        binder_list_count(&thread->todo));
            // A non-empty transaction stack on a thread that is also waiting
            // is the shape of a deadlock: it is blocked on a reply to a call
            // it made, and cannot service the call that would produce it.
            size_t depth = 0;
            for (struct binder_transaction *t = thread->transaction_stack;
                 t != NULL && depth < 16; t = t->to_parent)
                depth++;
            if (depth > 0)
                proc_printf(buf, " stack %zu", depth);
            if (thread->is_dead)
                proc_printf(buf, " dead");
            proc_printf(buf, "\n");
        }

        struct binder_node *node;
        list_for_each_entry(&proc->nodes, node, proc_link) {
            proc_printf(buf, "  node %d: refs %zu strong %d/%d weak %d async %zu%s\n",
                        node->debug_id, binder_list_count(&node->refs),
                        node->internal_strong_refs, node->local_strong_refs,
                        node->local_weak_refs, binder_list_count(&node->async_todo),
                        node->has_async_transaction ? " async-in-flight" : "");
        }

        struct binder_ref *ref;
        list_for_each_entry(&proc->refs, ref, proc_link) {
            proc_printf(buf, "  ref handle %u -> node %d (proc %d) strong %d weak %d%s\n",
                        ref->desc, ref->node != NULL ? ref->node->debug_id : -1,
                        ref->node != NULL && ref->node->proc != NULL
                            ? (int) ref->node->proc->pid : -1,
                        ref->strong, ref->weak, ref->death != NULL ? " death-requested" : "");
        }
    }

    if (list_empty(&binder_procs))
        proc_printf(buf, "no processes have the driver open\n");

    unlock(&binder_lock);
    return 0;
}
