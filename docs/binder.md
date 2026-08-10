# Android Binder support

iSH-AOK implements the Android Binder IPC driver: `/dev/binder`, `/dev/hwbinder`,
`/dev/vndbinder`, and binderfs. Binder is the IPC that all of Android's
userspace is built on, so this is the prerequisite for running anything that
links `libbinder` — `servicemanager`, HIDL/AIDL services, and the Android
service model generally.

The implementation lives in:

- [kernel/binder.h](../kernel/binder.h) — the guest-visible ABI (a transcription
  of Linux's `include/uapi/linux/android/binder.h` and `binderfs.h`)
- [kernel/binder.c](../kernel/binder.c) — the driver
- [fs/binderfs.c](../fs/binderfs.c) — binderfs and its `BINDER_CTL_ADD` control node
- [tests/manual/binder_ipc.c](../tests/manual/binder_ipc.c) — the regression test

## What userspace sees

A process opens a binder device, mmaps a receive region from it, and drives
everything through one ioctl, `BINDER_WRITE_READ`, which carries a stream of
`BC_` commands out and a stream of `BR_` returns back.

Supported ioctls:

| ioctl | Notes |
| --- | --- |
| `BINDER_VERSION` | Reports protocol 8 (the 64-bit ABI) |
| `BINDER_WRITE_READ` | The command/return stream |
| `BINDER_SET_MAX_THREADS` | Bounds `BR_SPAWN_LOOPER` requests |
| `BINDER_SET_CONTEXT_MGR`, `BINDER_SET_CONTEXT_MGR_EXT` | Claim handle 0 |
| `BINDER_THREAD_EXIT` | Retire the calling thread's binder state |
| `BINDER_GET_NODE_DEBUG_INFO`, `BINDER_GET_NODE_INFO_FOR_REF` | Introspection |
| `BINDER_FREEZE`, `BINDER_GET_FROZEN_INFO` | Process freezer |
| `BINDER_ENABLE_ONEWAY_SPAM_DETECTION` | Enables `BR_ONEWAY_SPAM_SUSPECT` |
| `BINDER_SET_IDLE_TIMEOUT`, `BINDER_SET_IDLE_PRIORITY` | Accepted and ignored, as on Linux |

Commands: `BC_TRANSACTION`, `BC_REPLY`, `BC_TRANSACTION_SG`, `BC_REPLY_SG`,
`BC_FREE_BUFFER`, `BC_INCREFS`/`BC_ACQUIRE`/`BC_RELEASE`/`BC_DECREFS`,
`BC_INCREFS_DONE`/`BC_ACQUIRE_DONE`, `BC_REGISTER_LOOPER`/`BC_ENTER_LOOPER`/
`BC_EXIT_LOOPER`, `BC_REQUEST_DEATH_NOTIFICATION`/
`BC_CLEAR_DEATH_NOTIFICATION`/`BC_DEAD_BINDER_DONE`.

Object types translated inside a transaction: `BINDER_TYPE_BINDER` and
`BINDER_TYPE_WEAK_BINDER` (become handles at the peer), `BINDER_TYPE_HANDLE` and
`BINDER_TYPE_WEAK_HANDLE` (become the owner's pointer when sent back home),
`BINDER_TYPE_FD` (file descriptor passing), `BINDER_TYPE_FDA` (fd arrays), and
`BINDER_TYPE_PTR` (scatter-gather buffers).

## How it maps onto iSH

The emulated kernel and the guest share one host address space, which makes
binder's central trick — kernel and userspace holding two mappings of the same
pages — fall out naturally.

Each open of a binder device gets a `binder_proc`. Its receive region is backed
by an unlinked host temp file, mapped twice: once into the guest (read-only) and
once into the driver (read-write). Delivering a transaction is a single
`user_read()` from the sender's guest memory directly into the driver's mapping,
after which the receiver sees the data at its own address. That is binder's
single copy, with the same page-sharing property the real driver gets from
`vm_insert_page`.

Two consequences worth knowing:

- **The guest's mmap is forced to `MAP_SHARED` internally.** `libbinder` asks
  for `PROT_READ | MAP_PRIVATE`; a genuinely private mapping would copy-on-write
  away from the pages the driver writes into, so the guest would never see
  incoming transactions. Since the guest mapping is read-only, mapping it shared
  is observationally identical. A writable mapping is refused with `EPERM`, as
  on Linux.
- **File descriptors are installed by the receiver, not the sender.** A
  `BINDER_TYPE_FD` object retains the sender's `struct fd` at send time and
  records a fixup; the number is allocated when the receiving thread dequeues
  the transaction, because that is the only point where the receiving task is
  `current`. This matches what modern Linux does (`binder_apply_fd_fixups`).

Locking is one global lock over every binder structure. Linux uses fine-grained
per-proc/per-node locking to scale to a phone's worth of IPC; here simplicity is
worth more than the contention, and the one place the driver must sleep — a
thread waiting for work — uses `wait_for()`, which drops the lock while blocked.

## Contexts and device nodes

`binder`, `hwbinder` and `vndbinder` are separate *contexts*: each has its own
service registry and its own context manager at handle 0. That is why they are
three devices rather than three minors of one namespace. All of them live on
major 249 (Linux allocates binder's major dynamically; a fixed one lets the
device nodes exist before anything opens them).

The nodes are created at boot by `binder_create_device_nodes()`. On a root that
cannot hold device nodes, that quietly does nothing and binderfs is the way in.

## binderfs

```sh
mkdir -p /dev/binderfs
mount -t binder binder /dev/binderfs
```

The mount contains `binder-control` plus a character device per registered
binder device. `BINDER_CTL_ADD` on the control node allocates a new minor and a
new context, and the device appears in the directory immediately:

```c
struct binderfs_device device = {};
strcpy(device.name, "my-binder");
ioctl(control_fd, BINDER_CTL_ADD, &device);
/* /dev/binderfs/my-binder now exists, with its own context manager slot */
```

Because binderfs supplies its own device nodes, it works on roots where `mknod`
is not permitted.

## Testing

```sh
sh /AOK/tests/setup-regressions.sh --run          # includes binder_ipc
```

`binder_ipc` speaks the protocol directly rather than through `libbinder`, so it
asserts on the wire format. It covers the ioctl surface and mmap rules, claiming
the context manager, a real cross-process transaction and reply (checking the
payload arrives through the receiver's own mapping), `BINDER_TYPE_BINDER` being
translated to a handle at the peer, oneway transactions, `BR_DEAD_BINDER` firing
when a node's owner exits, and binderfs device creation.

## Not implemented

- **Security contexts.** `FLAT_BINDER_FLAG_TXN_SECURITY_CTX` is parsed and
  stored but no SELinux context is attached, so `BR_TRANSACTION_SEC_CTX` is
  never delivered. iSH has no LSM to source a context from.
- **Scheduler policy inheritance.** `FLAT_BINDER_FLAG_INHERIT_RT` and the
  priority bits are accepted and ignored; binder priority inheritance has no
  meaning without a real scheduler underneath.
- **`/binderfs` statistics and `binder_logs` debugfs.** No `/sys/kernel/debug/binder`.

## Beyond binder

Binder is necessary but not sufficient for running Android userspace.

`ashmem` (`/dev/ashmem`) is now implemented too -- see `kernel/ashmem.c` and
`tests/manual/ashmem.c`. It is backed the same way binder's receive region is,
by an unlinked host temp file, so a descriptor passed between processes maps
the same pages on both sides.

DMA-BUF heaps are implemented as well -- `kernel/dma_heap.c`,
`tests/manual/dma_heap.c`. `/dev/dma_heap/system` answers
`DMA_HEAP_IOCTL_ALLOC` with a dma-buf descriptor that mmaps and can be passed
to another process, and the buffer fd supports `DMA_BUF_IOCTL_SYNC` and
`DMA_BUF_SET_NAME`. `DMA_BUF_IOCTL_SYNC` is a validated no-op: it exists for
cache maintenance between a device and the CPU, and there is no device here.

What is still missing is graphics. `/dev/dri` would need an actual DRM
implementation rather than a stub, since iSH has no GPU passthrough for Mesa
to use, and Android's graphics stack also wants sync fences
(`DMA_BUF_IOCTL_EXPORT_SYNC_FILE`), which are not implemented.
