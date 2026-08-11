# Running Android userspace under iSH-AOK

State of the Android bring-up work in this fork, what is proven, and what the
next blocker is. Written so the next person to pick this up -- including a
future session with none of the context -- does not have to re-derive it.

## What is proven

`servicemanager` from a real Android system image starts under iSH-AOK, claims
the binder context manager, and answers a transaction:

```
$ binder_ping --external -v
ok handle 0 replied to PING_TRANSACTION
```

That is libbinder on one side, `kernel/binder.c` in the middle, and
`BBinder::onTransact` on the other. Everything below it works under real
Android userspace, not just under our own tests:

| piece | where | evidence |
|---|---|---|
| binder IPC + binderfs | `kernel/binder.c`, `fs/binderfs.c` | servicemanager holds handle 0 and replies to PING |
| security contexts on transactions | `kernel/binder.c` | `/proc/ish/binder` shows `secctx yes` -- servicemanager asked for them |
| permissive selinuxfs | `fs/selinuxfs.c` | `Loaded service context from: /system/etc/selinux/plat_service_contexts` |
| SELinux class resolution | `fs/selinuxfs.c` | `Unknown class service_manager` no longer logged |
| `getcon` / process contexts | `fs/proc/pid.c` | `/proc/self/attr/current` reads `u:r:init:s0` |
| ashmem, DMA-BUF heaps | `kernel/ashmem.c`, `kernel/dma_heap.c` | guest tests; not yet exercised by Android |
| guest-writable `/dev/kmsg` | `fs/mem.c`, `kernel/log.c` | Android's fatal messages appear in `dmesg` |

## The current blocker: no property service

`service list` and every other ordinary client hangs **before touching binder**.
Modern libbinder waits on a property first:

```cpp
while (!WaitForProperty("servicemanager.ready", "true", 1s)) { ... }
```

servicemanager cannot set it -- there is no property service -- and logs
`Failed to set servicemanager ready property`. With `/dev/__properties__`
absent, `__system_property_find` returns null, the wait cannot block on a
serial, and the retry loop becomes a busy spin: the process burns CPU with only
fds 0/1/2 open and never calls `ProcessState::self()`.

This is why `binder_ping` exists. `PING_TRANSACTION` depends on no property, no
logd and no init, so it is the one call that can be aimed at a live
servicemanager while the rest of the platform is missing.

The fix is the Android property area: `/dev/__properties__`, a documented
shared-memory format (`prop_area` header plus a trie, plus a serialized
property-info file) that init normally populates. Nothing in it needs a kernel
change or an Android binary -- a generator running under iSH can write the files
and seed `servicemanager.ready=true`. It unblocks far more than one call, since
essentially all of Android userspace reads properties at startup.

## Diagnosing a hang

`/proc/ish/binder` (see `docs/binder.md`) exists because a transaction that
never returns has several causes that look identical from outside. The table
there maps each symptom to the line that identifies it. The single most useful
check: if a hung client does **not** appear in the dump at all, it never opened
the driver, and the problem is upstream of binder entirely -- that is exactly
how the property spin was found.

Android's own explanation of a failure usually goes to logd, which does not
exist here. It ends up in `dmesg` only because `/dev/kmsg` accepts writes;
`android::base`'s KernelLogger writes there. If `dmesg` is silent about a
crash, check that `/dev/kmsg` in that tree is a character device (1,11) and not
a regular file -- a plain file at that path swallows every message.

## Two ways to run a tree

**As an iSH root (preferred).** iSH mounts `/proc`, `/sys` and `/dev/pts` at
boot and creates `/dev/binder`, `/dev/ashmem` and `/dev/dma_heap` itself, so
almost nothing is left to do. See `tools/android-root-profile.sh` for the
session profile, and note:

- The launch/boot commands must be set explicitly. **Do not leave Boot Command
  at `/sbin/init`**: Android has no `/sbin/init`, and iSH's fallback list starts
  with `/init`, which in an Android image is Android's real init. It will run as
  pid 1, try to mount fstab partitions and start ueventd, and fail there.
- `/system/bin/linker64` must exist before the root can boot at all. It is
  `PT_INTERP` for every binary, and a missing interpreter makes `execve` return
  **ENOENT** naming the binary you ran, not the interpreter -- which reads as
  "the shell is missing" when the shell is fine. Modern images ship the real one
  at `system/bin/bootstrap/linker64` and expect init to have linked it.
- selinuxfs cannot go at `/sys/fs/selinux`: `/sys` is iSH's own synthetic
  read-only sysfs, which has no `fs/` directory and cannot be given one.
  libselinux falls back to scanning `/proc/self/mountinfo` for the `selinuxfs`
  type, so any mount point works -- `/selinux` is what Android used pre-4.3.
- Another root is reachable at `/AOK/roots/<name>` while you are booted
  elsewhere, so the tree can be prepared from Alpine before switching. Write
  through that path, not into the root's `data/` directory: `/AOK/roots/<name>`
  is the fakefs mount and records modes and symlinks in `meta.db`.
- Recovery if a bad launch command locks you out: iOS Settings -> iSH-AOK ->
  **Recovery Mode**, which boots the settings UI instead of a session. Do not
  delete the app; that destroys the tree.

**In a chroot.** Works, but mounts do not survive an app restart, so it needs
re-preparing on every launch. `tools/android-chroot-setup.sh` does the whole
thing and verifies it from inside the chroot. Four separate debugging rounds
were lost to setup drift before it existed, each presenting as a different
Android failure.

## Anticipated order of remaining work

1. **Property area** (`/dev/__properties__`) -- the current blocker.
2. **logd**, or a socket sink at `/dev/socket/logdw`, so Android's own logging
   is visible without relying on the kmsg path.
3. Whatever the first real service needs after that. Do not build ahead of the
   evidence: every wall so far has been something other than the one predicted,
   and the cheap diagnostics (`/proc/ish/binder`, `dmesg`, `binder_ping`) have
   each been worth more than a round of speculation.

## Known latent issue

`binder_wakeup_proc` and `binder_wakeup_thread` reach pollers through
`poll_wakeup_trylock`, which discards the wakeup when it cannot take the lock.
That is harmless for a client blocking in `BINDER_WRITE_READ`, which also gets
`notify()`, but an epoll-driven receiver -- which is what real Android is -- has
no second chance and would sleep forever with a transaction queued. It has never
reproduced: `binder_ipc`'s poll phase drives delivery purely through epoll and
passes consistently. Fixing it properly means deferring the wakeup until after
`binder_lock` is released, which is why it has not been done on a hunch.
