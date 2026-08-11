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
| system properties | `kernel/property_area.c` | bionic's own reader parses the area; not yet driven by a live client |

## The property area

`service list` and every other ordinary client used to hang **before touching
binder**. Modern libbinder waits on a property first:

```cpp
while (!WaitForProperty("servicemanager.ready", "true", 1s)) { ... }
```

servicemanager cannot set it -- setting a property means talking to a property
service, and there is none -- so it logs `Failed to set servicemanager ready
property`. With `/dev/__properties__` absent, `__system_property_find` returned
null, the wait had no serial to block on, and the retry loop became a busy
spin: the process burned CPU with only fds 0/1/2 open and never called
`ProcessState::self()`.

`kernel/property_area.c` now writes that file at boot, next to the binder and
ashmem device nodes. It contains `servicemanager.ready=true` plus everything in
the tree's own `build.prop` files, read in init's order with the later file
winning (`PropertyLoadBootDefaults` in `system/core/init/property_service.cpp`),
including `import` lines and the keys init refuses to take from a file.

Two things worth knowing about it:

- **The layout is the pre-split one.** bionic picks its layout from what is at
  `/dev/__properties__`: a directory with a `property_info` in it means one
  `prop_area` per SELinux context plus a serialized context trie, a directory
  without one means the `/plat_property_contexts` split, and a *regular file*
  means the whole property set in a single `prop_area`. We write the last.
  It is what Android used before 8.0, it is still in current bionic
  (`SystemProperties::InitContexts`), and the per-context split it gives up
  exists to stop one domain reading another's properties -- which means
  nothing next to a permissive `fs/selinuxfs.c`.
- **`servicemanager.ready` is seeded, not observed.** It says the area was
  built, not that servicemanager is up. Start servicemanager before anything
  that talks to it, or the client will get past the property and then block in
  binder with no context manager -- which `/proc/ish/binder` reports as `no
  context manager`.

There is still no property *service*: `/dev/socket/property_service` does not
exist, so `__system_property_set()` fails and the area is read-only. To change
a property, edit the `build.prop` it came from and rebuild:

```sh
echo / > /proc/ish/property_area     # or a tree's path, for a chroot
cat /proc/ish/property_area
```

The file is replaced, not rewritten, so a process that already mapped the old
one keeps it -- restart the process, not the session.

`/proc/ish/property_area` also reports what the last build produced, which
matters because from inside the guest "the property is not set" and "the area
was never built" look identical and call for opposite next steps.

**What has not been shown yet** is a live Android client getting past
`WaitForProperty` and going on to make a real call. What has been shown is that
bionic's own unmodified `prop_area.cpp` maps the area and finds every property
in it by name, long out-of-line values included, and that
`tests/manual/property_area.c` -- an independent transcription of the read side
-- agrees. The next person with a device should point `service list` at a
running servicemanager and see how far it gets.

`binder_ping` still exists and is still the cheapest probe:
`PING_TRANSACTION` depends on no property, no logd and no init, so it isolates
binder from everything above it.

## Diagnosing a hang

`/proc/ish/binder` (see `docs/binder.md`) exists because a transaction that
never returns has several causes that look identical from outside. The table
there maps each symptom to the line that identifies it. The single most useful
check: if a hung client does **not** appear in the dump at all, it never opened
the driver, and the problem is upstream of binder entirely -- that is exactly
how the property spin was found.

When a client is hung upstream of binder, `/proc/ish/property_area` is the next
place to look: a `no area` line, or a property count that does not include what
the client is waiting on, explains it without a debugger.

Android's own explanation of a failure usually goes to logd, which does not
exist here. It ends up in `dmesg` only because `/dev/kmsg` accepts writes;
`android::base`'s KernelLogger writes there. If `dmesg` is silent about a
crash, check that `/dev/kmsg` in that tree is a character device (1,11) and not
a regular file -- a plain file at that path swallows every message.

## Two ways to run a tree

**As an iSH root (preferred).** iSH mounts `/proc`, `/sys` and `/dev/pts` at
boot, creates `/dev/binder`, `/dev/ashmem` and `/dev/dma_heap` itself, and
builds `/dev/__properties__` from the tree's own `build.prop` files, so almost
nothing is left to do. See `tools/android-root-profile.sh` for the session
profile, and note:

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

A chroot needs one thing a root does not: the property area iSH builds at boot
went into the *outer* root's `/dev`, from the *outer* root's `build.prop` files
-- neither of which is the tree. The setup script fixes that by writing the
tree's path to `/proc/ish/property_area`, which rebuilds it from that tree into
that tree's `dev/__properties__`.

## Anticipated order of remaining work

1. **Run a real client against the area.** `service list` with servicemanager
   already started is the one-line experiment that says whether the property
   work landed. Until someone does it, the property area is verified against
   bionic's reader and nothing else.
2. **logd**, or a socket sink at `/dev/socket/logdw`, so Android's own logging
   is visible without relying on the kmsg path.
3. Whatever the first real service needs after that. Do not build ahead of the
   evidence: every wall so far has been something other than the one predicted,
   and the cheap diagnostics (`/proc/ish/binder`, `/proc/ish/property_area`,
   `dmesg`, `binder_ping`) have each been worth more than a round of
   speculation.

A property service is deliberately *not* on this list. Nothing has yet been
seen to need one: the properties Android reads at startup come from files, and
the one write that mattered (`servicemanager.ready`) is answered by seeding it.
If something turns out to need a real `__system_property_set`, that is when to
build the socket at `/dev/socket/property_service` -- and it will need the
in-place value update with the dirty-serial protocol, which the read-only area
does not implement.

## Known latent issue

`binder_wakeup_proc` and `binder_wakeup_thread` reach pollers through
`poll_wakeup_trylock`, which discards the wakeup when it cannot take the lock.
That is harmless for a client blocking in `BINDER_WRITE_READ`, which also gets
`notify()`, but an epoll-driven receiver -- which is what real Android is -- has
no second chance and would sleep forever with a transaction queued. It has never
reproduced: `binder_ipc`'s poll phase drives delivery purely through epoll and
passes consistently. Fixing it properly means deferring the wakeup until after
`binder_lock` is released, which is why it has not been done on a hunch.
