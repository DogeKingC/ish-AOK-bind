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

$ chroot /root/android-sys /system/bin/service list
Found 1 services:
0	manager: []
```

`service list` is the whole path in one command, and it is the command this
work started from: it used to spin forever on `WaitForProperty` without ever
opening the driver. It now gets past the property wait, opens binder,
transacts with a real Android `servicemanager` running from a real system
image, and prints what came back. One service, because only servicemanager is
registered.

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
| system properties | `kernel/property_area.c` | `service list` gets past `WaitForProperty` and goes on to transact |

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

**This has now been shown end to end.** `service list`, an unmodified Android
binary from the system image, gets past `WaitForProperty`, opens the driver and
transacts with a live `servicemanager` (`/proc/ish/binder` reports `manager pid
1995`, `secctx yes`). Independently, bionic's own unmodified `prop_area.cpp`
maps the area and finds every property in it by name, long out-of-line values
included, and `tests/manual/property_area.c` -- a separate transcription of the
read side -- agrees.

Getting there needed the arm64 tagged-pointer work below as much as the
property area itself: bionic tags every heap pointer, so before that was fixed
an Android process died in libc long before it reached a property or a binder
call.

A second process registers too. `incidentd` starts, calls `addService`, and
appears in the list:

```
$ chroot /root/android-sys /system/bin/service list
Found 2 services:
0	incident: []
1	manager: []
```

`/proc/ish/binder` confirms it is real rather than a name in a map:
servicemanager holds `ref handle 3 -> node 33 (proc 5031) strong 1 weak 1
death-requested` -- a strong reference to incidentd's node, with death
notification requested.

**The next blocker: `checkService` returns null for everything**, and it is
NOT the binder driver. `service list` works; `service check <name>` reports
"not found" for every service, `manager` included. What has been ruled out, and
how:

- **The driver.** `binder_ipc`'s relay phase now covers all three shapes this
  involves -- an object sent in a reply, a third party's handle relayed on to a
  stranger (`HANDLE -> HANDLE`, then a direct call through it), and the manager
  handing back its OWN node to a caller that already holds handle 0 for it.
  All pass, on an x86 box, with no device.
- **The SELinux permission check.** `canList` and `canFind` both call
  `selinux_check_access` with the same caller SID. Listing works, so the SID,
  the AVC and the stub's allow-everything verdict are all fine.
- **The context lookup.** `incident` and `manager` are both present in
  `plat_service_contexts` (lines 333 and 473), and servicemanager logs
  `No match for <name> in service_contexts` when `selabel_lookup` fails. It
  does not.
- **Enforcement mode.** `sys/fs/selinux/enforce` reads `0`.
- **A dead manager.** `/proc/ish/binder` reports `manager pid 43`, `secctx
  yes`, while the failing check runs.

So the difference is above the driver, in what libbinder or servicemanager does
between finding the service in its map and the caller seeing a usable binder.
The next step needs instrumentation on that side -- our own tests replicate the
protocol shape faithfully but not libbinder's exact parcel -- so it wants either
a printk in the driver dumping the objects in that specific reply, or a locally
built Android client.

Two other things the daemon sweep established, both about the image rather
than the emulator:

- **Most daemons cannot link, and re-extracting will not fix it.**
  `mediametrics`, `storaged`, `credstore`, `gatekeeperd`, `netd`, `vold` and
  `usbd` each die at the linker on a missing library, and the full list is of
  one kind:

  ```
  netd_aidl_interface-V18-cpp.so        android.hardware.health-V5-ndk.so
  android.system.keystore2-V6-ndk.so    android.hardware.usb.gadget-V2-ndk.so
  android.hardware.security.keymint-V5-ndk.so
  mediametricsservice-aidl-V1-cpp.so
  ```

  These are vendor-side HAL and AIDL interface libraries. A GSI ships `system`
  only, by design -- it is meant to pair with the phone's own vendor
  partition -- so they are absent from a correct, complete extraction, not just
  a careless one. This was first written up here as an incomplete image, which
  was wrong: re-extracting with `.github/workflows/extract-android-system.yml`,
  which copies the entire system root including `system_ext` and `product`,
  changed nothing about them. Even with the libraries these daemons would then
  want the HAL *services* behind them, which need real hardware, so they are
  not a route forward under emulation and no extraction workflow will make
  them one.

  What that same re-extraction DID fix is `build.prop`, which the previous
  extraction dropped: the property area went from 1 property to 111. The
  daemons that need no HAL -- servicemanager and incidentd -- are the working
  set.
- **`/data` did not exist.** A skeleton (`data/local/tmp`, `data/misc`,
  `data/system`, `data/resource-cache`, `data/user/0`) is enough for
  incidentd. `idmap2d` still dies with a null write (`page fault on 0x4`,
  twice, from a binder thread), which looks like an ordinary guest-side null
  dereference on missing configuration rather than an emulator fault.

**Re-run `chroot-setup.sh` after every iSH restart.** Mounts do not survive
one, and the symptom is not obviously a mount problem: `Bad boot_id: ''` and a
servicemanager that exits without logging why. It cost two rounds here.

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
nothing is left to do. See `/AOK/tools/android/root-profile.sh`
(`opt/AOK/tools/android/` in the tree) for the session profile, and note:

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
re-preparing on every launch. `/AOK/tools/android/chroot-setup.sh` does the
whole thing and verifies it from inside the chroot. Four separate debugging rounds
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

## arm64 tagged pointers (TBI): fixed, and one open case

AArch64 discards bits 56-63 of a data address on dereference, and bionic's
Scudo puts a heap tag there even with no MTE hardware (`AT_HWCAP2` is 0 here).
So under Android essentially every pointer libc touches is tagged, and an
emulator that treats the tag as part of the address rejects a good pointer.
The symptom is `SEGV_MAPERR` on an address that is genuinely mapped.

`tests/manual/arm64/tagged_pointer.c` covers this. `/AOK/tools/ish-remote.sh`
is what made it practical to iterate: the reproduction is on a device, and
each experiment costs seconds rather than a build cycle.

**Fixed.** The tag was stripped in exactly one place, the JIT's TLB fast path
(`jit/guest-arm64/gadgets.h`, `read_prep`/`write_prep`). Everything else saw
it raw:

- `jit/guest-arm64/atomics.S` -- every gadget there builds its own address
  instead of going through the prep macros, because an exclusive must keep the
  guest address for the monitor and hand it to `arm64_cas` itself. All six
  (`ldxr`, `stxr`, `cas`, `casp`, `ldxp`, `stxp`) were unmasked. Confirmed on
  device from a precisely-attributed fault on `STLXR W15, X17, [X1]`: an
  `__atomic_fetch_add` on a tagged pointer died while `__atomic_store_n` and
  `__atomic_load_n` on the same address passed, because those lower to
  STLR/LDAR, which do go through the prep macros. The monitor address is
  masked too -- on hardware an LDXR tagged A pairs with an STXR tagged B, so
  keeping the tag in `excl_addr` would make them miss and spin.
- `kernel/user.c` and `emu/arm64_interp.c` -- untagged at the boundaries
  Linux applies `untagged_addr()` to, via `guest_abi_untag_addr()`
  (`kernel/abi.h`). NOT applied to mmap/munmap/mprotect, which Linux leaves
  to the caller: silently mapping at a tagged address would be worse than the
  fault it replaced.

**Fixed: libc `memset`/`memcpy` on a tagged pointer, and it was not in the
JIT at all.** `jit/hle.c` -- the high-level emulation that recognises hot libc
functions and runs them natively in C instead of emulating them -- took its
pointer arguments straight out of the guest register file and used them as
guest addresses. The file contained no untagging whatsoever. So every HLE'd
`memset`, `memcpy`, `strlen` and friend faulted on an address the JIT itself
would have handled without complaint, and `hle_loop_exec` did the same with the
recognised copy/set loop's pointer registers.

`a2` is left alone deliberately: it is a length, and `~0ull` for the unbounded
string forms. Pointer-valued results get the tag put back, because hardware
never strips it and a caller comparing `memchr`'s result against the pointer it
passed in must still see them equal.

Two smaller leaks of the same shape were fixed on the way, and both were real:

- the seven arm64 C helpers in `emu/tlb.c` (`arm64_vldst_multi`,
  `arm64_vldst_struct`, `arm64_lse_rmw`, `arm64_cas`, `arm64_casp`,
  `arm64_ldxp`, `arm64_stxp`), which exist *because* they bypass the prep
  macros -- and so bypassed the only thing that strips the tag
- `handle_page_fault_interrupt`, which now resolves an arm64 fault against the
  untagged address, as Linux's `do_page_fault` does on its first line, with a
  cap so that a fault which resolves and immediately re-faults is delivered as
  SIGSEGV instead of spinning the app into a wedge

**Why it took a day, which is the part worth keeping.** HLE hooks a function AT
ITS ENTRY POINT, so the fault was always reported at the first instruction of
`memset` (`dup v0.16b, w1`) or `memcpy` (`add x4, x1, x2`) -- neither of which
touches memory. That one fact sent the investigation into the SIMD gadgets, the
fault-restart contract, instruction fusion and the TLB prep macros, all
innocent. It also explains the two results that should have been the clue and
could not be accounted for at the time: an inline copy of musl's memset body
passed against the same tagged pointer in the same process (not hooked, so
genuinely executed), and a minimal standalone repro never failed (HLE
recognition needs the function to be hot, and a short-lived forked child never
gets there).

What located it was instrumenting `tlb_handle_miss` to name its caller. The
tagged address arrived from C, from a translation unit far from `emu/tlb.c`,
and `jit/hle.c` is the only C on the arm64 path that touches guest memory on
behalf of an entire libc call. Those probes are still in, rate-limited, as
tripwires: if a tagged address ever reaches the TLB again, the log says so and
names the caller instead of costing another week.

Confirmed on device: `tagged_pointer: PASS`, and zero probe lines in `dmesg` --
the probes going silent is the real check, since it means nothing is handing
the emulator a tagged pointer any more.

### Reproducing arm64-guest bugs without a device

`tools/run-arm64-guest-tests.sh` cross-builds iSH for aarch64-linux (clang,
`tools/cross-aarch64.ini`) and runs `tests/manual/arm64/*` under qemu-user
against a real Alpine aarch64 rootfs, so the arm64 gadget set executes for
real on an x86_64 development machine. All nine tests pass there today.

It is stricter about tags than real hardware, which is a feature: an arm64
core IGNORES bits 56-63 on a dereference, so a path that forgets to mask still
works on device and faults under qemu. That difference caught a real bug. On
its first runs `tagged_pointer`'s `atomics` probe failed there while passing on
device, and that was written off in this document as a qemu artifact (qemu
clears the exclusive monitor more eagerly than a real core, so LDXR/STXR
sequences genuinely are not comparable). It was not an artifact: the LSE and
exclusive C helpers in `emu/tlb.c` were taking the guest address untagged, and
the device only survived it because TBI hid the bad pointer. Writing off a
failing test as a host artifact is the specific mistake to avoid here -- the
whole value of a stricter host is the failures it produces.

What it does NOT reproduce is the memset case, at either the pre-merge or the
current tree.
