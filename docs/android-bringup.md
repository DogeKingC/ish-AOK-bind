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

### `checkService` returned null for everything: fixed, and it WAS the driver

`service list` worked while `service check <name>` reported "not found" for
every service, `manager` included. The cause was one line in `kernel/binder.c`:
object offsets inside a transaction were required to be 8-byte aligned.

They only have to be 4-byte aligned. `Parcel` packs its contents to 4 bytes, so
an object inherits the alignment of whatever was written before it; only the
binder *buffer* is 8-aligned. Linux says the same thing explicitly --
`binder_validate_object()` tests `IS_ALIGNED(offset, sizeof(u32))`.

That single constant produces exactly the observed split:

| call | what precedes the object | offset | verdict |
|---|---|---|---|
| `listServices` | no objects at all | -- | worked |
| `addService` | interface token + service name | 8-aligned | worked |
| `checkService` **reply** | `Status::writeToParcel`, EX_NONE: one int32 | **4** | rejected |

libbinder's reply for `@nullable IBinder checkService` is a 4-byte status
followed immediately by `writeStrongBinder`, so its object sits at offset 4 and
the whole parcel is 28 bytes. The driver refused it with `BR_FAILED_REPLY`;
libbinder turns a failed transaction into a null binder; `service` prints "not
found". Nothing above the driver was ever wrong.

**Why the elimination list was wrong, which is the part worth keeping.** The
driver was ruled out because `binder_ipc`'s relay phase covers all three shapes
this involves -- an object in a reply, a third party's handle relayed on to a
stranger, and the manager handing back its own node -- and all three passed.
They still pass. They also all build their object as the second member of a
`struct { uint64_t magic; struct flat_binder_object obj; }`, so every one of
them lands at offset 8. The tests were faithful about the protocol *shape* and
silently unanimous about an alignment they never meant to be asserting.

A passing test only rules out the cases it encodes. "The driver is ruled out,
all three shapes pass" should have been "all three shapes pass **with an
8-aligned object**, and I have not checked that libbinder produces one" -- and
the doc even said, one paragraph later, that our tests "replicate the protocol
shape faithfully but not libbinder's exact parcel". That sentence was the
answer, filed as a caveat.

`tests/manual/binder_ipc.c` now has a phase (`align4`) that replays libbinder's
`checkService` reply byte for byte: a 28-byte parcel, an int32 status, and the
object at offset 4. It fails against the old driver with `BR_FAILED_REPLY` and
passes now.

**Confirmed on device**, against a real `servicemanager` and a real
`incidentd`, on a dev IPA built from the fix:

```
$ chroot /root/android-sys /system/bin/service list
Found 2 services:
0	incident: [android.os.IIncidentManager]
1	manager: [android.os.IServiceManager]

manager          Service manager: found
incident         Service incident: found
nosuchservice    Service nosuchservice: not found
```

The last line is the control, and it matters: without it "found" only shows
that something changed, not that lookup still discriminates.

Two things worth noticing in that output. The interface descriptors are new --
this document previously recorded `manager: []`, and the empty brackets were
the same bug seen from the other side. `service list` prints a descriptor by
calling `getInterfaceDescriptor()` on the binder it gets back from
`checkService`, so when `checkService` returned null there was nothing to ask
and the field came back empty. That detail sat in the doc for a session as an
unexplained cosmetic oddity; it was the bug, logged and not read.

**How this was established, because the obvious method does not work.** The
device build reports only `iSH-AOK 1.3 (547)` with a zeroed build date, so it
cannot tell you which commit it came from -- and reasoning from "the device
must be running the old binary" gets it wrong. `tests/manual/binder_ipc.c`'s
`align4` phase is the answer: a small standalone version of it (offsets 2, 4,
8 and 12, reply accepted or `BR_FAILED_REPLY`) is a *behavioural fingerprint*
of which alignment rule a driver implements. Offset 2 must be refused under
either rule, so it proves validation is running at all; 4 separates the two.
Run it against a known-good and known-bad local build first, then against the
device, and the device's driver identifies itself. That is cheaper and more
trustworthy than any version string, and it works over `ish-remote.sh`.

The other things ruled out at the time were correctly ruled out, and remain so:
`canList`/`canFind` and the caller SID, the `plat_service_contexts` lookup,
enforcement mode (`sys/fs/selinux/enforce` reads `0`), and a live manager
(`/proc/ish/binder` reported `manager pid 43`, `secctx yes`). They were just
answers to a question that was not the one being asked.

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
servicemanager that exits without logging why. It has now cost five rounds
across three sessions, three of them in a single afternoon. `Bad boot_id: ''`
is this, not a bug in `fs/proc/sys.c` -- check the mounts before you measure
anything.

**`/AOK/tools/ish-remote.sh <code>` drives the device over ntfy**, which is
much faster than round-tripping commands through a human: each experiment costs
seconds instead of a build-and-install cycle. It is what made the tagged-pointer
work tractable.

Two things about it that used to cost rounds and no longer should:

- **The relay rate-limits, and it used to look like large replies vanishing.**
  The listener now paces its chunk posts, honours the relay's `Retry-After` on
  a 429 instead of retrying faster than the limit replenishes, and truncates
  absurd output with a note rather than firing fifty messages that cannot
  land. Still: keep commands narrow. `head`, `grep` and `tail` at the far end
  beat twenty parts every time.
- **Never `pkill -f <pattern>` for something you named in the command.**
  ish-remote runs each command through `sh -c`, so the command TEXT is that
  shell's argv -- and `pkill -f servicemanager` in a command that mentions
  servicemanager matches the listener itself and kills the channel mid-run.
  It exits 143 and everything after it is lost. Use `pkill -x servicemanager`,
  or kill by pid, or avoid the word.
- **Keepalive is now the default.** It used to be opt-in, and forgetting it
  meant the listener stopped answering the moment iSH left the foreground --
  which reads exactly like the channel being dead. `--no-keepalive` if you
  want the old behaviour. Stop the listener when you are done either way.

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

## Logging: the sink, and what it found

`/dev/socket/logdw` exists and drains into the kernel log (`kernel/logd_sink.c`),
so Android's own account of a failure now reaches `dmesg`. It is NOT logd:
there is no ring buffer, no reader socket and no `logcat`. Real logd cannot be
used here because it does not open its own sockets -- it asks init for them via
`android_get_control_socket("logdw")`, which reads an fd out of
`ANDROID_SOCKET_logdw` -- and there is no init. Same wall as the property area,
same answer: supply the thing rather than build the daemon that supplies it.

**Confirmed end to end on device**, with a real `servicemanager` writing
through it:

```
logd/main W/libc(1128:1128): Using old property service protocol ("ro.property_service.version" is not set)
logd/main E/cutils-trace(1132:1132): Error opening trace file: No such file or directory (2)
logd/main W/libbinder.BackendUnifiedServiceManager(1132:1132): Thread Pool max thread count is 0.
    Cannot cache binder as linkToDeath cannot be implemented. serviceName: manager
```

That last line is worth keeping in view: libbinder is saying the process has no
binder thread pool, so it cannot `linkToDeath` and will not cache the binder.
Nothing needs it yet; something will.

**Two things the device found that the guest test could not.** The events
buffer arrived as `logd/events ?/ (1128:1128):` -- empty tag, empty message.
events, stats and security are Android's BINARY buffers: a 4-byte tag id and
typed values, with no priority byte and no NUL-terminated strings, so the text
parse produced a line that said nothing. They are now reported as binary with
their tag id, and the guest test covers it. Separately, the boot-time sink for
the outer root failed with "error -98", which was a lie: every bind failure
returned a hardcoded `EADDRINUSE`. It reports the real errno now. **A masked
errno is worse than no errno** -- it sends the reader somewhere specific and
wrong.

**The wire format was measured, not assumed.** Binding the socket from an
ordinary guest process and dumping what a real Android binary sent gave

```
04 | 53 00 | 8d 06 81 6a | 18 ee 1f 02 | 07 | 6c 69 62 63 00 | "Fatal signal 6 ..."
id   tid=83   sec           nsec         F    "libc"
```

-- an 11-byte packed header (id, tid, realtime sec/nsec), a priority byte, a
NUL-terminated tag, a NUL-terminated message. The seconds field was the wall
clock at capture time, which is what makes the alignment a fact rather than a
reading. That capture trick is worth keeping: a guest process can bind the
socket itself, so liblog's output can be inspected without involving the sink
at all.

### What logging found immediately

Within two datagrams of the first real capture, both previously invisible:

- **`F_SETPIPE_SZ` is not implemented.** bionic's crash handler sets the pipe
  buffer size when spawning `crash_dump` and gets `EINVAL`: `failed to set pipe
  buffer size: Invalid argument`. Nothing in `kernel/` or `fs/` implements
  either `F_SETPIPE_SZ` or `F_GETPIPE_SZ`. Small, and now the top of the
  remaining work.
- **The boot-time sink never came up on device, and it was an ordering bug.**
  `logd_sink_start()` ran 372 lines before `sock_tmp_prefix` was set in
  `-[AppDelegate boot]`, so the sink bound its host socket at the literal
  `/tmp/ishsock.<id>` -- outside the app sandbox on a real device, hence
  `EPERM`. It worked in the simulator, where the `#if !TARGET_OS_SIMULATOR`
  leaves the default alone and `/tmp` is writable, and it worked when rebuilt
  by hand through `/proc/ish/logd` afterwards, which is exactly what made it
  look like anything other than an ordering problem. The call now sits after
  the assignment, with a comment saying why it may not move back.
- **A servicemanager `SIGABRT`** -- since **resolved, and it was not a bug**.
  It was an artefact of the capture run, which killed and immediately
  restarted servicemanager. A clean start on the same build produces no abort
  at all. Recorded because the wrong conclusion was available and cheap: a
  fatal signal in a log looks like a finding.

### What the daemons say now

With the sink up, running each HAL-free daemon and reading its own words:

| daemon | outcome |
|---|---|
| `servicemanager` | starts, registers, serves `checkService` |
| `incidentd` | starts, registers `incident` |
| `apexd` | **exits 0** -- runs to completion |
| `installd` | `Could not find ANDROID_DATA` -> with `ANDROID_DATA=/data` set it reaches `installd firing up`, then `SIGSEGV` at `0x0` |
| `idmap2d` | logs `Starting`, registers `idmap`, then `SIGSEGV` at `0x4` in a **binder thread** |
| `hwservicemanager` | absent from the image |

`installd`'s environment is the kind of thing that was simply invisible before:
one log line, one variable, and it gets from "exit 1, silently" to running its
own startup. It is set by init in a real Android, which is why nothing here
supplies it.

Both remaining crashes are null dereferences. `idmap2d`'s is now identified
exactly; `installd`'s is not.

### idmap2d: `RefBase::incStrong` on an object whose `mRefs` is null

The whole diagnosis came out of `dmesg`, off the shipping build, with no new
instrumentation and no tombstone:

```
ERROR: 2981(binder:2981_2) [arm64] page fault on 0x4 at 0x7fffb359ca80 (write)
  x0=0x1 x1=0x4 ... x19=0 x20=0x7ffd33224ba8 ...
  x29=0xffffe7f0 x30=0x7fffb3593030
  sp=0xffffe7f0 pc=0x7fffb359ca80 tpidr=0x7fffbcd11d40
  pc-backing 0x7fffb359ca80: /system/lib64/libutils.so data_off=40960 file_off=65536
opcode window around 0x7fffb359ca80: 70 00 00 34 [20]00 20 b8 c0 03 5f d6 ...
```

**`pc-backing` is the line that matters, and it names a file offset.** The
page's offset in the file is `file_off + data_off` (`0x10000 + 0xa000`), plus
the address's offset within its page (`0xa80`), so `pc` is `libutils.so+0x1aa80`
and `x30` -- one page lower -- is `libutils.so+0x11030`. Both are directly
`objdump`-able. `dump_addr_backing` now prints that sum itself (`-> file+0x...`)
because computing it by hand off three fields is where the mistakes happen.

Disassembling `libutils.so+0x11010`, the function `x30` returns into:

```
stp x29, x30, [sp,#-0x20]!
ldr x19, [x0, #8]          ; x19 = this->mRefs   (RefBase's only field, at 8)
mov x20, x0                ; x20 = this
mov w0, #1
add x1, x19, #4            ; &mRefs->mWeak       (weakref_impl: mStrong 0, mWeak 4)
bl  __aarch64_ldadd4_relax ; <- returns to x30; the LDADD inside is the fault
cmp w0, #0x100, lsl #12
mov x1, x19                ; &mRefs->mStrong
bl  __aarch64_ldadd4_relax
mov w8, #0x10000000        ; INITIAL_STRONG_VALUE
```

That is `android::RefBase::incStrong()`, and the registers agree exactly:
`x1 = 4`, `x19 = 0`, `x20` a plausible object pointer. `mRefs` is a
`weakref_impl* const` assigned in `RefBase`'s constructor, so **a constructed
object cannot have it null**. `x7` held the bytes of `":2981_3"`, so this is
`ProcessState::spawnPooledThread` building the *third* pool thread's name --
the first two went through the same `sp<T>::make` -> `incStrong` path without
faulting, which makes it state-dependent rather than a broken code path.

**The fault is a real guest-side null dereference, not a tagged pointer and not
an intercepted function.** The faulting instruction has a memory operand
(`LDADD W0, W0, [X1]`) and `x1` is genuinely 4. The reason it *looked* like a
register-only instruction at first is that it sits inside an outline-atomics
dispatch stub, which builds no stack frame -- so `pc` names a compiler helper
and nothing names the caller. That is why `lr-backing` (x30) is now printed
unconditionally on an arm64 fault: without it a crash in one of those stubs is
unattributable, and `dump_stack` walks the emulator's stack, not the guest's.

Two hypotheses were cheap enough to test and both are **ruled out** by
`tests/manual/arm64/thread_identity.c` under the local harness: binder threads
sharing a stack, and binder threads sharing a thread pointer. Under iSH every
spawned thread gets its own high mmap'd stack and its own `TPIDR_EL0`, TLS
stays private under concurrent traffic, and a once-written object pointer
survives concurrent relaxed atomics through it. The device's identical `tpidr`
across three runs is a deterministic allocator, not sharing.

**And the faulting task is the MAIN thread, despite being called
`binder:2981_2`.** That looked like a pool thread running on the initial stack,
which would have been alarming. It is not: `makeBinderThreadName()` formats
`binder:<getpid()>_<seq>`, and iSH prints the faulting task's *tid*. Across all
three reproductions the tid and the pid inside the name are the same number
(`2981(binder:2981_2)`, `3976(binder:3976_2)`, `4071(binder:4071_2)`), which a
spawned thread's could not be. `ProcessState::giveThreadPoolName()` renames the
calling thread, and `idmap2d` calls it on main before `joinThreadPool()`. So
`sp` near `0xffffe800` is simply the process's initial stack, and there is
nothing wrong with it.

The sequence is therefore: main thread, inside `joinThreadPool()`, gets
`BR_SPAWN_LOOPER`, calls `spawnPooledThread()`, which builds the name
`binder:2981_3` (that is the `":2981_3"` sitting in `x7`) and does
`sp<PoolThread>::make(...)` -> `new PoolThread` -> `RefBase`'s constructor ->
`incStrong`. Worth noting for whoever picks this up: `Thread` inherits
`virtual public RefBase`, so the `this` in `x20` is a virtual-base subobject
pointer reached through a vtable offset, not the address `new` returned. "The
object was never constructed", "the constructor's store was lost" and "the
virtual-base offset was wrong" are three different bugs and the memory dump
below distinguishes them.

### The object has a valid vptr and a null `mRefs`

`/proc/ish/arm64_faultdump` answered this. `sh /AOK/tools/android/crash-probe.sh
-r 19,20 idmap2d`, with `servicemanager` running, dumps the object:

```
memdump around x20=0x7ffda5197448:
7ffda5197408: 00000000 00000000 ... 0000ffff 00000000
7ffda5197428: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
7ffda5197448: bc9b55d8 00007fff 00000000 00000000 00000000 00000000 00000000 00000000
```

`[this+0]` is `0x7fffbc9b55d8`, which is inside libutils (base `0x7fffbc991000`,
so file offset `0x245d8`, in `.data.rel.ro` -- a vtable). `[this+8]`, which is
`mRefs`, is zero, and the whole rest of the object is zero.

So of the three candidates:

- **Not "never constructed".** A vptr was stored. Fresh heap is zero, and
  something wrote a real vtable pointer into it.
- **Not "the virtual-base offset is wrong now".** `x20` points at a properly
  formed `RefBase` subobject: a genuine libutils vtable sits at `x20+0`.
- **What is left is that the store of `mRefs` did not land** -- and it is
  deterministic, byte for byte, across four reproductions.

Worth carrying forward: `x27` is `0xb0` below `x20` in every reproduction, and
`x8` is `0xb0`. That is the virtual-base offset -- `x27` is the `PoolThread`
and `x20` its `RefBase` subobject at `+0xb0`. Because `Thread` inherits
`virtual public RefBase`, the subobject's vptr is set by the *most-derived*
constructor through the VTT, not necessarily by `RefBase::RefBase()` itself.
So "a vptr is present" does not prove `RefBase::RefBase()` ran at this address;
it proves *a* constructor wrote *a* vptr there. A remaining possibility is that
`RefBase::RefBase()` ran against a different vbase offset than the one used
later, which would look identical from the corpse.

`new` returning null is a poor fit and should not be assumed without evidence:
the `PoolThread` allocation itself (larger, moments earlier) plainly succeeded,
since `x27` and `x20` point at real memory. A few dozen bytes failing right
after that is implausible.

The knob that made this readable used to be `ISH_ARM64_FAULT_MEMDUMP` in the
environment only, which on iOS is the *app's* environment -- so the one
diagnostic that could answer this was unreachable on the only machine where the
bug happens.

### The constructor, disassembled

`binutils` is on the device and the Alpine root is aarch64, so libutils can be
disassembled in place -- no pulling the file off:

```sh
nm -D --defined-only libutils.so | grep _ZN7android7RefBaseC2Ev
objdump -d --start-address=0x1d9b4 --stop-address=0x1da44 libutils.so
```

```
1d9c0: adrp x8, 24000
1d9c4: add  x8, x8, #0x5d8      ; x8 = 0x245d8  <- exactly the vptr observed
1d9c8: mov  x19, x0             ; x19 = this
1d9cc: str  x8, [x0]            ; *this = vptr            <- landed
1d9d0: mov  w0, #0x18
1d9d4: bl   _Znwm@plt           ; operator new(24)
1d9dc: str  x19, [x0, #8]       ; impl->mBase = this
1d9e0: ldr  d0, [x8, #352]
1d9e4: str  wzr, [x0, #16]
1d9e8: str  d0, [x0]
1d9ec: str  x0, [x19, #8]       ; this->mRefs = impl      <- did not land
1d9f8: ret
```

Two things this settles. `RefBase::RefBase()` **did** run on this object: the
vtable it computes is `0x245d8`, which is exactly what the dump shows at
`this+0`. And `operator new` returned a **usable** pointer -- otherwise
`str x19, [x0, #8]` two instructions later would have faulted at address 8,
and it did not. So "the allocation failed" is dead.

What is left is `str x0, [x19, #8]`. It addresses the object through **x19, a
callee-saved register held across a call into another library**. Either the
store was dropped, or x19 did not come back intact and the store landed
somewhere else -- which would leave `mRefs` zero and raise no fault at the time,
matching the evidence exactly.

`tests/manual/arm64/hle_callee_saved.c` asserts that ABI directly. It passes
under the harness -- **and that is not yet evidence**, because with
`ISH_HLE_STATS=1` the harness prints no HLE stats at all (nor does `hle_loop`):
`jit/hle-table.inc` identifies a libc by the exact 64 bytes at each function's
entry, and the harness's Alpine musl build is not among the fingerprinted ones.
So on that host the test is a control. `operator new` is not itself hooked, but
an allocator runs `mem*`/`str*` internally, so an HLE'd call -- leaving the
emulator, running native C, returning -- happens inside every allocation on a
libc that IS fingerprinted. bionic is. Run the probe on the device.

**Two setup facts this cost a round each to learn.** `idmap2d` needs
`servicemanager` already running, or it exits 1 with `Failed to start: -129`
(`Status::EX_TRANSACTION_FAILED`) and never reaches the crash at all. And
`pgrep -f servicemanager` matches the driving shell's own argv when run through
`ish-remote.sh`, exactly as `pkill -f` does, so a "is it already running?"
guard silently skips starting it. Start it unconditionally.

**There are no tombstones, and there will not be.** Android's own account of a
native crash comes from `debuggerd`, which forks `crash_dump64` (it lives in
`/apex/com.android.runtime/bin/`, not `/system/bin`). That process execs fine
by hand, but in the crash path it hangs and bionic gives up after ~30s with
`crash_dump helper failed to exec, or was killed` -- the 31 seconds between the
crash line and that line in `dmesg` is the whole diagnosis. It needs
`tombstoned` on `/dev/socket/tombstoned` to hand it somewhere to write, and
that socket does not exist. A tombstoned sink is buildable the same way the
logd one was, but it passes file descriptors rather than datagrams, so it is a
bigger job than `kernel/logd_sink.c` and has not been done.

**Do not go looking for a stack trace before reading what is already there.**
iSH reports a fatal guest fault itself, with more than a tombstone would give
for this purpose:

```
ERROR: 5(segv) [i386] page fault on 0 at 0x804988f (write)
opcode window around 0x804988f: 00 8b 45 fc [c7]00 01 00 00 00 b8 ...
stack at ffffdd58, base at ffffdd68, ip at 804988f
```

That was in `dmesg` the whole time. It went unnoticed for a round because every
command in this session filtered `dmesg` through `grep logd/`, which drops it.
An hour went into deciding whether to add a fault-location printk before
noticing the emulator already prints one. **Grep `dmesg` for `page fault` and
`ERROR:` as well as `logd/`.**

### A restart leaves a socket that looks alive

`/dev/socket/logdw` in a tree is a fakefs inode, so it SURVIVES an app restart
-- but the host socket behind it does not. `ls -la` then shows a perfectly good
`srw-rw-rw-` that nothing is bound to, and Android's logging silently goes
nowhere again. `chroot-setup.sh` rebuilds it, which is why it now writes
`/proc/ish/logd`; the trap is only for someone checking by hand and concluding
from the node that the sink is fine.

The other half of the same restart is the documented one: mounts are gone, so
`/proc` is not in the tree and every Android daemon dies early with
`Bad boot_id: ''`. Both are one `chroot-setup.sh` away.

### The merge did not break Android

Checked on device against build 548, i.e. after the 108-commit upstream sync
that included the arm64 `br`/`blr`/`ret` return-cache change -- exactly the
kind of thing that could break a large binary quietly:

```
Found 2 services:
0	incident: [android.os.IIncidentManager]
1	manager: [android.os.IServiceManager]

manager    Service manager: found
incident   Service incident: found
nosuch     Service nosuch: not found
```

## Two ways to be wrong for a long time

Both of the expensive bugs in this document -- the tagged pointers and
`checkService` -- cost far more than they should have, and for the same
underlying reason each time: a piece of evidence was trusted to mean more than
it actually meant. They are worth naming, because both will recur.

**"The fault is at this instruction" is not "this instruction is at fault."**
The tagged-pointer bug was reported at `dup v0.16b, w1` and `add x4, x1, x2` --
`memset`'s and `memcpy`'s first instructions, neither of which touches memory.
That is because `jit/hle.c` hooks a libc function at its *entry point*, so an
HLE'd call always faults at the callee's first instruction whatever the real
cause. A day went into the SIMD gadgets, instruction fusion and the
fault-restart contract, all innocent. **If a fault is attributed to an
instruction with no memory operand, the first hypothesis is that something is
intercepting the function, not that the instruction is wrong.** Whoever is
intercepting it is where to look.

**A passing test rules out only what it encodes, not what it was written for.**
`checkService` was blamed on libbinder for a full round because three driver
tests covering the right protocol shapes all passed -- and all three happened to
place their object at an 8-aligned offset, which was the entire bug. No test
asserted that alignment; they simply agreed on it, silently, because they were
all written the same way. **When a test suite clears a component, ask what the
tests hold constant that the real caller does not.** Here the answer was written
down in the same paragraph as the exoneration ("our own tests replicate the
protocol shape faithfully but not libbinder's exact parcel") and read as a
caveat instead of a lead.

**You do not know what code a device is running until you make it prove it.**
Confirming the `checkService` fix began with a confident and wrong assertion --
that the device must still have the old binary, because a fix committed an hour
ago could not be on a phone yet. It was: CI builds a dev IPA on every push to
`working`, and the device had installed one. The version string is no help
(`iSH-AOK 1.3 (547)`, zeroed build date), and neither is arithmetic about who
had time to install what. What settled it was a twenty-line probe that asks the
driver which alignment rule it implements, run first against known-good and
known-bad local builds and then against the device. **Fingerprint the
behaviour; do not date the binary.**

**A test that crashes is not yet evidence about the thing you are testing.**
`thread_identity.c` was written to test whether iSH gives binder pool threads
their own stacks and TLS, and it segfaulted on the first run -- on the exact
operation it was probing, a `__thread` write. That is as close to a confirmed
hypothesis as a first run ever looks. Running it under plain qemu-user with no
iSH in the picture at all took one minute and it crashed there too, which
turned "the emulator loses thread TLS" into "the harness links every test
against the wrong libc" (see the harness section below). **Before a failure is
attributed to the component under test, run it without that component.** Here
the component was removable in a single command; when it is not, that cost is
worth paying anyway.

The common shape in all four: a strong signal -- a precise PC, a green suite,
a plausible timeline -- was treated as an answer when it was only evidence
about a narrower question. The cheap diagnostics in this document
(`/proc/ish/binder`, `/proc/ish/property_area`, `dmesg`, `binder_ping`) and a
throwaway probe like the one above are worth more than any of them, because
they report state rather than inviting an inference. `ish-remote.sh` makes that
kind of probe cost about a minute, which is the whole reason it exists.

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

1. **The two null dereferences.** `installd` faults at `0x0` just after
   `installd firing up`; `idmap2d` faults at `0x4` in a binder thread just
   after registering `idmap`. Start from iSH's own `page fault ... opcode
   window` line in `dmesg` -- it names the guest PC and, via `pc-backing` and
   `lr-backing`, the library and file offset of both the faulting instruction
   and its caller -- rather than waiting on a tombstone that will not come.

   For `idmap2d` the function is known (`RefBase::incStrong` with a null
   `mRefs`) and so is the object's state: a valid vptr with `mRefs` unwritten,
   deterministically. See that section for what it rules out. The next step is
   `tests/manual/arm64/hle_callee_saved.c` run ON THE DEVICE. The constructor
   is now disassembled (see the idmap2d section): the missing store addresses
   the object through `x19`, held across `bl _Znwm@plt`. Either the store was
   dropped or `x19` did not survive the call. A minimal C++ virtual-inheritance
   repro passes under the harness, and so does the register probe -- but with
   `ISH_HLE_STATS=1` the harness prints no HLE stats at all, so **that pass is
   a control and rules nothing out**: `jit/hle-table.inc` matches a libc by its
   exact entry bytes and the harness's musl is not one of them. `gcc` is on the
   device, so compile and run the probe there, against bionic, where the
   fingerprints do match.

   Apply the same treatment to `installd` rather than assuming it is the same
   bug: its fault address is `0x0`, not `0x4`, so it is at best the same
   *class*.
2. **A `tombstoned` sink**, if those two do not yield to the above. It would
   give Android's own stack traces for every native crash. Same shape as
   `kernel/logd_sink.c` but with fd passing, so a bigger job; worth it only if
   the crashes resist the cheaper route.
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

## The dropped poll wakeup: fixed, and the scare was half real

`binder_wakeup_proc` and `binder_wakeup_thread` used to reach pollers through
`poll_wakeup_trylock`, which **discards** the wakeup when it cannot take the
lock. The trylock was not gratuitous: these run under `binder_lock`, and a
blocking `poll_wakeup()` there takes `fd->poll_lock -> poll->lock` while a poll
scan calling `binder_poll` takes `poll->lock -> binder_lock` -- the reverse
order, so two threads hitting both at once AB-BA deadlock.

**Fixed** by deferring instead of discarding: `binder_defer_wakeup()` records
the fd under the lock, and `binder_unlock()` -- which every one of the 19
unlock sites now calls -- delivers it with the blocking, non-lossy
`poll_wakeup()` immediately after the release. The subtle part is
`binder_thread_read`: `wait_for` only drops `binder_lock` once the thread is
already committed to sleeping, so a wakeup still queued at that point would
not go out until this thread was itself woken -- and the process waiting on it
may be the only one who could do the waking. It flushes and re-runs the loop
before parking, which is the difference between this fix and a deadlock.

**What the measurements actually showed**, because the doc used to assert more
than was known ("would sleep forever ... has never reproduced"):

- **The discard is real and easy to provoke.** With `poll_wakeup_trylock`
  instrumented, `tests/manual/binder_poll_wakeup_probe.c` drops roughly 3,100
  of 12,000 wakeups per run.
- **It never produced a stall.** Not in any of four configurations, including
  single-transaction trials where the wakeup was dropped on *every* one of 12
  runs and the transaction still arrived every time.
- **The reason is the awkward part.** To make the trylock fail you need a
  concurrent holder of `poll->lock`, and in this design any such holder is
  itself scanning. epoll here is level-triggered, so that scan recomputes
  readiness from `binder_poll` and finds the queued work regardless of the lost
  poke. Remove the scanner and the contention goes with it -- 0 failures. The
  thing that breaks the wakeup is also the thing that covers for it.

So the honest status is: the old code was **unsound** (a discarded wakeup with
no guaranteed second chance) and demonstrably discarded wakeups in bulk, but no
sequence was found that strands a receiver. The fix is cheap, removes the
mechanism rather than the symptom, and costs nothing across both suites -- worth
having on those grounds alone. It should not be described as having fixed an
observed hang, because it did not.

The probe is kept as a diagnostic rather than a test, precisely because it
passes either way. Anyone revisiting this should start by trying to build the
one case the argument above does not cover: contention arriving from a scan
that has *already passed* the binder fd, and then stopping, so nothing rescans.

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
real on an x86_64 development machine. All eleven tests pass there today.

**Every test binary it built used to be statically linked musl carrying a
`PT_INTERP`,** and nothing said so. `musl-dev` ships `usr/lib/libc.so` as a
symlink to the ldso, but the ldso lives in the `musl` package, so inside the
harness's sysroot that symlink dangled; lld cannot follow it, says nothing, and
satisfies `-lc` from `libc.a` instead. The binaries then ran with two copies of
libc: the dynamic musl set the main thread's TLS up from `PT_TLS`, while
`pthread_create` came from the static copy, whose `libc.tls_size` its own
`__init_tls` never filled in. So a spawned thread's TLS block was sized as
though the program had no TLS at all. One `__thread` variable fitted in the
slack; **the second one faulted on first write, in the thread, with no
diagnostic** -- which reads exactly like the emulator faulting on a plain TLS
store, and is an expensive thing to believe while hunting an emulator bug.

The fix is to copy the ldso into the sysroot so `-lc` resolves to the real
shared libc, plus a one-function `__getauxval` shim (Alpine defines that alias
only in `libc.a`, and libgcc's LSE-atomics initializer calls it -- it had been
resolving through the same accidental static link). The runner now also
verifies each binary has a `DT_NEEDED` for libc and fails loudly if it does
not, because the failure mode is silent and points at the wrong component.

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
