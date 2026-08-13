# The deferred binder poll wakeup: written, tested once, NOT landed

This is a design note plus the exact change, recorded because the session that
wrote it lost its shell before it could commit. **The code below is not in the
tree.** It was implemented, built, and passed `check-fork-additions.sh` and the
i386 guest suite 8/8; it was then temporarily reverted to measure the old
behaviour, and the session was cut off before it could be rebuilt and
committed. Treat it as a reviewed patch awaiting a build, not as folklore.

## The bug

`docs/android-bringup.md` has carried this under "Known latent issue":

> `binder_wakeup_proc` and `binder_wakeup_thread` reach pollers through
> `poll_wakeup_trylock`, which discards the wakeup when it cannot take the
> lock. That is harmless for a client blocking in `BINDER_WRITE_READ`, which
> also gets `notify()`, but an epoll-driven receiver -- which is what real
> Android is -- has no second chance and would sleep forever with a
> transaction queued.

The trylock is not gratuitous. `binder_wakeup_*` runs under `binder_lock`, and
a blocking `poll_wakeup()` there takes `fd->poll_lock -> poll->lock`, while a
poll scan calling `binder_poll` takes `poll->lock -> binder_lock`. Two threads
hitting both at once AB-BA deadlock. `poll_wakeup_trylock` avoids the deadlock
by dropping the wakeup, which is the right trade for signalfd (its readiness is
recomputed on the next scan) and the wrong one for binder, where the queued
transaction is the only thing that will ever make the fd readable.

## What was measured

Under the existing suite the trylock **never fails**: instrumenting
`poll_wakeup_trylock` to count outcomes across a full `binder_ipc` run gave

```
TRYLOCK-PROBE outer_ok 38 outer_fail 0 inner_fail 0
```

which is exactly why this has "never reproduced" -- `binder_ipc`'s poll phase
has one receiver and no concurrent scanner, so there is nothing to contend
with. A stress case that deliberately collides an epoll scan with a flood of
oneway transactions was written (`N=4000`, receiver driven purely by
`epoll_wait`, sender in a forked child) but never got to run. **That is the
first thing to do before trusting any of this**: if it shows `outer_fail` or
`inner_fail` going non-zero, the drop is reachable and this fix is load-bearing
rather than theoretical.

Note the fix is worth making either way -- a discarded wakeup with no second
chance is unsound by construction -- but "we never saw it fail" is the kind of
evidence this project has already been burned by twice (see "Two ways to be
wrong for a long time" in `docs/android-bringup.md`). Measure it.

## The change

Defer the poke until `binder_lock` is dropped, then deliver it with the
blocking, non-lossy `poll_wakeup()`.

### 1. The deferred list, next to `binder_lock` in `kernel/binder.c`

```c
#define BINDER_DEFERRED_WAKEUPS_MAX 8
static struct {
    struct fd *fds[BINDER_DEFERRED_WAKEUPS_MAX];
    unsigned n;
} binder_deferred_wakeups;

// Deduplicated, because one critical section routinely wakes the same process
// more than once (work queued plus a completion). fd_retain_if_live, not
// fd_retain: a concurrent last close may already have taken the refcount to
// zero, and resurrecting it there would race that close's free.
static void binder_defer_wakeup(struct fd *fd) {
    if (fd == NULL)
        return;
    for (unsigned i = 0; i < binder_deferred_wakeups.n; i++)
        if (binder_deferred_wakeups.fds[i] == fd)
            return;
    if (binder_deferred_wakeups.n == BINDER_DEFERRED_WAKEUPS_MAX) {
        // Fall back to the old best-effort poke rather than dropping it
        // outright: no worse than what this replaces, and the dedupe above
        // makes reaching it very unlikely.
        poll_wakeup_trylock(fd, POLL_READ);
        return;
    }
    struct fd *held = fd_retain_if_live(fd);
    if (held == NULL)
        return; // already being closed; nothing there to wake
    binder_deferred_wakeups.fds[binder_deferred_wakeups.n++] = held;
}

static bool binder_have_deferred_wakeups(void) {
    return binder_deferred_wakeups.n > 0;
}

// Releases binder_lock and then delivers whatever accumulated under it.
static void binder_unlock(void) {
    struct fd *fds[BINDER_DEFERRED_WAKEUPS_MAX];
    unsigned n = binder_deferred_wakeups.n;
    for (unsigned i = 0; i < n; i++)
        fds[i] = binder_deferred_wakeups.fds[i];
    binder_deferred_wakeups.n = 0;

    unlock(&binder_lock);

    for (unsigned i = 0; i < n; i++) {
        poll_wakeup(fds[i], POLL_READ);
        fd_close(fds[i]);
    }
}
```

### 2. The two wakeup helpers stop poking directly

```c
static void binder_wakeup_proc(struct binder_proc *proc) {
    struct binder_thread *thread;
    list_for_each_entry(&proc->threads, thread, proc_link) {
        if (thread->waiting && thread->wait_for_proc_work)
            notify(&thread->wait);
    }
    binder_defer_wakeup(proc->fd);          // was poll_wakeup_trylock(proc->fd, ...)
}

static void binder_wakeup_thread(struct binder_thread *thread) {
    if (thread->waiting)
        notify(&thread->wait);
    binder_defer_wakeup(thread->proc->fd);  // was poll_wakeup_trylock(...)
}
```

### 3. Every `unlock(&binder_lock)` becomes `binder_unlock()`

19 sites. The only one that stays a bare `unlock(&binder_lock)` is the one
inside `binder_unlock()` itself.

### 4. The blocking read must flush before it parks

This is the part that is easy to miss and would make things *worse* than the
trylock if skipped. `binder_thread_read` waits with
`wait_for(&thread->wait, &binder_lock, NULL)`, which only drops `binder_lock`
once the thread is already committed to sleeping. A wakeup still sitting in the
deferred list at that point would not go out until this thread was itself
woken -- and the process waiting on that wakeup may be the only one who could
ever do the waking. Deadlock by politeness.

In `binder_thread_read`, immediately before `thread->waiting = true;`:

```c
if (binder_have_deferred_wakeups()) {
    binder_unlock();
    lock(&binder_lock, 0);
    if (thread->is_dead)
        return _EBADF;
    continue;   // dropping the lock changes everything; re-evaluate
}
```

The `continue` matters: the surrounding loop re-checks `thread->todo` and
`proc->todo`, so work that arrived while the lock was down is picked up instead
of slept through.

## Checklist for whoever lands this

1. Apply the four pieces above.
2. Build; `sh tools/check-fork-additions.sh`.
3. `bash tools/run-guest-tests.sh build` -- expect 8/8.
4. `bash tools/run-arm64-guest-tests.sh` -- expect 9/9.
5. Run the contention stress described under "What was measured" against a
   build with the OLD trylock wakeups first, and record whether the drop is
   reachable. That number belongs in `docs/android-bringup.md`, replacing the
   "Known latent issue" section either way.
6. Consider promoting the stress case into `tests/manual/binder_ipc.c` as a
   phase, so the epoll delivery path has a receiver that can actually stall.
