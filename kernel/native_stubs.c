// The native-program subsystem, for hosts that cannot build it.
//
// WHY THIS EXISTS. kernel/native_libc.c is written against BSD/macOS libc and
// does not compile on glibc: funopen(), BSD `struct statfs`, the sockaddr
// sa_len fields, dirent's d_namlen, an fpos_t that is interchangeable with
// off_t, and static assertions that posix_spawn's opaque types are plain
// pointers. Those are not oversights -- they are what the file is written
// against, and the iOS build is the only one that has to run it.
//
// The trouble is that a Linux host is not optional here. It is where the guest
// regression suites run: tools/run-guest-tests.sh (binder, ashmem, dma_heap,
// selinuxfs, kmsg, property_area) and tools/run-arm64-guest-tests.sh, which is
// the ONLY automated cover the arm64 gadget set has anywhere. When upstream's
// native work landed, all of it stopped building, and with it every gate this
// fork has, on a change that is invisible to the iOS build.
//
// So on a non-Darwin host, meson.build builds this file in place of
// kernel/native.c, native_io.c, native_libc.c and smallclue_glue.c, and drops
// the SmallCLUE/nextvi/bash archives. Nothing is lost that a Linux build can
// use: the guest suites never invoke a native applet, and a build with no
// native programs is a state the design already accounts for -- exec falls
// through to the ordinary path and /AOK/native serves an empty directory,
// exactly as it does on an iOS build whose submodules were never populated.
//
// DELIBERATELY NOT A PORT of native_libc.c. Upstream is actively developing
// that file, so carrying local edits in it would conflict on every sync; and a
// port would be emulating funopen through fopencookie to make an iOS feature
// run on a host that never exercises it. Nothing here edits an upstream file,
// which is the point -- there is nothing for a future merge to fight with.
//
// If a native program ever needs to run on Linux, this file is the wrong
// answer and native_libc.c should be ported properly.

#include <stddef.h>
#include <stdbool.h>

#include "kernel/native.h"
#include "kernel/errno.h"

// No programs are compiled in. native_program_lookup returning NULL is the
// documented "not in this build" answer, so exec falls through to the ordinary
// path rather than failing, and fs/aok.c serves /AOK/native as empty.
const struct native_program *native_program_lookup(const char *name) {
    (void) name;
    return NULL;
}

size_t native_program_count(void) {
    return 0;
}

const struct native_program *native_program_at(size_t index) {
    (void) index;
    return NULL;
}

// Unreachable in practice: exec only calls this after a successful lookup, and
// lookup never succeeds here. Answering ENOSYS rather than asserting keeps a
// future caller that skips the lookup from taking the process down.
int native_exec_set_pending(const struct native_program *prog, int argc,
        char *const argv[], char *const envp[]) {
    (void) prog; (void) argc; (void) argv; (void) envp;
    return _ENOSYS;
}

// Called unconditionally on every exec path and at task teardown, so these are
// the ones that actually run. Nothing is ever pending, so nothing to do.
void native_exec_run_pending(void) {
}

void native_exec_discard_pending(struct task *task) {
    (void) task;
}

void native_checkpoint(void) {
}

// The native environment block belongs to a running native program. With none,
// there is nothing to initialise, hand out or free. native_env_slot must still
// return a valid pointer rather than NULL -- callers dereference it to read the
// vector, and an empty vector is the correct answer here.
static char **native_env_empty = NULL;

void native_env_init(char *const envp[]) {
    (void) envp;
}

void native_env_discard(struct task *task) {
    (void) task;
}

char **native_env_vector(void) {
    return NULL;
}

char ***native_env_slot(void) {
    return &native_env_empty;
}

const char *native_env_get(const char *name) {
    (void) name;
    return NULL;
}

int native_env_set(const char *name, const char *value, bool overwrite) {
    (void) name; (void) value; (void) overwrite;
    return 0;
}

int native_env_unset(const char *name) {
    (void) name;
    return 0;
}
