#ifndef KERNEL_BINFMT_MISC_H
#define KERNEL_BINFMT_MISC_H

#include <stdbool.h>
#include <stddef.h>
#include "misc.h"

// binfmt_misc: run a binary through a registered interpreter.
//
// This is implemented for real, and that is the point. /proc/sys/fs/binfmt_misc
// used to present `register` and `status` with nothing behind them -- writes
// were accepted and discarded, `status` always read "enabled" -- and it was
// removed because update-binfmts and systemd-binfmt believe the success they
// are handed, so a guest looked configured and then silently ran nothing. An
// empty directory replaced it as the truthful state.
//
// The rule that follows: a registration that appears here MUST affect execve,
// or the empty directory was the better answer.

struct fd;

// Is the filesystem mounted? Linux shows an empty directory until then, and
// `register`/`status` exist only once it is mounted.
bool binfmt_misc_is_mounted(void);
void binfmt_misc_set_mounted(bool mounted);

// The global switch `status` reads and writes. Registrations survive it being
// turned off; Linux keeps them and simply stops consulting them.
bool binfmt_misc_enabled(void);
void binfmt_misc_set_enabled(bool enabled);
// `echo -1 > status` removes every registration.
void binfmt_misc_clear_all(void);

// One `:name:type:offset:magic:mask:interpreter:flags` line, as written to
// `register`. Returns 0, or a negative kernel/errno.h code.
int binfmt_misc_register(const char *spec, size_t len);

// Enumeration, for the procfs directory. Returns false when index is past the
// end. The name is copied into buf.
bool binfmt_misc_name_at(size_t index, char *buf, size_t bufsize);
// The five-line body Linux shows for one registration, into buf.
int binfmt_misc_show(const char *name, char *buf, size_t bufsize, size_t *len_out);
// Writes to one registration's file: "-1" removes it, "0" disables, "1" enables.
int binfmt_misc_control(const char *name, const char *value, size_t len);
bool binfmt_misc_exists(const char *name);

// The exec hook. Given an opened executable and its first bytes, find the
// interpreter that claims it. Returns true and fills interp (a PATH_MAX buffer)
// when one matches. preserve_argv0 reports the registration's P flag.
bool binfmt_misc_match(const char *file, const char *header, size_t header_len,
                       char *interp, size_t interp_size, bool *preserve_argv0);

#endif
