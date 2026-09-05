#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/binfmt_misc.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "util/sync.h"
#include "debug.h"

// See kernel/binfmt_misc.h for why this is implemented rather than faked.
//
// Format of a `register` line, from Linux's fs/binfmt_misc.c:
//
//   :name:type:offset:magic:mask:interpreter:flags
//
// The delimiter is whatever the first character is -- ':' by convention, and
// update-binfmts uses '|' when a magic contains a colon, so it must be taken
// from the string rather than assumed. type is 'M' (magic) or 'E' (extension).
// For 'E' the offset is unused and `magic` is the filename suffix. magic and
// mask are \xNN-escaped byte strings for 'M' and are matched byte-for-byte
// under the mask at the given offset.

#define BINFMT_NAME_MAX 128
#define BINFMT_MAGIC_MAX 128
#define BINFMT_INTERP_MAX 1024

struct binfmt_entry {
    char name[BINFMT_NAME_MAX];
    bool enabled;
    bool extension;                     // 'E' rather than 'M'
    size_t offset;
    unsigned char magic[BINFMT_MAGIC_MAX];
    unsigned char mask[BINFMT_MAGIC_MAX];
    size_t magic_len;
    bool has_mask;
    char interpreter[BINFMT_INTERP_MAX];
    char flags[8];                      // as written, for the `flags:` line
    bool preserve_argv0;                // 'P'
    struct binfmt_entry *next;
};

static lock_t binfmt_lock = LOCK_INITIALIZER;
static struct binfmt_entry *binfmt_entries;
static _Atomic bool binfmt_mounted;
// Linux boots with binfmt_misc ENABLED once mounted; `status` reads "enabled".
static _Atomic bool binfmt_global_enabled = true;

bool binfmt_misc_is_mounted(void) {
    return atomic_load_explicit(&binfmt_mounted, memory_order_relaxed);
}
void binfmt_misc_set_mounted(bool mounted) {
    atomic_store_explicit(&binfmt_mounted, mounted, memory_order_relaxed);
}
bool binfmt_misc_enabled(void) {
    return atomic_load_explicit(&binfmt_global_enabled, memory_order_relaxed);
}
void binfmt_misc_set_enabled(bool enabled) {
    atomic_store_explicit(&binfmt_global_enabled, enabled, memory_order_relaxed);
}

static void binfmt_free_all_locked(void) {
    struct binfmt_entry *e = binfmt_entries;
    binfmt_entries = NULL;
    while (e != NULL) {
        struct binfmt_entry *next = e->next;
        free(e);
        e = next;
    }
}

void binfmt_misc_clear_all(void) {
    lock(&binfmt_lock, 0);
    binfmt_free_all_locked();
    unlock(&binfmt_lock);
}

// One field of the delimiter-separated spec. Advances *p past the delimiter.
// Returns NULL when the spec ends early, which every caller treats as EINVAL.
static char *binfmt_field(char **p, char delim) {
    char *start = *p;
    if (start == NULL)
        return NULL;
    char *end = strchr(start, delim);
    if (end == NULL)
        return NULL;
    *end = '\0';
    *p = end + 1;
    return start;
}

// \xNN unescaping, in place. Returns the byte count, or -1 on a bad escape.
// Linux accepts only \x escapes here; a literal backslash is written \x5c.
static ssize_t binfmt_unescape(const char *in, unsigned char *out, size_t out_max) {
    size_t n = 0;
    while (*in != '\0') {
        if (n >= out_max)
            return -1;
        if (in[0] == '\\' && in[1] == 'x') {
            char hex[3] = {in[2], in[3], '\0'};
            if (hex[0] == '\0' || hex[1] == '\0')
                return -1;
            char *endp = NULL;
            long v = strtol(hex, &endp, 16);
            if (endp != hex + 2 || v < 0 || v > 255)
                return -1;
            out[n++] = (unsigned char) v;
            in += 4;
        } else {
            out[n++] = (unsigned char) *in++;
        }
    }
    return (ssize_t) n;
}

static struct binfmt_entry *binfmt_find_locked(const char *name) {
    for (struct binfmt_entry *e = binfmt_entries; e != NULL; e = e->next)
        if (strcmp(e->name, name) == 0)
            return e;
    return NULL;
}

bool binfmt_misc_exists(const char *name) {
    lock(&binfmt_lock, 0);
    bool found = binfmt_find_locked(name) != NULL;
    unlock(&binfmt_lock);
    return found;
}

int binfmt_misc_register(const char *spec, size_t len) {
    if (len == 0)
        return _EINVAL;
    char buf[BINFMT_INTERP_MAX + BINFMT_MAGIC_MAX * 4 + BINFMT_NAME_MAX + 64];
    if (len >= sizeof(buf))
        return _EINVAL;
    memcpy(buf, spec, len);
    buf[len] = '\0';
    // A trailing newline is normal -- `echo :name:... > register`.
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    if (len < 2)
        return _EINVAL;

    // The delimiter is the FIRST character, not necessarily ':'. update-binfmts
    // switches to '|' when a magic contains a colon, so assuming ':' would
    // reject registrations Linux accepts.
    char delim = buf[0];
    char *p = buf + 1;

    char *name = binfmt_field(&p, delim);
    char *type = binfmt_field(&p, delim);
    char *offset_s = binfmt_field(&p, delim);
    char *magic_s = binfmt_field(&p, delim);
    char *mask_s = binfmt_field(&p, delim);
    char *interp = binfmt_field(&p, delim);
    char *flags = p;                    // last field, no trailing delimiter needed
    if (name == NULL || type == NULL || offset_s == NULL || magic_s == NULL ||
        mask_s == NULL || interp == NULL)
        return _EINVAL;
    if (name[0] == '\0' || strlen(name) >= BINFMT_NAME_MAX)
        return _EINVAL;
    // Linux refuses a name with '/' -- it would escape the directory.
    if (strchr(name, '/') != NULL)
        return _EINVAL;
    if (interp[0] == '\0' || strlen(interp) >= BINFMT_INTERP_MAX)
        return _EINVAL;
    if (type[0] == '\0' || type[1] != '\0')
        return _EINVAL;

    struct binfmt_entry *e = calloc(1, sizeof(*e));
    if (e == NULL)
        return _ENOMEM;
    strncpy(e->name, name, sizeof(e->name) - 1);
    strncpy(e->interpreter, interp, sizeof(e->interpreter) - 1);
    if (flags != NULL)
        strncpy(e->flags, flags, sizeof(e->flags) - 1);
    e->enabled = true;
    e->preserve_argv0 = strchr(e->flags, 'P') != NULL;

    if (type[0] == 'E') {
        e->extension = true;
        // The "magic" is a filename suffix, taken literally.
        if (magic_s[0] == '\0' || strlen(magic_s) >= BINFMT_MAGIC_MAX) {
            free(e);
            return _EINVAL;
        }
        memcpy(e->magic, magic_s, strlen(magic_s));
        e->magic_len = strlen(magic_s);
    } else if (type[0] == 'M') {
        e->offset = offset_s[0] == '\0' ? 0 : (size_t) strtoul(offset_s, NULL, 10);
        ssize_t mlen = binfmt_unescape(magic_s, e->magic, sizeof(e->magic));
        if (mlen <= 0) {
            free(e);
            return _EINVAL;
        }
        e->magic_len = (size_t) mlen;
        if (mask_s[0] != '\0') {
            ssize_t masklen = binfmt_unescape(mask_s, e->mask, sizeof(e->mask));
            // Linux requires the mask to be the same length as the magic.
            if (masklen != (ssize_t) e->magic_len) {
                free(e);
                return _EINVAL;
            }
            e->has_mask = true;
        }
        if (e->offset + e->magic_len > BINFMT_MAGIC_MAX) {
            free(e);
            return _EINVAL;
        }
    } else {
        free(e);
        return _EINVAL;
    }

    lock(&binfmt_lock, 0);
    if (binfmt_find_locked(e->name) != NULL) {
        unlock(&binfmt_lock);
        free(e);
        return _EEXIST;             // Linux: a duplicate name is EEXIST
    }
    e->next = binfmt_entries;
    binfmt_entries = e;
    unlock(&binfmt_lock);
    return 0;
}

bool binfmt_misc_name_at(size_t index, char *buf, size_t bufsize) {
    lock(&binfmt_lock, 0);
    size_t i = 0;
    for (struct binfmt_entry *e = binfmt_entries; e != NULL; e = e->next, i++) {
        if (i == index) {
            strncpy(buf, e->name, bufsize - 1);
            buf[bufsize - 1] = '\0';
            unlock(&binfmt_lock);
            return true;
        }
    }
    unlock(&binfmt_lock);
    return false;
}

// Byte-for-byte the body Linux shows, captured from a Debian 13 box:
//
//   enabled
//   interpreter /usr/bin/lli-19
//   flags:
//   offset 0
//   magic 4243
//
// with "extension <suffix>" in place of offset/magic for an 'E' registration,
// and "disabled" on the first line when the entry is off.
int binfmt_misc_show(const char *name, char *buf, size_t bufsize, size_t *len_out) {
    lock(&binfmt_lock, 0);
    struct binfmt_entry *e = binfmt_find_locked(name);
    if (e == NULL) {
        unlock(&binfmt_lock);
        return _ENOENT;
    }
    int n = snprintf(buf, bufsize, "%s\ninterpreter %s\nflags: %s\n",
                     e->enabled ? "enabled" : "disabled", e->interpreter, e->flags);
    if (n < 0 || (size_t) n >= bufsize) {
        unlock(&binfmt_lock);
        return _EINVAL;
    }
    size_t used = (size_t) n;
    if (e->extension) {
        n = snprintf(buf + used, bufsize - used, "extension .%.*s\n",
                     (int) e->magic_len, (const char *) e->magic);
    } else {
        n = snprintf(buf + used, bufsize - used, "offset %zu\nmagic ", e->offset);
        if (n > 0 && (size_t) n < bufsize - used) {
            used += (size_t) n;
            for (size_t i = 0; i < e->magic_len && used + 2 < bufsize; i++) {
                snprintf(buf + used, bufsize - used, "%02x", e->magic[i]);
                used += 2;
            }
            if (e->has_mask && used + 6 < bufsize) {
                n = snprintf(buf + used, bufsize - used, "\nmask ");
                used += (size_t) n;
                for (size_t i = 0; i < e->magic_len && used + 2 < bufsize; i++) {
                    snprintf(buf + used, bufsize - used, "%02x", e->mask[i]);
                    used += 2;
                }
            }
            n = snprintf(buf + used, bufsize - used, "\n");
        }
    }
    if (n < 0) {
        unlock(&binfmt_lock);
        return _EINVAL;
    }
    used += (size_t) n;
    unlock(&binfmt_lock);
    if (len_out != NULL)
        *len_out = used;
    return 0;
}

int binfmt_misc_control(const char *name, const char *value, size_t len) {
    char v[8] = "";
    size_t n = len < sizeof(v) - 1 ? len : sizeof(v) - 1;
    memcpy(v, value, n);
    v[n] = '\0';
    while (n > 0 && (v[n - 1] == '\n' || v[n - 1] == '\r'))
        v[--n] = '\0';

    lock(&binfmt_lock, 0);
    struct binfmt_entry *prev = NULL;
    for (struct binfmt_entry *e = binfmt_entries; e != NULL; prev = e, e = e->next) {
        if (strcmp(e->name, name) != 0)
            continue;
        if (strcmp(v, "-1") == 0) {
            if (prev == NULL)
                binfmt_entries = e->next;
            else
                prev->next = e->next;
            unlock(&binfmt_lock);
            free(e);
            return 0;
        }
        if (strcmp(v, "0") == 0) {
            e->enabled = false;
            unlock(&binfmt_lock);
            return 0;
        }
        if (strcmp(v, "1") == 0) {
            e->enabled = true;
            unlock(&binfmt_lock);
            return 0;
        }
        unlock(&binfmt_lock);
        return _EINVAL;
    }
    unlock(&binfmt_lock);
    return _ENOENT;
}

bool binfmt_misc_match(const char *file, const char *header, size_t header_len,
                       char *interp, size_t interp_size, bool *preserve_argv0) {
    if (!binfmt_misc_enabled())
        return false;               // the global switch is off; Linux keeps the
                                    // registrations and stops consulting them
    lock(&binfmt_lock, 0);
    for (struct binfmt_entry *e = binfmt_entries; e != NULL; e = e->next) {
        if (!e->enabled)
            continue;
        bool hit = false;
        if (e->extension) {
            // Match the filename suffix, after the last '.'.
            const char *dot = strrchr(file, '.');
            hit = dot != NULL && dot[1] != '\0' &&
                  strlen(dot + 1) == e->magic_len &&
                  memcmp(dot + 1, e->magic, e->magic_len) == 0;
        } else if (e->offset + e->magic_len <= header_len) {
            const unsigned char *at = (const unsigned char *) header + e->offset;
            hit = true;
            for (size_t i = 0; i < e->magic_len; i++) {
                unsigned char m = e->has_mask ? e->mask[i] : 0xff;
                if ((at[i] & m) != (e->magic[i] & m)) {
                    hit = false;
                    break;
                }
            }
        }
        if (hit) {
            strncpy(interp, e->interpreter, interp_size - 1);
            interp[interp_size - 1] = '\0';
            if (preserve_argv0 != NULL)
                *preserve_argv0 = e->preserve_argv0;
            unlock(&binfmt_lock);
            return true;
        }
    }
    unlock(&binfmt_lock);
    return false;
}
