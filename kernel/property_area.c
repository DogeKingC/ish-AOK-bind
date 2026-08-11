// Android's system property area. See kernel/property_area.h for why this
// exists and which of bionic's three layouts it writes.
//
// The on-disk structure, from bionic's prop_area.cpp:
//
//   0                    the 128-byte header: bytes_used, serial, magic,
//                        version, 28 reserved words
//   128                  the data area. Every offset stored inside the file is
//                        relative to here, not to the start of the file.
//     data+0             the root trie node, all zero
//     data+20            the "dirty backup area", 92 bytes bionic reserves so
//                        a reader racing a value update has somewhere
//                        consistent to read from. We never write it -- there
//                        is no writer -- but the space has to be there,
//                        because bionic computes it as a fixed offset rather
//                        than storing it.
//     data+112 onward    trie nodes, prop_infos and long values, in the order
//                        they were added, each 4-byte aligned
//
// Names are split on '.' into a trie; siblings at one level form a binary
// search tree ordered by (length, then strncmp) -- length first, which is
// bionic's cmp_prop_name and not what anyone would guess. A prop_info hangs
// off the node for the last component.
//
// What this file does NOT do is provide a property *service*: there is no
// /dev/socket/property_service, so __system_property_set() from the guest
// fails and the area is effectively read-only. That is why servicemanager
// still logs "Failed to set servicemanager ready property" -- it is telling
// the truth, and the seeded value below is what its clients read instead.

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "kernel/calls.h"
#include "kernel/errno.h"
#include "kernel/fs.h"
#include "kernel/log.h"
#include "kernel/property_area.h"
#include "fs/fd.h"
#include "fs/path.h"
#include "fs/proc.h"

#define PROP_AREA_MAGIC 0x504f5250u   // "PROP"
#define PROP_AREA_VERSION 0xfc6ed0abu
#define PROP_VALUE_MAX 92             // bionic's PROP_VALUE_MAX
#define PROP_LONG_FLAG (1u << 16)     // prop_info::kLongFlag
#define PROP_LONG_ERROR_BUF 56        // prop_info::kLongLegacyErrorBufferSize

// What __system_property_get() reports for a value too long to fit in one.
// Byte-for-byte bionic's kLongLegacyError; a caller that sees it is meant to
// switch to __system_property_read_callback().
static const char prop_long_error[] = "Must use __system_property_read_callback() to read";

#define PROP_HEADER_SIZE 128
#define PROP_TRIE_NODE_SIZE 20
#define PROP_INFO_SIZE 96

// bionic maps whatever size the file is (map_fd_ro takes pa_size_ from
// fstat), and its own writer uses 128 KiB. We size the file to its contents
// instead, so a root with no property files pays 4 KiB rather than 128, and
// cap the data area at bionic's large-node size so a pathological build.prop
// cannot make us allocate without bound.
#define PROP_AREA_MAX (1024 * 1024)
#define PROP_AREA_GROW_MIN 8192

// A trie node's fixed part. `name` follows, NUL-terminated.
struct prop_trie_node {
    uint32_t namelen;
    uint32_t prop;      // offset of the prop_info, 0 for none
    uint32_t left;      // offsets of the sibling BST children, 0 for none
    uint32_t right;
    uint32_t children;  // offset of the first node one level down
};

// A property's value. `name` follows the fixed part, NUL-terminated.
//
// serial packs three things: the value length in the top byte, kLongFlag at
// bit 16, and a dirty counter in the low bits that a reader spins on. We only
// ever write clean serials (low bits zero), which is what a reader wants to
// see. For a long value, `value` holds the legacy error string and, at offset
// PROP_LONG_ERROR_BUF, the distance from this prop_info to the real value.
struct prop_info {
    uint32_t serial;
    char value[PROP_VALUE_MAX];
};

struct prop_area {
    char *image;        // header + data
    size_t capacity;
    uint32_t bytes_used; // of the data area, matching the header field
    unsigned count;      // properties in the area
    unsigned dropped;    // adds that did not fit
};

static char *prop_data(struct prop_area *area) {
    return area->image + PROP_HEADER_SIZE;
}

static struct prop_trie_node *prop_node(struct prop_area *area, uint32_t off) {
    return (struct prop_trie_node *) (prop_data(area) + off);
}

static char *prop_node_name(struct prop_area *area, uint32_t off) {
    return prop_data(area) + off + PROP_TRIE_NODE_SIZE;
}

static struct prop_info *prop_info_at(struct prop_area *area, uint32_t off) {
    return (struct prop_info *) (prop_data(area) + off);
}

// bionic's allocate_obj: bump the data area, 4-byte aligned. Returns false
// (leaving *off untouched) when the area is at its cap. Any pointer taken
// from the image is invalid afterwards -- this may move the image.
static bool prop_alloc(struct prop_area *area, size_t size, uint32_t *off) {
    size_t aligned = (size + 3) & ~(size_t) 3;
    size_t need = PROP_HEADER_SIZE + area->bytes_used + aligned;
    if (need > PROP_AREA_MAX)
        return false;
    if (need > area->capacity) {
        size_t capacity = area->capacity * 2;
        if (capacity < need)
            capacity = need + PROP_AREA_GROW_MIN;
        if (capacity > PROP_AREA_MAX)
            capacity = PROP_AREA_MAX;
        char *image = realloc(area->image, capacity);
        if (image == NULL)
            return false;
        memset(image + area->capacity, 0, capacity - area->capacity);
        area->image = image;
        area->capacity = capacity;
    }
    *off = area->bytes_used;
    area->bytes_used += aligned;
    return true;
}

static bool prop_new_node(struct prop_area *area, const char *name, uint32_t namelen, uint32_t *off) {
    if (!prop_alloc(area, PROP_TRIE_NODE_SIZE + namelen + 1, off))
        return false;
    prop_node(area, *off)->namelen = namelen;
    memcpy(prop_node_name(area, *off), name, namelen);
    prop_node_name(area, *off)[namelen] = '\0';
    return true;
}

// bionic's cmp_prop_name: shorter names sort first, and only then is it a
// strncmp. A reader that walked the BST any other way would miss entries.
static int prop_cmp_name(const char *one, uint32_t one_len, const char *two, uint32_t two_len) {
    if (one_len < two_len)
        return -1;
    if (one_len > two_len)
        return 1;
    return strncmp(one, two, one_len);
}

// Walks (and extends) the sibling BST rooted at `root`, returning the offset
// of the node for this one path component.
static bool prop_find_sibling(struct prop_area *area, uint32_t root,
                              const char *name, uint32_t namelen, uint32_t *off) {
    uint32_t current = root;
    for (;;) {
        struct prop_trie_node *node = prop_node(area, current);
        int cmp = prop_cmp_name(name, namelen, prop_node_name(area, current), node->namelen);
        if (cmp == 0) {
            *off = current;
            return true;
        }
        uint32_t next = cmp < 0 ? node->left : node->right;
        if (next != 0) {
            current = next;
            continue;
        }
        uint32_t created;
        if (!prop_new_node(area, name, namelen, &created))
            return false;
        // prop_new_node may have moved the image, so re-take the pointer.
        node = prop_node(area, current);
        if (cmp < 0)
            node->left = created;
        else
            node->right = created;
        *off = created;
        return true;
    }
}

// Returns the offset of the trie node for `name`, creating the path to it.
static bool prop_find_node(struct prop_area *area, const char *name, uint32_t *off) {
    uint32_t current = 0; // the root node
    const char *remaining = name;
    for (;;) {
        const char *sep = strchr(remaining, '.');
        size_t len = sep != NULL ? (size_t) (sep - remaining) : strlen(remaining);
        if (len == 0)
            return false; // an empty component: "a..b", ".a", "a."

        uint32_t children = prop_node(area, current)->children;
        if (children == 0) {
            if (!prop_new_node(area, remaining, len, &children))
                return false;
            prop_node(area, current)->children = children;
        }
        if (!prop_find_sibling(area, children, remaining, len, &current))
            return false;

        if (sep == NULL)
            break;
        remaining = sep + 1;
    }
    *off = current;
    return true;
}

// Writes `value` into an already-allocated prop_info. Long values live in a
// separate block, reached by an offset relative to the prop_info itself --
// the area is mapped at a different address in every process, so it cannot
// hold pointers.
static bool prop_write_value(struct prop_area *area, uint32_t info_off, const char *value) {
    size_t valuelen = strlen(value);
    if (valuelen >= PROP_VALUE_MAX) {
        uint32_t long_off;
        if (!prop_alloc(area, valuelen + 1, &long_off))
            return false;
        memcpy(prop_data(area) + long_off, value, valuelen + 1);

        struct prop_info *info = prop_info_at(area, info_off);
        size_t error_len = sizeof(prop_long_error) - 1;
        info->serial = ((uint32_t) error_len << 24) | PROP_LONG_FLAG;
        memset(info->value, 0, PROP_VALUE_MAX);
        memcpy(info->value, prop_long_error, sizeof(prop_long_error));
        uint32_t relative = long_off - info_off;
        memcpy(info->value + PROP_LONG_ERROR_BUF, &relative, sizeof(relative));
        return true;
    }

    struct prop_info *info = prop_info_at(area, info_off);
    info->serial = (uint32_t) valuelen << 24;
    memset(info->value, 0, PROP_VALUE_MAX);
    memcpy(info->value, value, valuelen);
    return true;
}

// Adds `name`, or replaces the value of one already present. Replacing in
// place is what makes the later of two property files win, which is the rule
// init applies (PropertyLoadBootDefaults builds a map before setting
// anything, so a later file overrides an earlier one even for ro.* names).
static bool prop_set(struct prop_area *area, const char *name, const char *value) {
    size_t namelen = strlen(name);
    if (namelen == 0)
        return false;

    uint32_t node_off;
    if (!prop_find_node(area, name, &node_off))
        return false;

    uint32_t info_off = prop_node(area, node_off)->prop;
    if (info_off == 0) {
        if (!prop_alloc(area, PROP_INFO_SIZE + namelen + 1, &info_off))
            return false;
        memcpy(prop_data(area) + info_off + PROP_INFO_SIZE, name, namelen + 1);
        prop_node(area, node_off)->prop = info_off;
        area->count++;
    }
    return prop_write_value(area, info_off, value);
}

static void prop_set_counted(struct prop_area *area, const char *name, const char *value) {
    if (!prop_set(area, name, value))
        area->dropped++;
}

static bool prop_area_init(struct prop_area *area) {
    memset(area, 0, sizeof(*area));
    area->capacity = PROP_AREA_GROW_MIN;
    area->image = calloc(1, area->capacity);
    if (area->image == NULL)
        return false;

    // The root node, then bionic's dirty backup area. Both stay zero; only
    // the space matters, since bionic addresses the backup area as a fixed
    // offset (prop_area::dirty_backup_area) rather than reading it from the
    // file.
    area->bytes_used = PROP_TRIE_NODE_SIZE + ((PROP_VALUE_MAX + 3) & ~3u);

    uint32_t *header = (uint32_t *) area->image;
    header[0] = area->bytes_used; // patched again before the write
    header[1] = 0;                // serial
    header[2] = PROP_AREA_MAGIC;
    header[3] = PROP_AREA_VERSION;
    return true;
}

// ---------------------------------------------------------------------------
// Android's property files
// ---------------------------------------------------------------------------

// init reads the same key=value files at boot (PropertyLoadBootDefaults in
// system/core/init/property_service.cpp), and since Android 12 the canonical
// location is /<partition>/etc/build.prop with /<partition>/build.prop and
// /<partition>/default.prop as the legacy names. Order matters: the later a
// file appears here, the more specific the partition, and a later value wins.
//
// init consults ro.<partition>.build.version.sdk to decide whether a
// partition is old enough for its legacy paths to be read at all. We read
// both and let the canonical path win, which differs only for a key that
// exists solely in a legacy file of a partition new enough to have ignored
// it -- a value init would have dropped and we keep.
static const char *const property_files[] = {
    "/system/etc/ramdisk/build.prop",
    "/system/build.prop",
    "/system/etc/prop.default",
    "/system_ext/default.prop",
    "/system_ext/build.prop",
    "/system_ext/etc/build.prop",
    "/system_dlkm/etc/build.prop",
    "/vendor/default.prop",
    "/vendor/build.prop",
    "/vendor_dlkm/etc/build.prop",
    "/odm_dlkm/etc/build.prop",
    "/odm/default.prop",
    "/odm/build.prop",
    "/odm/etc/build.prop",
    "/product/default.prop",
    "/product/build.prop",
    "/product/etc/build.prop",
    "/debug_ramdisk/adb_debug.prop",
};

// A build.prop is a few tens of KiB. The cap is only here so a wrong path
// (a device, a disk image) cannot be read into memory whole.
#define PROPERTY_FILE_MAX (4 * 1024 * 1024)
#define PROPERTY_IMPORT_DEPTH 8

static void property_load_file(struct prop_area *area, const char *prefix, const char *path,
                               const char *filter, int depth);

// Every path in here is absolute inside the tree being described, which is not
// always the tree we are running in -- see property_area_build's prefix.
static bool property_path(char *buf, size_t size, const char *prefix, const char *path) {
    size_t prefix_len = strlen(prefix);
    if (prefix_len + strlen(path) + 1 > size)
        return false;
    memcpy(buf, prefix, prefix_len);
    strcpy(buf + prefix_len, path);
    return true;
}

// Reads a whole file into a NUL-terminated buffer. NULL if it is missing,
// unreadable, or not a regular file.
static char *property_read_file(const char *prefix, const char *path) {
    char full[MAX_PATH + 1];
    if (!property_path(full, sizeof(full), prefix, path))
        return NULL;

    struct fd *fd = generic_open(full, O_RDONLY_, 0);
    if (IS_ERR(fd))
        return NULL;

    char *buf = NULL;
    struct statbuf stat;
    if (generic_fstat(fd, &stat) >= 0 && S_ISREG(stat.mode) && stat.size <= PROPERTY_FILE_MAX) {
        size_t size = (size_t) stat.size;
        buf = malloc(size + 1);
        if (buf != NULL) {
            size_t got = 0;
            while (got < size) {
                ssize_t n = fd->ops->read(fd, buf + got, size - got);
                if (n <= 0)
                    break;
                got += (size_t) n;
            }
            buf[got] = '\0';
        }
    }

    fd_close(fd);
    return buf;
}

// init's filter argument on an `import` line: an exact name, or a prefix when
// it ends in '*'.
static bool property_filter_matches(const char *filter, const char *name) {
    if (filter == NULL)
        return true;
    size_t len = strlen(filter);
    if (len > 0 && filter[len - 1] == '*')
        return strncmp(name, filter, len - 1) == 0;
    return strcmp(name, filter) == 0;
}

static char *property_skip_space(char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r')
        p++;
    return p;
}

static void property_trim_end(char *start, char *end) {
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
        *--end = '\0';
}

// One line of a property file, already split off and NUL-terminated. Mirrors
// init's LoadProperties: leading space ignored, '#' comments, `import <path>
// [filter]`, otherwise key=value with the space around both trimmed.
static void property_load_line(struct prop_area *area, const char *prefix, char *line,
                               const char *filter, int depth) {
    char *key = property_skip_space(line);
    if (*key == '\0' || *key == '#')
        return;
    property_trim_end(key, key + strlen(key));

    if (strncmp(key, "import ", 7) == 0) {
        // A filtered file does not get to pull in more files, exactly as in
        // init -- the filter would not apply to what the import brought in.
        if (filter != NULL || depth >= PROPERTY_IMPORT_DEPTH)
            return;
        char *path = property_skip_space(key + 7);
        char *sub_filter = strchr(path, ' ');
        if (sub_filter != NULL) {
            *sub_filter++ = '\0';
            sub_filter = property_skip_space(sub_filter);
            if (*sub_filter == '\0')
                sub_filter = NULL;
        }
        // init expands ${prop} references in the path against properties set
        // so far. Nothing seeds those before build.prop is read, so an
        // unexpanded path would name a file that cannot exist; skip it rather
        // than pretend.
        if (*path == '\0' || strstr(path, "${") != NULL)
            return;
        property_load_file(area, prefix, path, sub_filter, depth + 1);
        return;
    }

    char *value = strchr(key, '=');
    if (value == NULL)
        return;
    *value++ = '\0';
    property_trim_end(key, value - 1);
    value = property_skip_space(value);
    if (*key == '\0')
        return;

    if (!property_filter_matches(filter, key))
        return;

    // ctl.* is a command to init ("start this service"), not a value, and
    // sys.powerctl reboots the device. init refuses to take either from a
    // property file and so do we.
    if (strncmp(key, "ctl.", 4) == 0 || strcmp(key, "sys.powerctl") == 0)
        return;

    // Only ro.* names may carry a value past PROP_VALUE_MAX: the long
    // encoding works because the value can never change, which is exactly
    // what ro. promises. bionic's __system_property_add rejects the rest.
    if (strlen(value) >= PROP_VALUE_MAX && strncmp(key, "ro.", 3) != 0)
        return;

    prop_set_counted(area, key, value);
}

static void property_load_file(struct prop_area *area, const char *prefix, const char *path,
                               const char *filter, int depth) {
    char *data = property_read_file(prefix, path);
    if (data == NULL)
        return;

    char *line = data;
    for (;;) {
        char *eol = strchr(line, '\n');
        if (eol != NULL)
            *eol = '\0';
        property_load_line(area, prefix, line, filter, depth);
        if (eol == NULL)
            break;
        line = eol + 1;
    }
    free(data);
}

// ---------------------------------------------------------------------------
// Building, at boot and on demand
// ---------------------------------------------------------------------------

static int property_area_write(struct prop_area *area, const char *prefix) {
    char path[MAX_PATH + 1];
    if (!property_path(path, sizeof(path), prefix, PROPERTY_AREA_PATH))
        return _ENAMETOOLONG;

    // Replaced rather than rewritten: a process that already mapped the old
    // file keeps a coherent view of it, which a truncate-and-rewrite under a
    // live mapping would not give it.
    struct statbuf stat;
    int err = generic_statat(AT_PWD, path, &stat, AT_SYMLINK_NOFOLLOW_);
    if (err >= 0) {
        if (S_ISDIR(stat.mode)) {
            // A directory here is the modern layout, which we do not write.
            // Removing it only succeeds if it is empty; if something else
            // populated it, that thing knows more than we do -- leave it.
            err = generic_rmdirat(AT_PWD, path);
            if (err < 0)
                return err;
        } else {
            err = generic_unlinkat(AT_PWD, path);
            if (err < 0)
                return err;
        }
    }

    // bionic's map_fd_ro refuses an area that is group- or other-writable, or
    // not owned by root, and 0444 is the mode its own writer uses.
    struct fd *fd = generic_open(path, O_WRONLY_ | O_CREAT_ | O_EXCL_, 0444);
    if (IS_ERR(fd))
        return (int) PTR_ERR(fd);

    // Page-align the size. Any size is legal -- a reader takes its length from
    // fstat -- but a whole number of pages is what gets mapped either way.
    size_t size = PROP_HEADER_SIZE + area->bytes_used;
    size = (size + 4095) & ~(size_t) 4095;
    if (size > area->capacity) {
        char *image = realloc(area->image, size);
        if (image == NULL) {
            fd_close(fd);
            return _ENOMEM;
        }
        memset(image + area->capacity, 0, size - area->capacity);
        area->image = image;
        area->capacity = size;
    }
    ((uint32_t *) area->image)[0] = area->bytes_used;

    size_t written = 0;
    while (written < size) {
        ssize_t n = fd->ops->write(fd, area->image + written, size - written);
        if (n <= 0)
            break;
        written += (size_t) n;
    }
    fd_close(fd);

    if (written != size) {
        generic_unlinkat(AT_PWD, path);
        return _EIO;
    }

    // On a root that records ownership (fakefs) this is what makes bionic
    // accept the file at all; on one that does not, it fails harmlessly and
    // only the guest tests, which do their own parsing, will read it there.
    generic_setattrat(AT_PWD, path, make_attr(uid, 0), true);
    generic_setattrat(AT_PWD, path, make_attr(gid, 0), true);
    generic_setattrat(AT_PWD, path, make_attr(mode, 0444), true);
    return 0;
}

// What the last build produced, for /proc/ish/property_area.
static lock_t property_area_lock = LOCK_INITIALIZER;
static char property_area_last_path[MAX_PATH + 1];
static size_t property_area_last_size;
static unsigned property_area_last_count;
static unsigned property_area_last_dropped;
static int property_area_last_err = _ENOENT; // nothing built yet

int property_area_build(const char *prefix) {
    // Held across the whole build, not just the bookkeeping at the end: two
    // writes to /proc/ish/property_area naming the same tree would otherwise
    // race over unlinking and recreating the one file.
    lock(&property_area_lock, 0);

    struct prop_area area;
    if (!prop_area_init(&area)) {
        unlock(&property_area_lock);
        return _ENOMEM;
    }

    // Seeded before the files are read, so a tree with its own opinion wins.
    // servicemanager is meant to set this itself once it is listening; it
    // cannot, because setting a property means talking to a property service
    // that does not exist, so its clients would wait forever. The cost of
    // seeding it up front is that "ready" now means "the area was built", not
    // "servicemanager is up" -- so start servicemanager before anything that
    // talks to it. docs/android-bringup.md says so too.
    prop_set_counted(&area, "servicemanager.ready", "true");

    for (size_t i = 0; i < sizeof(property_files) / sizeof(property_files[0]); i++)
        property_load_file(&area, prefix, property_files[i], NULL, 0);

    if (area.dropped > 0)
        ish_printk("property area: %u properties did not fit\n", area.dropped);

    int err = property_area_write(&area, prefix);

    snprintf(property_area_last_path, sizeof(property_area_last_path), "%s%s",
             prefix, PROPERTY_AREA_PATH);
    property_area_last_size = err == 0 ? PROP_HEADER_SIZE + area.bytes_used : 0;
    property_area_last_count = area.count;
    property_area_last_dropped = area.dropped;
    property_area_last_err = err;

    free(area.image);
    unlock(&property_area_lock);
    return err;
}

void property_area_create(void) {
    int err = property_area_build("");
    if (err < 0)
        ish_printk("property area: could not write %s (%d)\n", PROPERTY_AREA_PATH, err);
}

// ---------------------------------------------------------------------------
// /proc/ish/property_area
// ---------------------------------------------------------------------------

int property_area_show(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    lock(&property_area_lock, 0);
    if (property_area_last_err != 0) {
        proc_printf(buf, "no area: %s (error %d)\n",
                    property_area_last_path[0] != '\0' ? property_area_last_path
                                                       : PROPERTY_AREA_PATH,
                    property_area_last_err);
    } else {
        proc_printf(buf, "path %s\n", property_area_last_path);
        proc_printf(buf, "size %zu\n", property_area_last_size);
        proc_printf(buf, "properties %u\n", property_area_last_count);
        if (property_area_last_dropped > 0)
            proc_printf(buf, "dropped %u\n", property_area_last_dropped);
    }
    unlock(&property_area_lock);
    return 0;
}

// Writing a directory path rebuilds the area for the tree rooted there:
// property files are read from <path>/system/build.prop and friends, and the
// area is written to <path>/dev/__properties__. An empty write (or "/")
// rebuilds for the current root.
int property_area_update(struct proc_entry *UNUSED(entry), struct proc_data *data) {
    size_t start = 0, end = data->size;
    while (start < end && (data->data[start] == ' ' || data->data[start] == '\t' ||
                           data->data[start] == '\r' || data->data[start] == '\n'))
        start++;
    while (end > start && (data->data[end - 1] == ' ' || data->data[end - 1] == '\t' ||
                           data->data[end - 1] == '\r' || data->data[end - 1] == '\n'))
        end--;

    // The prefix is glued to absolute paths, so it must not end in a slash --
    // and "/" is how you say "the current root" without writing nothing.
    while (end > start && data->data[end - 1] == '/')
        end--;

    size_t len = end - start;
    if (len + strlen(PROPERTY_AREA_PATH) >= MAX_PATH)
        return _ENAMETOOLONG;

    char prefix[MAX_PATH + 1];
    memcpy(prefix, &data->data[start], len);
    prefix[len] = '\0';

    if (len > 0) {
        // Fail loudly on a path that is not there: silently building an area
        // nothing will ever read is the failure mode this whole file exists
        // to stop happening.
        struct statbuf stat;
        int err = generic_statat(AT_PWD, prefix, &stat, 0);
        if (err < 0)
            return err;
        if (!S_ISDIR(stat.mode))
            return _ENOTDIR;
    }

    return property_area_build(prefix);
}
