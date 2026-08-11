// property_area: Android's property area at /dev/__properties__
// (kernel/property_area.c).
//
// Nothing on an Alpine root reads this file, so the only thing that can catch
// a mistake in it is a reader that behaves the way bionic's does. That is what
// this test is: an independent transcription of the read side of
// bionic/libc/system_properties/prop_area.cpp, pointed at the area the kernel
// built at boot.
//
// It matters because the failure mode on the other side is silent. bionic does
// not validate the trie; it follows offsets. A node linked into the wrong
// branch of a sibling BST, a value whose recorded length disagrees with its
// NUL, a long value whose offset is relative to the wrong base -- each of them
// reads back as "that property does not exist", and the only symptom is an
// Android process behaving as if the platform never set it. That is the same
// class of bug as the one this whole file exists to fix.
//
// Covered:
//   header       magic, version, and a bytes_used that accounts for the root
//                node and bionic's dirty backup area.
//   structure    every offset in bounds and 4-byte aligned, every name and
//                value NUL-terminated inside the area, no cycles.
//   lookup       every property reachable by a full walk is also reachable by
//                name through the trie -- which is the only path bionic uses,
//                so a walkable-but-unfindable entry is invisible to Android.
//   ordering     siblings are ordered by bionic's cmp_prop_name (length
//                first, then strncmp), because a reader's binary search
//                stops early on any other order.
//   long values  a value at or past PROP_VALUE_MAX is stored out of line, and
//                the legacy error string is what an old reader sees.
//   the blocker  servicemanager.ready is "true": libbinder waits on it before
//                it will construct ProcessState.
//   build.prop   with the harness fixture in place, the parsing rules init
//                applies to a property file: comments, whitespace, later
//                values winning, imports, and the keys init refuses.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "test_common.h"

#define PROPERTY_AREA_PATH "/dev/__properties__"

// bionic's constants (prop_area.cpp, prop_info.h, sys/system_properties.h).
#define PROP_AREA_MAGIC 0x504f5250u
#define PROP_AREA_VERSION 0xfc6ed0abu
#define PROP_VALUE_MAX 92
#define PROP_LONG_FLAG (1u << 16)
#define PROP_LONG_ERROR_BUF 56
#define SERIAL_VALUE_LEN(serial) ((serial) >> 24)
#define SERIAL_DIRTY(serial) ((serial) & 1)

#define HEADER_SIZE 128
#define TRIE_NODE_SIZE 20
#define INFO_SIZE 96

static const char long_error[] = "Must use __system_property_read_callback() to read";

static const char *map;
static size_t map_size;
static const char *data;      // the data area: every stored offset is from here
static size_t data_size;
static uint32_t bytes_used;

static void check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s\n", what);
        failures_total++;
    } else {
        test_logf("ok %s\n", what);
    }
}

static void checkf(int cond, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (!cond) {
        printf("FAIL ");
        vprintf(fmt, ap);
        printf("\n");
        failures_total++;
    } else if (test_verbose) {
        printf("ok ");
        vprintf(fmt, ap);
        printf("\n");
    }
    va_end(ap);
}

static uint32_t load32(const char *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

// An offset is usable if the fixed part of the object fits inside the bytes
// the header says are in use. bionic only bounds-checks against the mapped
// size, so anything looser than this would still "work" until it did not.
static int off_ok(uint32_t off, size_t fixed) {
    return off < bytes_used && (uint64_t) off + fixed <= bytes_used && (off & 3) == 0;
}

struct node_view {
    uint32_t namelen, prop, left, right, children;
    const char *name;
};

static int node_at(uint32_t off, struct node_view *out) {
    if (!off_ok(off, TRIE_NODE_SIZE))
        return 0;
    out->namelen = load32(data + off);
    out->prop = load32(data + off + 4);
    out->left = load32(data + off + 8);
    out->right = load32(data + off + 12);
    out->children = load32(data + off + 16);
    if ((uint64_t) off + TRIE_NODE_SIZE + out->namelen + 1 > bytes_used)
        return 0;
    out->name = data + off + TRIE_NODE_SIZE;
    if (out->name[out->namelen] != '\0' || strlen(out->name) != out->namelen)
        return 0;
    return 1;
}

struct info_view {
    uint32_t serial;
    const char *name;
    const char *value;
    size_t value_len;
    int is_long;
};

static int info_at(uint32_t off, struct info_view *out) {
    if (!off_ok(off, INFO_SIZE))
        return 0;
    out->serial = load32(data + off);
    if (SERIAL_DIRTY(out->serial))
        return 0; // nothing writes this area, so no entry may be mid-update

    const char *name = data + off + INFO_SIZE;
    size_t max_name = bytes_used - (off + INFO_SIZE);
    if (memchr(name, '\0', max_name) == NULL)
        return 0;
    out->name = name;

    out->is_long = (out->serial & PROP_LONG_FLAG) != 0;
    if (out->is_long) {
        uint32_t rel = load32(data + off + 4 + PROP_LONG_ERROR_BUF);
        uint64_t value_off = (uint64_t) off + rel;
        if (value_off >= bytes_used)
            return 0;
        const char *value = data + value_off;
        if (memchr(value, '\0', bytes_used - value_off) == NULL)
            return 0;
        out->value = value;
    } else {
        out->value = data + off + 4;
        if (memchr(out->value, '\0', PROP_VALUE_MAX) == NULL)
            return 0;
    }
    out->value_len = strlen(out->value);
    return 1;
}

// bionic's cmp_prop_name: length first. Getting this wrong in the writer puts
// a node in a branch no reader will descend into.
static int cmp_prop_name(const char *one, uint32_t one_len, const char *two, uint32_t two_len) {
    if (one_len < two_len)
        return -1;
    if (one_len > two_len)
        return 1;
    return strncmp(one, two, one_len);
}

// find_prop_trie_node with alloc_if_needed = false.
static uint32_t find_sibling(uint32_t root, const char *name, uint32_t namelen) {
    uint32_t current = root;
    for (int steps = 0; steps < 4096; steps++) {
        struct node_view node;
        if (current == 0 || !node_at(current, &node))
            return 0;
        int cmp = cmp_prop_name(name, namelen, node.name, node.namelen);
        if (cmp == 0)
            return current;
        current = cmp < 0 ? node.left : node.right;
    }
    return 0;
}

// find_property with alloc_if_needed = false: returns the prop_info offset.
static uint32_t find_property(const char *name) {
    uint32_t current = 0; // the root node
    const char *remaining = name;
    for (;;) {
        const char *sep = strchr(remaining, '.');
        uint32_t len = sep != NULL ? (uint32_t) (sep - remaining) : (uint32_t) strlen(remaining);
        if (len == 0)
            return 0;

        struct node_view node;
        if (!node_at(current, &node) || node.children == 0)
            return 0;
        current = find_sibling(node.children, remaining, len);
        if (current == 0)
            return 0;

        if (sep == NULL)
            break;
        remaining = sep + 1;
    }
    struct node_view node;
    if (!node_at(current, &node))
        return 0;
    return node.prop;
}

static const char *find_value(const char *name) {
    uint32_t off = find_property(name);
    if (off == 0)
        return NULL;
    static struct info_view info;
    if (!info_at(off, &info))
        return NULL;
    return info.value;
}

// ---------------------------------------------------------------------------
// The full walk
// ---------------------------------------------------------------------------

static unsigned walk_count;
static unsigned walk_bad;
static unsigned walk_visited;

#define WALK_MAX_DEPTH 64        // '.'-separated components in one name
#define WALK_MAX_SIBLINGS 8192   // one level of the trie, in BST form
#define WALK_MAX_NODES 200000    // a cycle would otherwise walk forever

static void walk_siblings(uint32_t root, const char *prefix, int depth);

// One trie node: its property, if it has one, and the level below it. Kept
// apart from the sibling walk because the two nest very differently -- names
// are a handful of components deep, while a sibling BST is built by insertion
// order with no rebalancing and can be a chain as long as the level is wide.
static void visit_node(uint32_t off, const struct node_view *node_in, const char *prefix, int depth) {
    (void) off;
    struct node_view node = *node_in;
    char name[512];
    if (prefix[0] == '\0')
        snprintf(name, sizeof(name), "%s", node.name);
    else
        snprintf(name, sizeof(name), "%s.%s", prefix, node.name);

    if (node.prop != 0) {
        struct info_view info;
        if (!info_at(node.prop, &info)) {
            printf("FAIL prop_info at %u (for '%s') is out of bounds or malformed\n",
                   node.prop, name);
            walk_bad++;
        } else {
            walk_count++;
            if (strcmp(info.name, name) != 0) {
                printf("FAIL prop_info name '%s' but trie path '%s'\n", info.name, name);
                walk_bad++;
            }
            // The value length in the top byte of the serial is what
            // __system_property_get() returns; a disagreement with the NUL
            // truncates or over-reads the value in every caller.
            size_t serial_len = SERIAL_VALUE_LEN(info.serial);
            if (info.is_long) {
                if (serial_len != strlen(long_error) ||
                    strcmp(data + node.prop + 4, long_error) != 0) {
                    printf("FAIL long property '%s' does not carry the legacy error string\n", name);
                    walk_bad++;
                }
                if (info.value_len < PROP_VALUE_MAX) {
                    printf("FAIL '%s' is stored out of line but is only %zu bytes\n",
                           name, info.value_len);
                    walk_bad++;
                }
                if (strncmp(name, "ro.", 3) != 0) {
                    printf("FAIL '%s' is stored out of line but is not a ro. property\n", name);
                    walk_bad++;
                }
            } else if (serial_len != info.value_len) {
                printf("FAIL '%s' records length %zu but the value is %zu bytes\n",
                       name, serial_len, info.value_len);
                walk_bad++;
            }
            // The check that matters most: bionic reaches a property only
            // through find_property, never through a walk.
            if (find_property(name) != node.prop) {
                printf("FAIL '%s' is in the area but a lookup by name does not find it\n", name);
                walk_bad++;
            }
        }
    }

    if (node.children != 0) {
        if (depth + 1 > WALK_MAX_DEPTH) {
            printf("FAIL '%s' nests more than %d levels deep\n", name, WALK_MAX_DEPTH);
            walk_bad++;
        } else {
            walk_siblings(node.children, name, depth + 1);
        }
    }
}

// foreach_property over one level of the trie, plus the check a reader takes
// on faith: that the BST really is ordered by cmp_prop_name. It is not, a
// lookup's binary search turns the wrong way and the property is invisible --
// which is why every entry is looked up by name again in visit_node.
//
// Iterative, because this is the dimension that can be deep: bionic never
// rebalances, so a level whose names arrived in sorted order is a chain.
static void walk_siblings(uint32_t root, const char *prefix, int depth) {
    uint32_t stack[WALK_MAX_SIBLINGS];
    size_t top = 0;
    stack[top++] = root;

    while (top > 0) {
        uint32_t off = stack[--top];
        struct node_view node;
        if (!node_at(off, &node)) {
            printf("FAIL trie node at %u (under '%s') is out of bounds or malformed\n", off, prefix);
            walk_bad++;
            continue;
        }
        if (++walk_visited > WALK_MAX_NODES) {
            printf("FAIL the trie has more than %d nodes; it is probably a cycle\n", WALK_MAX_NODES);
            walk_bad++;
            return;
        }

        struct node_view child;
        if (node.left != 0) {
            if (node_at(node.left, &child) &&
                cmp_prop_name(child.name, child.namelen, node.name, node.namelen) >= 0) {
                printf("FAIL sibling order: '%s' is on the left of '%s'\n", child.name, node.name);
                walk_bad++;
            }
            if (top < WALK_MAX_SIBLINGS)
                stack[top++] = node.left;
            else
                goto too_wide;
        }
        if (node.right != 0) {
            if (node_at(node.right, &child) &&
                cmp_prop_name(child.name, child.namelen, node.name, node.namelen) <= 0) {
                printf("FAIL sibling order: '%s' is on the right of '%s'\n", child.name, node.name);
                walk_bad++;
            }
            if (top < WALK_MAX_SIBLINGS)
                stack[top++] = node.right;
            else
                goto too_wide;
        }

        visit_node(off, &node, prefix, depth);
    }
    return;

too_wide:
    printf("FAIL more than %d siblings pending under '%s'\n", WALK_MAX_SIBLINGS, prefix);
    walk_bad++;
}

// ---------------------------------------------------------------------------

// Points the reader at an area, replacing whatever it was looking at.
static int map_area(const char *path) {
    if (map != NULL) {
        munmap((void *) map, map_size);
        map = NULL;
    }
    struct stat st;
    int fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) < 0) {
        printf("FAIL cannot open %s (errno=%d %s)\n", path, errno, strerror(errno));
        failures_total++;
        if (fd >= 0)
            close(fd);
        return -1;
    }
    map_size = (size_t) st.st_size;
    if (map_size < HEADER_SIZE) {
        printf("FAIL %s is %zu bytes, smaller than the header\n", path, map_size);
        failures_total++;
        close(fd);
        return -1;
    }
    // MAP_SHARED PROT_READ, exactly as bionic's map_fd_ro does it.
    void *p = mmap(NULL, map_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        printf("FAIL cannot mmap %s (errno=%d %s)\n", path, errno, strerror(errno));
        failures_total++;
        return -1;
    }
    map = p;
    data = map + HEADER_SIZE;
    data_size = map_size - HEADER_SIZE;
    return 0;
}

static int open_area(void) {
    struct stat st;
    if (stat(PROPERTY_AREA_PATH, &st) < 0) {
        printf("FAIL %s does not exist (errno=%d %s)\n",
               PROPERTY_AREA_PATH, errno, strerror(errno));
        failures_total++;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        // A directory here sends bionic down ContextsSerialized/ContextsSplit,
        // which want per-SELinux-context files we do not write.
        printf("FAIL %s is not a regular file (mode %o)\n", PROPERTY_AREA_PATH, st.st_mode);
        failures_total++;
        return -1;
    }
    // map_fd_ro refuses an area anything but root could have written.
    check((st.st_mode & (S_IWGRP | S_IWOTH)) == 0, "area is not group- or other-writable");

    // Ownership is only recordable on a root that keeps its own metadata. On a
    // realfs root run by an unprivileged user the file belongs to that user
    // and bionic would refuse it -- true, and not this test's business, so
    // establish first whether ownership can be set at all here.
    int can_chown = 0;
    int fd = open("/tmp/.ish-propcheck", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd >= 0) {
        can_chown = fchown(fd, 0, 0) == 0;
        close(fd);
        unlink("/tmp/.ish-propcheck");
    }
    if (can_chown)
        check(st.st_uid == 0 && st.st_gid == 0, "area is owned by root");
    else
        test_logf("skip ownership check: this root cannot record it\n");

    return map_area(PROPERTY_AREA_PATH);
}

static void test_header(void) {
    bytes_used = load32(map);
    uint32_t serial = load32(map + 4);
    uint32_t magic = load32(map + 8);
    uint32_t version = load32(map + 12);

    checkf(magic == PROP_AREA_MAGIC, "magic is PROP (got %08x)", magic);
    checkf(version == PROP_AREA_VERSION, "version is %08x (got %08x)", PROP_AREA_VERSION, version);
    check(serial == 0, "area serial starts clean");

    // The root node, then the 92-byte dirty backup area bionic reserves right
    // after it. bionic addresses the backup area as a fixed offset rather than
    // reading it from the file, so an area that did not reserve it hands out
    // the first real object as scratch space.
    uint32_t reserved = TRIE_NODE_SIZE + ((PROP_VALUE_MAX + 3) & ~3u);
    checkf(bytes_used >= reserved, "bytes_used %u covers the root node and dirty backup area (%u)",
           bytes_used, reserved);
    checkf(bytes_used <= data_size, "bytes_used %u fits in the %zu-byte data area",
           bytes_used, data_size);

    for (uint32_t i = 0; i < 28; i++)
        checkf(load32(map + 16 + i * 4) == 0, "header reserved word %u is zero", i);

    struct node_view root;
    if (bytes_used >= reserved && bytes_used <= data_size && node_at(0, &root)) {
        check(root.namelen == 0 && root.prop == 0 && root.left == 0 && root.right == 0,
              "the root node is empty except for its children");
    } else {
        check(0, "the root node is readable");
    }
}

// ---------------------------------------------------------------------------
// The fixture (tools/run-guest-tests.sh)
// ---------------------------------------------------------------------------

static void expect(const char *name, const char *value) {
    const char *got = find_value(name);
    if (got == NULL) {
        printf("FAIL '%s' is missing, wanted '%s'\n", name, value);
        failures_total++;
        return;
    }
    if (strcmp(got, value) != 0) {
        printf("FAIL '%s' is '%s', wanted '%s'\n", name, got, value);
        failures_total++;
        return;
    }
    test_logf("ok %s='%s'\n", name, value);
}

static void expect_absent(const char *name, const char *why) {
    if (find_property(name) != 0) {
        printf("FAIL '%s' is present; %s\n", name, why);
        failures_total++;
    } else {
        test_logf("ok %s absent (%s)\n", name, why);
    }
}

static void test_fixture(void) {
    char longv[101];
    memset(longv, 'x', sizeof(longv) - 1);
    longv[sizeof(longv) - 1] = '\0';

    expect("ro.ish.test.plain", "plain");
    // Space around the '=' belongs to neither side, and a line's trailing
    // space is not part of the value.
    expect("ro.ish.test.spaced", "value with spaces");
    expect("ro.ish.test.empty", "");
    // init builds a map before setting anything, so the later of two lines
    // wins even for a ro. name -- which cannot be overwritten once the
    // property service is running.
    expect("ro.ish.test.dup", "second");
    // ...and the later of two files wins the same way: this one is set in
    // /system/build.prop and again in /vendor/build.prop.
    expect("ro.ish.test.override", "vendor");
    expect("ro.ish.test.imported", "yes");
    expect("ro.ish.test.deep.a.b.c", "nested");
    expect("ro.ish.test.hash", "value # not a comment");

    // Past PROP_VALUE_MAX the value moves out of line, and only a ro. name is
    // allowed to do that: the encoding assumes the value never changes.
    expect("ro.ish.test.long", longv);
    expect_absent("ish.test.longnonro",
                  "a value at PROP_VALUE_MAX is only allowed for a ro. name");

    // Commands, not values. init refuses to take them from a property file.
    expect_absent("ctl.start", "ctl.* is a command to init");
    expect_absent("sys.powerctl", "sys.powerctl reboots the device");

    expect_absent("ro.ish.test.commented", "the line is a comment");
    expect_absent("ro.ish.test", "it is an interior trie node, not a property");
    expect_absent("ro.ish.test.plain.more", "nothing extends a leaf");
}

// ---------------------------------------------------------------------------
// /proc/ish/property_area
// ---------------------------------------------------------------------------

// Rebuilding for a tree other than the booted root is the only way a chroot
// gets an area at all -- the boot-time build wrote into the outer /dev, which
// a chroot cannot see. tools/android-chroot-setup.sh does exactly this.
#define PROC_PATH "/proc/ish/property_area"
#define TREE_PATH "/tmp/ish-prop-tree"

static int write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t) strlen(text) ? 0 : -1;
}

static int write_new_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t) strlen(text) ? 0 : -1;
}

static void test_rebuild(void) {
    if (access(PROC_PATH, W_OK) != 0) {
        printf("FAIL %s is missing; a chroot has no other way to get an area\n", PROC_PATH);
        failures_total++;
        return;
    }

    mkdir(TREE_PATH, 0755);
    mkdir(TREE_PATH "/system", 0755);
    mkdir(TREE_PATH "/dev", 0755);
    unlink(TREE_PATH "/dev/__properties__");
    if (write_new_file(TREE_PATH "/system/build.prop",
                       "ro.ish.tree.only=yes\nro.ish.test.plain=from-the-tree\n") < 0) {
        printf("FAIL cannot write the test tree's build.prop (errno=%d %s)\n",
               errno, strerror(errno));
        failures_total++;
        return;
    }

    check(write_file(PROC_PATH, TREE_PATH "\n") == 0, "a tree path is accepted");
    // A path that is not a directory has to be refused: an area written where
    // nothing will read it is indistinguishable from one that works until
    // something tries to use it.
    check(write_file(PROC_PATH, "/no/such/tree\n") < 0, "a missing tree is refused");
    check(write_file(PROC_PATH, TREE_PATH "/system/build.prop\n") < 0,
          "a path that is not a directory is refused");

    if (map_area(TREE_PATH "/dev/__properties__") < 0)
        return;
    test_header();
    walk_count = walk_bad = walk_visited = 0;
    struct node_view root;
    if (node_at(0, &root) && root.children != 0)
        walk_siblings(root.children, "", 0);
    check(walk_bad == 0, "the rebuilt area is well formed");
    expect("ro.ish.tree.only", "yes");
    // Read from the tree's build.prop, not the booted root's: the prefix
    // applies to the property files as well as to the output.
    expect("ro.ish.test.plain", "from-the-tree");
    expect("servicemanager.ready", "true");

    // Rebuilding for the booted root has to put the original area back, or a
    // chroot handover would leave the outer root without one.
    check(write_file(PROC_PATH, "/\n") == 0, "rebuilding for the current root is accepted");
    if (map_area(PROPERTY_AREA_PATH) == 0)
        expect("servicemanager.ready", "true");
}

int main(int argc, char **argv) {
    test_init(argc, argv);

    if (open_area() < 0)
        return finish_suite("property_area");
    test_header();
    if (failures_total != 0)
        return finish_suite("property_area");

    struct node_view root;
    if (node_at(0, &root) && root.children != 0)
        walk_siblings(root.children, "", 0);
    check(walk_bad == 0, "the trie is well formed and every entry is findable by name");
    test_logf("%u properties in %u trie nodes\n", walk_count, walk_visited);
    check(walk_count > 0, "the area holds at least one property");

    // The blocker this whole file exists for: libbinder waits on this before
    // it constructs ProcessState, and with no property service to set it, a
    // client that does not find it here spins forever.
    expect("servicemanager.ready", "true");

    expect_absent("no.such.property.at.all", "it was never set");

    // The harness plants a set of property files covering the parsing rules;
    // on a device without them there is nothing here to check.
    if (find_value("ish.test.fixture") != NULL)
        test_fixture();
    else
        test_logf("skip build.prop checks: no fixture in this root\n");

    test_rebuild();

    return finish_suite("property_area");
}
