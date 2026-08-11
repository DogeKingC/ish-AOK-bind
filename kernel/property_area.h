#ifndef KERNEL_PROPERTY_AREA_H
#define KERNEL_PROPERTY_AREA_H

struct proc_entry;
struct proc_data;

// Android's system property area (/dev/__properties__).
//
// Properties are how Android userspace answers "what device is this, and what
// is running on it". They live in shared memory that bionic mmaps read-only
// into every process; the memory is written by init's property service, which
// nothing here provides.
//
// The absence is not a missing nicety, it is a hang. Modern libbinder does
//
//     while (!WaitForProperty("servicemanager.ready", "true", 1s)) { ... }
//
// before it ever constructs ProcessState, so with no property file
// __system_property_find() returns null, the wait has no serial to block on,
// and the retry loop becomes a busy spin: the process burns CPU with only fds
// 0/1/2 open and never opens the binder driver at all. docs/binder.md covers
// how that symptom is told apart from a real binder stall.
//
// The format is bionic's, transcribed from
// bionic/libc/system_properties/{prop_area.cpp,prop_info.cpp} and
// .../include/system_properties/{prop_area.h,prop_info.h}. A reader
// (system_properties.cpp, SystemProperties::InitContexts) picks its layout
// from what it finds at /dev/__properties__:
//
//   a directory holding property_info  ContextsSerialized: one prop_area per
//                                      SELinux context, plus a serialized
//                                      context-lookup trie
//   a directory without it             ContextsSplit: one prop_area per
//                                      context named in /plat_property_contexts
//   a regular file                     ContextsPreSplit: the whole property
//                                      set in that one prop_area
//
// We write the third. It is what Android itself used before 8.0, it is still
// in current bionic, and it needs one well-defined structure rather than a
// context split we have no policy to derive. Nothing is lost by it: the
// per-context files exist to stop one domain reading another's properties,
// and fs/selinuxfs.c is a permissive stub with no policy anyway.

// The path bionic maps: PROP_DIRNAME in <sys/system_properties.h>. A
// directory there in modern Android -- hence the name -- but a regular file is
// the older and, for us, simpler contract.
#define PROPERTY_AREA_PATH "/dev/__properties__"

// Builds the area and writes it to PROPERTY_AREA_PATH, replacing whatever was
// there. Called once at boot, next to the binder/ashmem/dma_heap device nodes:
// like them it is a piece of the Android platform that must exist before the
// first process to look for it, and like them it quietly does nothing on a
// root that will not take it.
void property_area_create(void);

// Builds the area under `prefix`, reading the property files at
// <prefix>/system/build.prop and friends and writing
// <prefix>/dev/__properties__. An empty prefix means the current root, which
// is what boot uses.
//
// A prefix exists for the two cases where boot is the wrong time. A chroot
// has its own /dev that the outer boot never touched, so the tree has to be
// given its area explicitly. And during bring-up the useful loop is to add a
// property and try again, which otherwise means restarting the app. Both go
// through /proc/ish/property_area (fs/proc/ish.c).
//
// Returns 0, or a negative errno. Anything already mapping the old area keeps
// it: the file is replaced by unlink-and-create, not rewritten underneath a
// reader.
int property_area_build(const char *prefix);

// /proc/ish/property_area: what the last build produced, and a write target
// that triggers another one. Same purpose as /proc/ish/binder -- from inside
// the guest, "the property is not there" and "the area was never built" look
// identical, and they call for opposite next steps.
int property_area_show(struct proc_entry *entry, struct proc_data *buf);
int property_area_update(struct proc_entry *entry, struct proc_data *data);

#endif
