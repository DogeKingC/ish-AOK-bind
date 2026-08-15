#ifndef KERNEL_LOGD_SINK_H
#define KERNEL_LOGD_SINK_H

#include <stddef.h>
#include "fs/proc.h"

// A stand-in for Android's logd, on the one thing that matters for bring-up:
// giving liblog somewhere to write, so a failing Android process can say why.
//
// See kernel/logd_sink.c for what this is and is not.

// Creates /dev/socket/logdw for the tree rooted at `prefix` ("" or "/" means
// the current root) and starts draining it into the kernel log. Safe to call
// again: it replaces whatever was there.
int logd_sink_create(const char *prefix);

// Boot hook, for the current root. Failure is reported, not fatal.
void logd_sink_start(void);

// /proc/ish/logd -- whether the sink is up, and what it has seen. Writing a
// tree path rebuilds it there, the same way /proc/ish/property_area does.
int logd_sink_show(struct proc_entry *entry, struct proc_data *buf);
int logd_sink_update(struct proc_entry *entry, struct proc_data *data);

#endif
