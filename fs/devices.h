#ifndef FS_DEVICES_H
#define FS_DEVICES_H

// losely based on devices.txt from linux

// --- memory devices ---
#define MEM_MAJOR 1
// /dev/null
#define DEV_NULL_MINOR 3
// /dev/zero
#define DEV_ZERO_MINOR 5
// /dev/full
#define DEV_FULL_MINOR 7
// /dev/random
#define DEV_RANDOM_MINOR 8
// /dev/urandom
#define DEV_URANDOM_MINOR 9
// /dev/kmsg
#define DEV_KMSG_MINOR 11

// --- tty devices ---
// /dev/ttyX where X is minor
#define TTY_CONSOLE_MAJOR 4

// --- alternate tty devices ---
#define TTY_ALTERNATE_MAJOR 5
// /dev/tty
#define DEV_TTY_MINOR 0
// /dev/console
#define DEV_CONSOLE_MINOR 1
// /dev/ptmx
#define DEV_PTMX_MINOR 2

// --- pseudo tty devices ---
#define TTY_PSEUDO_MASTER_MAJOR 128
#define TTY_PSEUDO_SLAVE_MAJOR 136

// --- dynamic devices ---
#define DYN_DEV_MAJOR 240
// /dev/rtc
#define DEV_RTC_MAJOR 252
#define DEV_RTC_MINOR 2


// --- android binder ---
// Linux allocates binder's major dynamically; we pick a fixed free one so the
// device nodes can be created before any binder device is opened.
#define BINDER_MAJOR 249
// The three standard binder contexts. Each has its own name registry and its
// own context manager, so they are separate devices rather than separate
// minors of one shared namespace.
#define DEV_BINDER_MINOR 0
#define DEV_HWBINDER_MINOR 1
#define DEV_VNDBINDER_MINOR 2
// binderfs's control node (/dev/binderfs/binder-control).
#define DEV_BINDER_CONTROL_MINOR 3
// Minors from here up are handed out by binderfs's BINDER_CTL_ADD.
#define BINDER_FIRST_DYNAMIC_MINOR 4
#define BINDER_MAX_MINORS 64

// /dev/clipboard
#define DEV_CLIPBOARD_MINOR 0
// /dev/gps
#define DEV_LOCATION_MINOR 1
// /dev/dsp
#define DEV_DSP_MINOR 3

#endif
