// F_SETPIPE_SZ / F_GETPIPE_SZ (fs/fd.c).
//
// bionic's crash handler sets a pipe's buffer size before spawning crash_dump,
// and on every Android crash here it logged "failed to set pipe buffer size:
// Invalid argument" because neither command existed. That was invisible until
// Android's own logging had somewhere to go (kernel/logd_sink.c).
//
// The checks that matter are not "a number came back". They are:
//
//   effect     after F_SETPIPE_SZ the pipe REALLY holds that much -- verified
//              by filling it with a non-blocking write, not by trusting the
//              return value. An implementation that answers plausibly without
//              touching the pipe passes every other check and fails this one,
//              which is exactly the bug this file was written after.
//   truthful   F_GETPIPE_SZ agrees with what F_SETPIPE_SZ returned, and the
//              value returned is never MORE than the pipe can hold.
//   rejects    the command is for pipes only, and a nonsense size is refused.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif

// Whether the HOST can resize a pipe. The guest cannot tell "this host has no
// such call" from "we stopped forwarding to the host" by behaviour alone --
// both leave the capacity unchanged -- and treating that as a skip everywhere
// makes this test unable to fail for the one regression it exists to catch.
// /proc/ish/host_info names the host, so on Linux the strong assertion stands.
static int host_can_resize_pipes(void) {
    int fd = open("/proc/ish/host_info", O_RDONLY);
    if (fd < 0)
        return -1; // unknown; caller falls back to skipping
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return strstr(buf, "Linux") != NULL;
}

static void check(int cond, const char *what) {
    if (!cond)
        printf("FAIL %s (errno=%d %s)\n", what, errno, strerror(errno));
    else
        test_logf("ok %s\n", what);
    if (!cond)
        failures_total++;
}

// How much this pipe actually swallows before it would block. The only honest
// measure of capacity: fill the write end non-blocking until EAGAIN.
static long pipe_fill(int wfd) {
    int flags = fcntl(wfd, F_GETFL, 0);
    fcntl(wfd, F_SETFL, flags | O_NONBLOCK);
    static char chunk[4096];
    memset(chunk, 'x', sizeof(chunk));
    long total = 0;
    for (;;) {
        ssize_t n = write(wfd, chunk, sizeof(chunk));
        if (n <= 0)
            break;
        total += n;
        if (total > 64 * 1024 * 1024)
            break; // runaway guard
    }
    fcntl(wfd, F_SETFL, flags);
    return total;
}

int main(int argc, char **argv) {
    test_init(argc, argv);
    alarm(test_watchdog_secs(60));

    int p[2];
    check(pipe(p) == 0, "pipe()");

    int got = fcntl(p[1], F_GETPIPE_SZ, 0);
    if (got < 0 && errno == EINVAL) {
        printf("SKIP pipe_size: F_GETPIPE_SZ not supported (errno=%d %s)\n",
               errno, strerror(errno));
        return finish_suite("pipe_size");
    }
    check(got > 0, "F_GETPIPE_SZ reports a size");

    // Measure what a default pipe really holds, so "it grew" can be asserted
    // against a number from this machine rather than an assumed default.
    long held_default = pipe_fill(p[1]);
    close(p[0]);
    close(p[1]);

    check(pipe(p) == 0, "another pipe to resize");
    int want = 4 * got;
    int set = fcntl(p[1], F_SETPIPE_SZ, want);
    check(set > 0, "F_SETPIPE_SZ is accepted");

    int after = fcntl(p[1], F_GETPIPE_SZ, 0);
    check(after == set, "F_GETPIPE_SZ agrees with what F_SETPIPE_SZ returned");

    long held = pipe_fill(p[1]);
    test_logf("default held=%ld, asked %d, set=%d, now held=%ld\n",
              held_default, want, set, held);

    // Never claim more than the pipe has. A implementation that answers with
    // the REQUESTED number without resizing fails here.
    check(held >= set,
          "the pipe holds at least what F_SETPIPE_SZ claimed");

    // And the resize actually happened. This is the check that matters, and
    // the reason it is phrased against a measured baseline: an implementation
    // that quietly stops forwarding to the host still returns a plausible,
    // even truthful, number -- the host's own default -- and every other check
    // here passes. Only "it now holds MORE than it did" catches that.
    //
    // It assumes a host that can resize a pipe, which the guest-test harness
    // always is (it is Linux; tools/run-guest-tests.sh needs gcc -m32). On a
    // host that cannot -- iOS -- the honest answer is the unchanged capacity,
    // so say that rather than failing, and let the invariants above stand.
    int host_resizes = host_can_resize_pipes();
    if (set > got) {
        check(held > held_default, "the pipe really grew, not just its reported size");
    } else if (host_resizes == 1) {
        // A Linux host CAN do this, so an unchanged size is our bug, not the
        // platform's. Fail rather than skip: skipping here is precisely how a
        // lost forwarding path would go unnoticed.
        check(0, "a Linux host resizes pipes, so an unchanged size is a regression");
    } else {
        printf("SKIP pipe_size: this host does not resize pipes "
               "(asked %d, kept %d)\n", want, set);
    }
    close(p[0]);
    close(p[1]);

    // Not a pipe: Linux answers EINVAL.
    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd >= 0) {
        check(fcntl(nullfd, F_GETPIPE_SZ, 0) < 0 && errno == EINVAL,
              "F_GETPIPE_SZ on a non-pipe is EINVAL");
        close(nullfd);
    }

    // A nonsense size is refused rather than accepted and ignored.
    check(pipe(p) == 0, "second pipe()");
    check(fcntl(p[1], F_SETPIPE_SZ, 0) < 0, "F_SETPIPE_SZ(0) is refused");
    check(fcntl(p[1], F_SETPIPE_SZ, -1) < 0, "F_SETPIPE_SZ(-1) is refused");
    close(p[0]);
    close(p[1]);

    return finish_suite("pipe_size");
}
