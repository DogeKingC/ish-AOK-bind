#ifndef ISH_HOSTINFO_H
#define ISH_HOSTINFO_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

char *printHostInfo(void);
// Identifies the build itself, for uname -v. On iOS that is the app's version
// and build number ("1.3 (546)"), which is what tells you which build a device
// is actually running; elsewhere it is the compile timestamp. Caller frees.
char *copyBuildVersion(void);

// Appended to the build identifier when the emulator was compiled without
// optimization. Worth reporting because an unoptimized build is not "a bit
// slower": it changed the crypto accelerator's throughput by 13x and silently
// invalidated a full round of benchmarking, which read as "the accelerator is
// a net loss" when the real finding was "this is a debug build".
//
// Only meaningful in files the *emulator's* build system compiles (meson
// builds libish.a, and xcode-meson.sh selects buildtype=debug unless the Xcode
// configuration is Release). Do not use it from app-target sources: those are
// compiled by Xcode with its own flags and would report a different answer.
#ifdef __OPTIMIZE__
#define ISH_BUILD_OPT_SUFFIX ""
#else
#define ISH_BUILD_OPT_SUFFIX " unoptimized"
#endif

// Same idea, same reason, for the gadget dispatch mode selected by -Darm64_gret
// (see jit/guest-arm64/gadgets.h). A build whose dispatch instruction you cannot
// see makes a dispatch A/B unfalsifiable: a flat result is then indistinguishable
// from "the option never took effect", and that ambiguity really did produce a
// bogus flat reading before this existed. Reports only the NON-default 'ldar',
// so ordinary builds read unchanged, following ISH_BUILD_OPT_SUFFIX. Note the
// default flipped to dmb once ARMv8.0 was measured, so the reported value
// flipped with it: seeing nothing here means dmb.
#if defined(ISH_ARM64_GRET_LDAPR)
#define ISH_BUILD_GRET_SUFFIX " gret=ldapr"
#elif defined(ISH_ARM64_GRET_LDAR)
#define ISH_BUILD_GRET_SUFFIX " gret=ldar"
#else
#define ISH_BUILD_GRET_SUFFIX ""
#endif
// The same build stamp copyBuildVersion() formats, as a time_t: the running
// executable's own mtime, which moves on every relink. 0 if the host won't say.
// aokfs uses it as the mtime of everything it synthesizes (see fs/aok.c), so
// `ls -l /AOK` and `uname -v` describe the same build.
time_t buildTimestamp(void);
char *copyHostArchitecture(void);
char *copyHostMachineIdentifier(void);
char *copyHostDeviceName(void);
char *copyHostCoreTopology(void);

// Host CPU extensions the JIT could exploit, queried at runtime rather than
// assumed from the build's -march. That distinction is the whole point: this
// project ships ONE binary to everything from an ARMv8.0 iPad to the newest
// phone, so anything selected at compile time is selected for the oldest
// device -- and the dispatch A/B in jit/gadgets-aarch64/gadgets.h is the
// standing proof that the right answer differs by 2x between them.
//
// Only extensions with a plausible use in an x86-on-ARM emulator are listed;
// a longer list would be inventory rather than information:
//
//   flagm/flagm2  FEAT_FlagM, FEAT_FlagM2 (v8.4/v8.5). rmif/setf8/setf16/
//                 cfinv/axflag/xaflag write NZCV directly and convert between
//                 ARM and x86 flag conventions. x86 flag emulation is the
//                 hottest thing in this emulator, and the aarch64 gadgets
//                 currently synthesise all of it.
//   lrcpc/lrcpc2  FEAT_LRCPC, FEAT_LRCPC2 (v8.3/v8.4). ldapr is a cheaper
//                 load-acquire than ldar, and gadget dispatch does exactly
//                 one acquire-load per guest instruction.
//   lse/lse2      FEAT_LSE, FEAT_LSE2 (v8.1/v8.4). Atomics without an LL/SC
//                 retry loop; lse2 additionally makes unaligned atomics
//                 single-copy atomic.
//   sve/sme       Reported only to settle the recurring "should we target
//                 ARMv9" question with data. Apple implements SME but not
//                 SVE, so the headline v9 vector feature is absent on exactly
//                 the hardware this runs on.
//
// Every field is false when the host will not say, which is also what a
// non-ARM host reports -- absence is never inferred as presence.
struct host_cpu_features {
    bool valid;    // the host answered at all
    bool flagm, flagm2;
    bool lrcpc, lrcpc2;
    bool lse, lse2;
    bool sve, sme;
    char isa[32];  // e.g. "ARMv8.6-A", "" when unknown
};
void hostCpuFeatures(struct host_cpu_features *out);

// Real cache geometry of the host CPU, for /sys/devices/system/cpu/cpuN/cache.
// Any field the host will not tell us about is left 0, and the corresponding
// sysfs attribute is then omitted rather than invented.
struct host_cache_geometry {
    uint64_t l1i_size; // bytes
    uint64_t l1d_size; // bytes
    uint64_t l2_size;  // bytes
    uint64_t line_size; // bytes
};

void hostCacheGeometry(struct host_cache_geometry *out);

#endif
