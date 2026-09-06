#include "gadgets.h"

#define REP_LIST once,rep,repnz

.gadget cmc
    xorb $1, CPU_cf(%_cpu)
    andl $~1, CPU_eflags(%_cpu)
    movzbl CPU_cf(%_cpu), %_tmp
    orl %_tmp, CPU_eflags(%_cpu)
    gret

.gadget clc
    movb $0, CPU_cf(%_cpu)
    andl $~1, CPU_eflags(%_cpu)
    gret

.gadget stc
    movb $1, CPU_cf(%_cpu)
    orl $1, CPU_eflags(%_cpu)
    gret

.gadget cld
    andl $~DF_FLAG, CPU_eflags(%_cpu)
    movl $1, CPU_df_offset(%_cpu)
    gret

.gadget std
    orl $DF_FLAG, CPU_eflags(%_cpu)
    movl $-1, CPU_df_offset(%_cpu)
    gret

.macro do_strop op, size, rep, s, ss, a
    # repnz is only a thing for cmps and scas
    .ifc \rep,repnz
        .ifnc \op,cmps; .ifnc \op,scas
            .exitm
        .endif; .endif
    .endif

    .gadget \op\size\()_\rep
        .ifnc \rep,once
            testl %ecx, %ecx
            jz 2f
    1:
        .endif
        movl $-(\size/8), CPU_df_offset(%_cpu)
        testl $DF_FLAG, CPU_eflags(%_cpu)
        jnz 3f
        negl CPU_df_offset(%_cpu)
    3:

        .ifc \op,lods
            movl %esi, %_addr
            read_prep \size, \op\size\()_\rep
            mov\ss (%_addrq), %\a

        .else; .ifc \op,stos
            movl %edi, %_addr
            write_prep \size, \op\size\()_\rep
            mov\ss %\a, (%_addrq)
            write_done \size, \op\size\()_\rep

        .else; .ifc \op,movs
            movl %esi, %_addr
            read_prep \size, \op\size\()_\rep
            mov\ss (%_addrq), %tmp\s
            movl %edi, %_addr
            write_prep \size, \op\size\()_\rep\()2
            mov\ss %tmp\s, (%_addrq)
            write_done \size, \op\size\()_\rep

        .else; .ifc \op, scas
            mov %edi, %_addr
            read_prep \size, \op\size\()_\rep
            mov\ss (%_addrq), %r14\s
            setf_a src=%\a, dst=%r14\s, ss=\ss
            mov\ss %\a, %tmp\s
            sub\ss %r14\s, %tmp\s
            setf_oc
            setf_zsp %tmp\s, \ss

        .else; .ifc \op, cmps
            movl %esi, %_addr
            read_prep \size, \op\size\()_\rep
            mov\ss (%_addrq), %tmp\s
            mov %edi, %_addr
            read_prep \size, \op\size\()_\rep\()2
            mov\ss (%_addrq), %r14\s
            setf_a src=%r14\s, dst=%tmp\s, ss=\ss
            sub\ss %r14\s, %tmp\s
            setf_oc
            setf_zsp %tmp\s, \ss
        .endif; .endif; .endif; .endif; .endif

        .ifin(\op, lods,movs,cmps)
            addl CPU_df_offset(%_cpu), %esi
        .endifin
        .ifin(\op, movs,stos,cmps,scas)
            addl CPU_df_offset(%_cpu), %edi
        .endifin

        .ifnc \rep,once
            decl %ecx
            .ifin(\op, scas,cmps)
                .ifc \rep,rep
                    test\ss %tmp\s, %tmp\s
                    jnz 2f
                .else; .ifc \rep,repnz
                    test\ss %tmp\s, %tmp\s
                    jz 2f
                .endif; .endif
            .endifin
            testl %ecx, %ecx
            jz 2f
            # x86 makes REP interruptible BETWEEN iterations, and this loop ran
            # its whole count regardless. ecx is a guest-supplied 32-bit value,
            # so the bound is 2^32 iterations -- for that whole window the
            # thread takes no signal (no SIGKILL, no SIGSTOP) and cannot see
            # the poke, including the memory throttle raised by its own write
            # faults. Measured on the aarch64 host before the same fix: a 96 MB
            # backward `rep movsb` ran 118ms and delivered ONE signal.
            #
            # This host needs it independently: the aarch64 backend gets it via
            # rep_string_fast (jit/helpers.c), which this backend does not use
            # at all, so fixing the other host left Intel Macs and x86_64 Linux
            # with the full stall.
            #
            # ecx doubles as the counter -- it decrements every iteration, so
            # testing its low bits costs no register and checks once per 1024
            # elements. %r10 is _tmp, dead here: the scas/cmps compare above has
            # already been consumed. Same register jit_ret_chain uses to read
            # this flag.
            testl $1023, %ecx
            jnz 1b
            mov CPU_poked_ptr(%_cpu), %r10
            cmpb $0, (%r10)
            je 1b
            # Poked. save_regs in jit_exit spills ecx/esi/edi, which ARE the x86
            # restart state, so re-entry resumes the rep where it stopped. The
            # operand at (%_ip) is this instruction's guest address -- the same
            # slot segfault_read/write and the `exit` gadget read -- and _eip is
            # the low half of _ip, so this both rewinds and leaves.
            #
            # NOT the shared `poke` label: that rewinds to the start of the
            # BLOCK, which is right at a block boundary and wrong mid-block.
            movl (%_ip), %_eip
            jmp jit_ret
    2:
        .endif
        gret 1
.endm

.irp op, lods,stos,movs,scas,cmps
    .irp size, 8,16,32
        .irp rep, REP_LIST
            .if \size == 8
                do_strop \op, \size, \rep, b, b, al
            .elseif \size == 16
                do_strop \op, \size, \rep, w, w, ax
            .elseif \size == 32
                do_strop \op, \size, \rep, d, l, eax
            .endif
        .endr
    .endr
    .gadget_list_size \op, REP_LIST
.endr
# temporary
