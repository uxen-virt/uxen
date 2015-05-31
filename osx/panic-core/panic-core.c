/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE "panic-core"
#include "bfd.h"
#include "mach-o.h"

#include <mach/thread_status.h>
#include <mach-o/loader.h>

#ifdef _WIN32
DECLARE_PROGNAME;
#endif  /* _WIN32 */

#ifdef PAGE_MASK
#undef PAGE_MASK
#endif
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define v_printf(fmt, ...) do {                 \
        if (verbose)                            \
            fprintf(stderr, fmt, __VA_ARGS__);  \
    } while (0)

static int verbose = 0;

#define err_bfd(fmt, ...)                                               \
    errx(1, fmt ": %s", ## __VA_ARGS__, bfd_errmsg(bfd_get_error()))

#define LINE_LEN 4096

struct stack_info {
    uintptr_t stack;
    uintptr_t stack_start;
    uintptr_t stack_end;
};

struct mach_seg_info {
    asection *sec;
    char *name;
    uintptr_t vmsize;
    uintptr_t fileoff;
    uintptr_t filesize;
};

struct mach_info {
    uintptr_t slide;
    struct mach_seg_info machtext;
    struct mach_seg_info machdata;
};

int
parse_panic(const char *file, struct x86_thread_state *regstate,
            struct stack_info *si, struct mach_info *mi)
{
    FILE *f;
    char line[LINE_LEN];
    int cpu;
    uintptr_t frame = 0, addr, next_frame, next_addr;

    si->stack = si->stack_start = si->stack_end = 0;

    f = fopen(file, "r");
    if (!f)
        err(1, "fopen panic");

    while (fgets(line, LINE_LEN, f) != NULL) {
        if (sscanf(line, "RAX: 0x%llx, RBX: 0x%llx, RCX: 0x%llx, RDX: 0x%llx",
                   &regstate->uts.ts64.__rax, &regstate->uts.ts64.__rbx,
                   &regstate->uts.ts64.__rcx, &regstate->uts.ts64.__rdx) == 4)
            continue;
        if (sscanf(line, "RSP: 0x%llx, RBP: 0x%llx, RSI: 0x%llx, RDI: 0x%llx",
                   &regstate->uts.ts64.__rsp, &regstate->uts.ts64.__rbp,
                   &regstate->uts.ts64.__rsi, &regstate->uts.ts64.__rdi) == 4)
            continue;
        if (sscanf(line, "R8:  0x%llx, R9:  0x%llx, R10: 0x%llx, R11: 0x%llx",
                   &regstate->uts.ts64.__r8, &regstate->uts.ts64.__r9,
                   &regstate->uts.ts64.__r10, &regstate->uts.ts64.__r11) == 4)
            continue;
        if (sscanf(line, "R12: 0x%llx, R13: 0x%llx, R14: 0x%llx, R15: 0x%llx",
                   &regstate->uts.ts64.__r12, &regstate->uts.ts64.__r13,
                   &regstate->uts.ts64.__r14, &regstate->uts.ts64.__r15) == 4)
            continue;
        if (sscanf(line, "RFL: 0x%llx, RIP: 0x%llx, CS:  0x%llx, SS:  0x%*llx",
                   &regstate->uts.ts64.__rflags, &regstate->uts.ts64.__rip,
                   &regstate->uts.ts64.__cs) == 3)
            continue;
        if (sscanf(line, "Backtrace (CPU %d), Frame : Return Address",
                   &cpu) == 1) {
            while (fgets(line, LINE_LEN, f) != NULL) {
                if (sscanf(line, "0x%lx : 0x%lx", &next_frame, &next_addr) != 2)
                    break;
                if (!regstate->uts.ts64.__rip &&
                    next_frame == regstate->uts.ts64.__rbp)
                    regstate->uts.ts64.__rip = next_addr;
                if (!frame) {
                    frame = next_frame;
                    addr = next_addr;
                    continue;
                }
                if ((frame & PAGE_MASK) > si->stack_end) {
                    if (!si->stack_start) {
                        si->stack = (uintptr_t)calloc(1, PAGE_SIZE);
                        if (!si->stack)
                            err(1, "calloc stack");
                        si->stack_start = frame & PAGE_MASK;
                        si->stack_end = si->stack_start + PAGE_SIZE;
                    } else {
                        uintptr_t new_end;
                        new_end = (frame & PAGE_MASK) + PAGE_SIZE;
                        si->stack = (uintptr_t)realloc((void *)si->stack,
                                                   new_end - si->stack_start);
                        if (!si->stack)
                            err(1, "realloc stack");
                        memset((void *)(si->stack + si->stack_end -
                                        si->stack_start), 0,
                               new_end - si->stack_end);
                    }
                }
                if (frame < si->stack_start)
                    errx(1, "stack going backwards");
                *(uintptr_t *)(si->stack + frame - si->stack_start) =
                    next_frame;
                *(uintptr_t *)(si->stack + frame - si->stack_start + 8) =
                    addr;
                frame = next_frame;
                addr = next_addr;
            }
            continue;
        }
        if (sscanf(line, "Kernel slide:     0x%lx", &mi->slide) == 1)
            continue;
    }

    v_printf("stack from %lx to %lx\n", si->stack_start, si->stack_end);

    return 0;
}

asection *
create_copy_section(bfd *ibfd, const char *isec_name, bfd *obfd,
                    const char *osec_name, uintptr_t vma_base)
{
    asection *isec, *osec;
    int ret;

    isec = bfd_get_section_by_name(ibfd, isec_name);
    if (!isec)
        err_bfd("bfd_get_section_by_name %s failed", isec_name);

#if 0
    ret = bfd_set_section_vma(ibfd, isec, vma_base +
                              bfd_section_vma(ibfd, isec));
    if (!ret)
        err_bfd("bfd_set_section_vma %s failed", isec_name);
#endif

    osec = bfd_make_section_with_flags(obfd, osec_name,
                                       SEC_HAS_CONTENTS);
    if (!osec)
        err_bfd("bfd_make_section %s failed", osec_name);

    ret = bfd_set_section_size(obfd, osec, bfd_section_size(ibfd, isec));
    if (!ret)
        err_bfd("bfd_set_section_size %s failed", osec_name);

    ret = bfd_set_section_vma(obfd, osec, vma_base +
                              bfd_section_vma(ibfd, isec));
    if (!ret)
        err_bfd("bfd_set_section_vma %s failed", osec_name);

    return osec;
}

int
set_copy_section(bfd *ibfd, const char *isec_name, bfd *obfd, asection *osec,
                 uintptr_t vma_base)
{
    asection *isec;
    unsigned int size;
    bfd_byte *buf;
    void *p;
    int ret;

    isec = bfd_get_section_by_name(ibfd, isec_name);
    if (!isec)
        err_bfd("bfd_get_section_by_name %s failed", isec_name);

    size = bfd_section_size(ibfd, isec);
    buf = calloc(1, size);
    if (!buf)
        err(1, "calloc %s/%d failed", isec_name, size);

    p = bfd_simple_get_relocated_section_contents(ibfd, isec, buf, NULL);
    if (p != buf)
        err_bfd("bfd_simple_get_relocated_section_contents %s failed",
                isec_name);

    ret = bfd_set_section_contents(obfd, osec, buf, 0, size);
    if (!ret)
        err_bfd("bfd_set_section_contents %s failed", osec->name);

    return 1;
}

int
main(int argc, char **argv)
{
    FILE *machf;
    bfd *obfd;
    asection *tssec;
    struct x86_thread_state ts = { };
    asection *stacksec;
    struct stack_info si = { };
    struct mach_seg_info *seg;
    struct mach_info mi = { };
    int ret;

#ifdef _WIN32
    setprogname(argv[0]);
#endif  /* _WIN32 */

    while (1) {
        int c, index = 0;

        enum { LI_ };

        static int long_index;
        static struct option long_options[] = {
            {"verbose",       no_argument,       NULL,       'v'},
            {NULL,            0,                 NULL,       0}
        };

        long_index = 0;
        c = getopt_long(argc, argv, "v", long_options,
                        &index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            switch (long_index) {
            case LI_:
                break;
            }
            break;
        case 'v':
            verbose++;
            break;
        }
    }

    optind--;
    argv += optind;
    argc -= optind;

    if (argc != 4)
        errx(1, "usage: %s [-v] outfile panic.txt mach_kernel",
             argv[0]);

    ret = parse_panic(argv[2], &ts, &si, &mi);
    if (ret)
        errx(1, "parse panic failed");

    /* open mach_kernel */
    machf = fopen(argv[3], "r");
    if (!machf)
        err(1, "fopen mach_kernel failed");

    /* open output core file */
    obfd = bfd_openw(argv[1], "mach-o-x86-64");
    if (!obfd)
        errx(1, "bfd_openw failed");

    ret = bfd_set_arch_mach(obfd, bfd_arch_i386, bfd_mach_x86_64);
    if (!ret)
        err_bfd("bfd_set_arch_mach failed");

    ret = bfd_set_format(obfd, bfd_core);
    if (!ret)
        err_bfd("bfd_set_format failed");

    /* create thread state section */
    tssec = bfd_make_section_with_flags(obfd, "LC_THREAD.x86_THREAD_STATE.0",
                                        SEC_HAS_CONTENTS | SEC_IN_MEMORY |
                                        SEC_LINKER_CREATED);
    if (!tssec)
        err_bfd("bfd_make_section thread state failed");

    ret = bfd_set_section_size(obfd, tssec, sizeof(ts));
    if (!ret)
        err_bfd("bfd_set_section_size thread state failed");

    /* create stack section */
    stacksec = bfd_make_section_with_flags(obfd, "stack", SEC_HAS_CONTENTS);
    if (!stacksec)
        err_bfd("bfd_make_section stack failed");

    ret = bfd_set_section_size(obfd, stacksec,
                               si.stack_end - si.stack_start);
    if (!ret)
        err_bfd("bfd_set_section_size stack failed");

    ret = bfd_set_section_vma(obfd, stacksec, si.stack_start);
    if (!ret)
        err_bfd("bfd_set_section_vma stack failed");

    /* read mach_kernel and create sections for text and data segments */
    {
        struct mach_header_64 mh;
        uint8_t *cmds;
        off_t cmd_off;
        uintptr_t offset;
        unsigned int i;

        ret = fread(&mh, sizeof(struct mach_header_64), 1, machf);
        if (ret != 1)
            err(1, "fread mach_header_64");

        if (mh.magic != MH_MAGIC_64)
            errx(1, "invalid file (header magic)");

        if (mh.filetype != MH_OBJECT && mh.filetype != MH_EXECUTE &&
            mh.filetype != MH_CORE)
            errx(1, "invalid file (file type)");

        cmds = calloc(1, mh.sizeofcmds);
        if (!cmds)
            err(1, "calloc cmds");

        cmd_off = ftello(machf);
        if (cmd_off == -1)
            err(1, "ftello cmds");

        ret = fread(cmds, mh.sizeofcmds, 1, machf);
        if (ret != 1)
            err(1, "fread cmds");

        offset = 0;
        for (i = 0; i < mh.ncmds; i++) {
            struct load_command *lc;
            lc = (struct load_command *)&cmds[offset];
            v_printf("cmd %d type 0x%x size 0x%x\n", i, lc->cmd, lc->cmdsize);
            offset += lc->cmdsize;

            switch (lc->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64 *sc = (struct segment_command_64 *)lc;
                v_printf("LC_SEGMENT_64 name %-16.16s vma 0x%llx size 0x%llx\n",
                         sc->segname, sc->vmaddr, sc->vmsize);
                v_printf("              fileoff 0x%llx filesize 0x%llx\n",
                         sc->fileoff, sc->filesize);
                if (!strncmp(sc->segname, "__TEXT", 16)) {
                    seg = &mi.machtext;
                    seg->name = "mach_text";
                } else if (!strncmp(sc->segname, "__DATA", 16)) {
                    seg = &mi.machdata;
                    seg->name = "mach_data";
                } else
                    break;

                seg->sec = bfd_make_section_with_flags(obfd, seg->name,
                                                      SEC_HAS_CONTENTS);
                if (!seg->sec)
                    err_bfd("bfd_make_section %s failed", seg->name);

                ret = bfd_set_section_size(obfd, seg->sec, sc->vmsize);
                if (!ret)
                    err_bfd("bfd_set_section_size %s failed", seg->name);

                ret = bfd_set_section_vma(obfd, seg->sec,
                                          sc->vmaddr + mi.slide);
                if (!ret)
                    err_bfd("bfd_set_section_vma %s failed", seg->name);

                seg->vmsize = sc->vmsize;
                seg->fileoff = sc->fileoff;
                seg->filesize = sc->filesize;

                break;
            }
            }
        }
    }

    /* output thread state section */
    ts.tsh.flavor = x86_THREAD_STATE64;
    ts.tsh.count = x86_THREAD_STATE64_COUNT;

    tssec->contents = bfd_alloc(obfd, sizeof(ts));

    ret = bfd_set_section_contents(obfd, tssec, &ts, 0,
                                   sizeof(ts));
    if (!ret)
        err_bfd("bfd_set_section_contents thread state failed");

    /* output reconstructed stack */
    ret = bfd_set_section_contents(obfd, stacksec, (void *)si.stack, 0,
                                   si.stack_end - si.stack_start);
    if (!ret)
        err_bfd("bfd_set_section_contents stack failed");

    /* output text/data sections copies from mach_kernel */
    seg = NULL;
    do {
        uint8_t *buf;

        if (!seg)
            seg = &mi.machtext;
        else if (seg == &mi.machtext)
            seg = &mi.machdata;
        else if (seg == &mi.machdata)
            break;

        buf = calloc(1, seg->vmsize);
        if (!buf)
            err(1, "calloc %s/%ld failed", seg->name, seg->vmsize);

        ret = fseeko(machf, seg->fileoff, SEEK_SET);
        if (ret != 0)
            err(1, "fseeko %s failed", seg->name);

        ret = fread(buf, seg->filesize, 1, machf);
        if (ret != 1)
            err(1, "fread %s failed", seg->name);

        ret = bfd_set_section_contents(obfd, seg->sec, buf, 0, seg->vmsize);
        if (!ret)
            err_bfd("bfd_set_section_contents %s failed", seg->name);

        free(buf);
    } while (1);

    ret = bfd_close(obfd);
    if (!ret)
        err_bfd("bfd_close failed");

    return 0;
}
