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

int
main(int argc, char **argv)
{
    FILE *f;
    struct mach_header_64 mh = { };
    uint8_t *cmds;
    off_t cmd_off;
    uintptr_t offset;
    unsigned int i, j;
    int ret = 0;

    uintptr_t adjust_vma = 0;
    int verbose = 0;

#ifdef _WIN32
    setprogname(argv[0]);
#endif  /* _WIN32 */

    while (1) {
        int c, index = 0;

        enum { LI_ };

        static int long_index;
        static struct option long_options[] = {
            {"adjust-vma",    required_argument, NULL,       'a'},
            {"verbose",       no_argument,       NULL,       'v'},
            {NULL,            0,                 NULL,       0}
        };

        long_index = 0;
        c = getopt_long(argc, argv, "a:v", long_options,
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
        case 'a':
            adjust_vma = strtoull(optarg, NULL, 0);
            break;
        case 'v':
            verbose++;
            break;
        }
    }

    optind--;
    argv += optind;
    argc -= optind;

    if (argc < 2)
        errx(1, "usage: %s [options] file", argv[0]);

    f = fopen(argv[1], "r+");
    if (!f)
        err(1, "fopen %s", argv[1]);

    ret = fread(&mh, sizeof(struct mach_header_64), 1, f);
    if (ret != 1)
        err(1, "fread mach_header_64");

    if (mh.magic != MH_MAGIC_64)
        errx(1, "invalid file (header magic)");

    if (mh.filetype != MH_OBJECT && mh.filetype != MH_EXECUTE &&
        mh.filetype != MH_CORE && mh.filetype != MH_DSYM)
        errx(1, "invalid file (file type: %d)", mh.filetype);

    cmds = calloc(1, mh.sizeofcmds);
    if (!cmds)
        err(1, "calloc cmds");

    cmd_off = ftello(f);
    if (cmd_off == -1)
        err(1, "ftello cmds");

    ret = fread(cmds, mh.sizeofcmds, 1, f);
    if (ret != 1)
        err(1, "fread cmds");

    offset = 0;
    for (i = 0; i < mh.ncmds; i++) {
        struct load_command *lc;
        lc = (struct load_command *)&cmds[offset];
        v_printf("cmd %d type 0x%x size 0x%x\n", i, lc->cmd,
                 lc->cmdsize);
        offset += lc->cmdsize;

        switch (lc->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *sc = (struct segment_command_64 *)lc;
            struct section_64 *s;
            v_printf("LC_SEGMENT_64 name %-16.16s vma 0x%llx size 0x%llx\n",
                     sc->segname, sc->vmaddr, sc->vmsize);
            v_printf("              fileoff 0x%llx filesize 0x%llx nsects %d\n",
                     sc->fileoff, sc->filesize, sc->nsects);
            sc->vmaddr += adjust_vma;

            s = (struct section_64 *)&sc[1];
            for (j = 0; j < sc->nsects; j++, s++) {
                v_printf("section %02d: name %.16s.%.16s\n", j,
                         s->segname, s->sectname);
                v_printf("            vma %llx size %llx\n",
                         s->addr, s->size);
                s->addr += adjust_vma;
            }
            break;
        }
        }
    }

    if (adjust_vma) {
        ret = fseeko(f, cmd_off, SEEK_SET);
        if (ret != 0)
            err(1, "fseeko cmds");
        ret = fwrite(cmds, mh.sizeofcmds, 1, f);
        if (ret != 1)
            err(1, "fwrite cmds");
    }

    fclose(f);

    return ret;
}
