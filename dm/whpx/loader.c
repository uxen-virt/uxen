/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include "whpx.h"

#define NO_XEN_ELF_NOTE
#include <libelf/libelf.h>

static void
elf_log_cb(struct elf_binary *elf, void *called_data, int iserr,
           const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
}

static int
load_elf_image(void *membase, uint8_t *image, uint32_t image_size, uint64_t *out_start_rip,
               uint64_t *out_elf_end)
{
    struct elf_binary elf;

    elf_set_log(&elf, elf_log_cb, NULL, 1);

    memset(&elf, 0, sizeof(elf));
    if ( elf_init(&elf, (char*)image, image_size) != 0 )
        goto error_out;

    elf_parse_binary(&elf);

    debug_printf("VIRTUAL MEMORY ARRANGEMENT:\n"
             "  Loader:        %016"PRIx64"->%016"PRIx64"\n"
             "  ENTRY ADDRESS: %016"PRIx64"\n",
             elf.pstart, elf.pend,
             elf_uval(&elf, elf.ehdr, e_entry));

    elf.dest = membase + elf.pstart;
    elf_load_binary(&elf);

    *out_start_rip = elf_uval(&elf, elf.ehdr, e_entry);
    *out_elf_end = elf.pend;

    return 0;

error_out:
    return -1;
}

/* load hvmloader at membase, return it's start IP and end address */
void
load_hvmloader(
    const char *imagefile,
    void *membase,
    uint64_t *start_rip,
    uint64_t *hvmloader_end)
{
    uint8_t *image, *p;
    uint32_t len;
    FILE *f = fopen(imagefile, "rb");
    int i;

    if (!f)
        whpx_panic("failed to open kernel file: %s", imagefile);
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    p = image = malloc(len);
    if (!image)
        whpx_panic("no memory");

    // FIXME: slow?
    for (i = 0; i < len; ++i) {
        size_t rd = fread(p, 1, 1, f);
        if (!rd) {
            if (feof(f))
                break;
            else
                whpx_panic("error reading kernel file");
        }
        ++p;
    }
    fclose(f);

    if (load_elf_image(membase, image, len, start_rip, hvmloader_end))
        whpx_panic("error loading elf kernel image");
    free(image);
}
