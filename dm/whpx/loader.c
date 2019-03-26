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

/* load trampoline code at membase, which switches to protected mode
 * and jumps to 'jmp_addr'
 * FIXME: this should be loaded from some assembly file */
void
load_pmode_trampoline(void *membase, uint64_t jmp_addr)
{
    /* generated from trampoline.asm, switches to protected mode using skanky code from stackoverflow */
    static unsigned char array[] = {
0xea, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
0x00, 0x00, 0x9a, 0xcf, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0xcf, 0x00, 0x18, 0x00, 0x05,
0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x8e, 0xd0, 0xbc, 0xfc, 0xff, 0xb8, 0x00, 0x00, 0x8e, 0xd8,
0x8e, 0xc0, 0x8e, 0xe0, 0x8e, 0xe8, 0xfa, 0x0f, 0x01, 0x16, 0x1d, 0x00, 0x0f, 0x20, 0xc0, 0x66,
0x83, 0xc8, 0x01, 0x0f, 0x22, 0xc0, 0xea, 0x4b, 0x00, 0x08, 0x00, 0x66, 0xb8, 0x10, 0x00, 0x8e,
0xd8, 0x8e, 0xc0, 0x8e, 0xe0, 0x8e, 0xe8, 0x8e, 0xd0, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0xff, 0xe0,
    };

    // deadbeef -> jmp_addr;
    int i;
    for (i = 0; i < sizeof(array)-4; ++i) {
        uint32_t *p = (uint32_t*)&array[i];
        if (*p == 0xdeadbeef)
            *p = (uint32_t)jmp_addr;
    }

    memcpy(membase, array, sizeof(array));
}
