/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

//#include "xc_private.h"

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

//#include "xg_private.h"
#include "attoimg.h"
#include "attoimg-private.h"
#include "util.h"
#include "sha256.h"

#include "libelf.h"

#define DEFAULT_FILE_ATTOLINUX "vmlinux.bin"
#define DEFAULT_FILE_ATTOINITRAMFS "initramfs.cpio.gz"
#define DEFAULT_FILE_ATTOTRAMPOLINE "trampoline-64.raw"

#define BOOTDATA_ADDR  0x14000
#define MPTABLES_ADDR  0xf0000
#define MPTABLES_SIZE 1024

#define ROOTDEV "/dev/sda"
#define VERITYDEV "/dev/sdb"
#define RESUMEDEV "/dev/sdc"
#define CMDLINE_ADDR (BOOTDATA_ADDR + 4096)
#define CMDLINE_SIZE 512
#define CMDLINE "BOOT_IMAGE=/vmlinuz initrd=/initrd LABEL=boot " \
  "root="ROOTDEV" verity="VERITYDEV" resume="RESUMEDEV" " \
  "no_console_suspend=1 clocksource=tsc noxsave debug"

#define PAGE_ALIGNED(x) (!((x) & (PAGE_SIZE-1)))
#define PAGE_ALIGN(x) (((x) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))
#define ERROR(fmt, ...) log_error("ERROR: " fmt "\n", ##__VA_ARGS__)

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#define E820MAX         128
#define E820_RAM        1
#define E820_RESERVED   2
#define EDD_MBR_SIG_MAX 16

#define VGA_HOLE_PFN_START 0xa0
#define VGA_HOLE_PFN_END   0xbf

struct e820entry {
    __u64 addr;     /* start of memory segment */
    __u64 size;     /* size of memory segment */
    __u32 type;     /* type of memory segment */
} __attribute__((packed));

struct setup_header {
    __u8    setup_sects;
    __u16   root_flags;
    __u32   syssize;
    __u16   ram_size;
    __u16   vid_mode;
    __u16   root_dev;
    __u16   boot_flag;
    __u16   jump;
    __u32   header;
    __u16   version;
    __u32   realmode_swtch;
    __u16   start_sys;
    __u16   kernel_version;
    __u8    type_of_loader;
    __u8    loadflags;
    __u16   setup_move_size;
    __u32   code32_start;
    __u32   ramdisk_image;
    __u32   ramdisk_size;
    __u32   bootsect_kludge;
    __u16   heap_end_ptr;
    __u8    ext_loader_ver;
    __u8    ext_loader_type;
    __u32   cmd_line_ptr;
    __u32   initrd_addr_max;
    __u32   kernel_alignment;
    __u8    relocatable_kernel;
    __u8    min_alignment;
    __u16   xloadflags;
    __u32   cmdline_size;
    __u32   hardware_subarch;
    __u64   hardware_subarch_data;
    __u32   payload_offset;
    __u32   payload_length;
    __u64   setup_data;
    __u64   pref_address;
    __u32   init_size;
    __u32   handover_offset;
} __attribute__((packed));

struct boot_params {
    __u8  _pad_screen_info[0x40];                 /* 0x000 */
    __u8  _pad_apm_bios_info[0x14];             /* 0x040 */
    __u8  _pad2[4];                                 /* 0x054 */
    __u64  tboot_addr;                              /* 0x058 */
    __u8  _pad_ist_info[0x10];                       /* 0x060 */
    __u8  _pad3[16];                                /* 0x070 */
    __u8  hd0_info[16];     /* obsolete! */         /* 0x080 */
    __u8  hd1_info[16];     /* obsolete! */         /* 0x090 */
    __u8 _pad_sys_desc_table[0x10]; /* obsolete! */   /* 0x0a0 */
    __u8 _padolpc_ofw_header[0x10];         /* 0x0b0 */
    __u32 ext_ramdisk_image;                        /* 0x0c0 */
    __u32 ext_ramdisk_size;                         /* 0x0c4 */
    __u32 ext_cmd_line_ptr;                         /* 0x0c8 */
    __u8  _pad4[116];                               /* 0x0cc */
    __u8  _pad_edid_info[0x80];                     /* 0x140 */
    __u8  _pad_efi_info[0x20];                       /* 0x1c0 */
    __u32 alt_mem_k;                                /* 0x1e0 */
    __u32 scratch;          /* Scratch field! */    /* 0x1e4 */
    __u8  e820_entries;                             /* 0x1e8 */
    __u8  eddbuf_entries;                           /* 0x1e9 */
    __u8  edd_mbr_sig_buf_entries;                  /* 0x1ea */
    __u8  kbd_status;                               /* 0x1eb */
    __u8  _pad5[3];                                 /* 0x1ec */
    __u8  sentinel;                                 /* 0x1ef */
    __u8  _pad6[1];                                 /* 0x1f0 */
    struct setup_header hdr;    /* setup header */  /* 0x1f1 */
    __u8  _pad7[0x290-0x1f1-sizeof(struct setup_header)];
    __u32 edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];      /* 0x290 */
    struct e820entry e820_map[E820MAX];             /* 0x2d0 */
    __u8  _pad8[48];                                /* 0xcd0 */
    __u8  _pad_eddbuf[0x1ec];               /* 0xd00 */
    __u8  _pad9[276];                               /* 0xeec */
} __attribute__((packed));

struct attoimg_builder {
    struct attoimg_guest_mapper *mapper;
};

static attoimg_error_log_fun_t error_log_fun;

void attoimg_set_error_log_fun(attoimg_error_log_fun_t f)
{
    error_log_fun = f;
}

static void
log_error(const char *fmt, ...)
{
    char msg[512];

    va_list args;

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (error_log_fun)
        error_log_fun(msg);
    else
        printf("%s", msg);
}

struct mapper_pagerange {
    uint64_t pfn;
    uint64_t count;
    void *memory;
};

struct simple_mapper_data {
    int num_pageranges;
    struct mapper_pagerange pagerange[ATTOVM_MAX_PAGERANGES];
};

static void *
simple_map(struct attoimg_guest_mapper *m, uint64_t addr, uint64_t size)
{
    struct simple_mapper_data *d = m->opaque;
    uint64_t pfn, count;
    void *ptr = NULL;
    int i;

//    printf("mapping addr 0x%016"PRIx64" length 0x%"PRIx64"\n",
//        addr, size);

    if (!PAGE_ALIGNED(addr))
        return NULL;
    size = PAGE_ALIGN(size);
    pfn = addr >> PAGE_SHIFT;
    count = size >> PAGE_SHIFT;
    for (i = 0; i < d->num_pageranges; i++) {
        if (d->pagerange[i].pfn == pfn && d->pagerange[i].count == count)
            return d->pagerange[i].memory;
    }

    if (d->num_pageranges >= ATTOVM_MAX_PAGERANGES)
        return NULL;

    ptr = malloc(size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, size);
    d->pagerange[d->num_pageranges].pfn = pfn;
    d->pagerange[d->num_pageranges].count = count;
    d->pagerange[d->num_pageranges].memory = ptr;
    d->num_pageranges++;

    return ptr;
}

static void
simple_unmap(struct attoimg_guest_mapper *m, void *ptr, uint64_t size)
{
}

struct attoimg_guest_mapper *
attoimg_create_simple_mapper(void)
{
    struct attoimg_guest_mapper *m;
    struct simple_mapper_data *data;

    m = malloc(sizeof(struct attoimg_guest_mapper));
    if (!m)
        return NULL;
    memset(m, 0, sizeof(*m));

    data = malloc(sizeof(struct simple_mapper_data));
    if (!data) {
        free(m);
        return NULL;
    }

    data->num_pageranges = 0;

    m->opaque = data;
    m->map = simple_map;
    m->unmap = simple_unmap;

    return m;
}

void
attoimg_free_simple_mapper(struct attoimg_guest_mapper *m)
{
    if (m) {
        struct simple_mapper_data *data = m->opaque;
        int i;

        for (i = 0; i < data->num_pageranges; i++)
            free(data->pagerange[i].memory);
        free(m->opaque);
        free(m);
    }
}

static void
zeropad(void *buffer, size_t size)
{
    size_t size_aligned = PAGE_ALIGN(size);
    size_t pad = size_aligned - size;

    if (pad)
        memset((char*)buffer + size, 0, size_aligned - size);
}

static int
add_page_range(struct attoimg_builder *builder, struct attovm_definition_v1 *def,
    uint64_t pfn, uint32_t count)
{
    if (def->m.num_pageranges >= ATTOVM_MAX_PAGERANGES) {
        ERROR("Out of free pageranges\n");
        return -1;
    }
    def->m.pagerange[def->m.num_pageranges].pfn   = pfn;
    def->m.pagerange[def->m.num_pageranges].count = count;
    def->m.num_pageranges++;

    return 0;
}

static int
load_elf(struct attoimg_builder *builder, struct elf_binary *elf,
    struct attovm_definition_v1 *def)
{
    struct attoimg_guest_mapper *mapper = builder->mapper;
    uint64_t pgoff = elf->pstart & (PAGE_SIZE-1);
    uint64_t pfn = elf->pstart >> PAGE_SHIFT;
    uint64_t sz = elf->pend - elf->pstart + 1;
    uint64_t sz_aligned = PAGE_ALIGN(sz);
    void *mapped;

    if (pgoff) {
        ERROR("Elf load address %lx is not aligned", elf->pstart);
        return -1;
    }
    mapped = mapper->map(mapper, pfn << PAGE_SHIFT, sz_aligned);
    if (!mapped) {
        ERROR("Failed to map elf image\n");
        return -1;
    }
    elf->dest = mapped + pgoff;
    elf_load_binary(elf);
    zeropad(mapped, sz);
    mapper->unmap(mapper, mapped, sz_aligned);
    elf->dest = NULL;

    return add_page_range(builder, def, elf->pstart >> PAGE_SHIFT, sz_aligned >> PAGE_SHIFT);
}

static int
load_elf_image(struct attoimg_builder *builder, const char *image_name,
    struct attovm_definition_v1 *def)
{
    struct elf_binary elf;
    void *image;
    unsigned long image_size;

    image = read_image(image_name, &image_size);
    if (!image) {
        ERROR("Failed to load elf image file: %s", image_name);
        return -1;
    }

    memset(&elf, 0, sizeof(elf));
    if ( elf_init(&elf, image, image_size) != 0 ) {
        ERROR("Failed to init elf parser");
        return -1;
    }
    elf_parse_binary(&elf);

    return load_elf(builder, &elf, def);
}

static int
load_raw_image(struct attoimg_builder *builder, const char *image_name, uint64_t addr,
    struct attovm_definition_v1 *def)
{
    struct attoimg_guest_mapper *mapper = builder->mapper;
    void *image;
    unsigned long image_size, image_size_aligned;
    void *mapped;

    if (!PAGE_ALIGNED(addr)) {
        ERROR("Address %"PRIx64" is not aligned", addr);
        return -1;
    }

    image = read_image(image_name, &image_size);
    if (!image) {
        ERROR("Failed to load raw image file: %s", image_name);
        return -1;
    }

    image_size_aligned = PAGE_ALIGN(image_size);
    mapped = mapper->map(mapper, addr, image_size_aligned);
    if (!mapped) {
        ERROR("Failed to map area for raw image\n");
        return -1;
    }
    memcpy(mapped, image, image_size);
    zeropad(mapped, image_size);
    mapper->unmap(mapper, mapped, image_size);

    return add_page_range(builder, def, addr >> PAGE_SHIFT, image_size_aligned >> PAGE_SHIFT);
}

static int
load_trampoline(struct attoimg_builder *builder,
    struct attoimg_initial_image_info *info,
    struct attovm_definition_v1 *def)
{
    return load_raw_image(builder,
        info->trampoline ? info->trampoline : DEFAULT_FILE_ATTOTRAMPOLINE, 0, def);
}

static int
load_kernel(struct attoimg_builder *builder,
    struct attoimg_initial_image_info *info,
    struct attovm_definition_v1 *def)
{
    /* vmlinux.bin has to be uncompressed elf kernel image */
    return load_elf_image(builder,
        info->kernel ? info->kernel : DEFAULT_FILE_ATTOLINUX, def);
}

static void
build_cmdline(char *ptr, int flags, uint8_t *roothash)
{
    char str_hash[ATTOIMG_ROOTHASH_BYTES * 2 + 1] = { 0 };
    char str_apic[32] = { 0 };
    char str_tsc[32] = { 0 };
    int i;

//    if (!(flags % ATTOVM_USE_APIC))
//      snprintf(str_apic, sizeof(str_apic), " disableapic");
    for (i = 0; i < ATTOIMG_ROOTHASH_BYTES; i++)
      sprintf(str_hash + i*2, "%02x", roothash[i]);

    snprintf(ptr, CMDLINE_SIZE, "%s roothash=%s %s%s", CMDLINE, str_hash,
      str_apic, str_tsc);
}

static int
load_bootdata(struct attoimg_builder *builder, uint64_t memsize, struct boot_params *bp,
  int flags, uint8_t *roothash, struct attovm_definition_v1 *def)
{
    struct attoimg_guest_mapper *mapper = builder->mapper;
    uint64_t lowmem_end = memsize;
    void *mapped;
    int i;
    uint64_t sz = sizeof(struct boot_params);
    uint64_t sz_aligned = PAGE_ALIGN(sz);

    i = 0;
    bp->e820_map[i].addr = 0;
    bp->e820_map[i].size = 0x9e800;
    bp->e820_map[i].type = E820_RAM;

    i++;
    bp->e820_map[i].addr = 0x9e800;
    bp->e820_map[i].size = 0xa0000 - 0x9e800;
    bp->e820_map[i].type = E820_RESERVED;

    i++;
    bp->e820_map[i].addr = 0xf0000;
    bp->e820_map[i].size = 0x100000 - 0xf0000;
    bp->e820_map[i].type = E820_RESERVED;

    i++;
    bp->e820_map[i].addr = 0x100000;
    bp->e820_map[i].size = lowmem_end - 0x100000;
    bp->e820_map[i].type = E820_RAM;

    i++;
    bp->e820_map[i].addr = 0xfc000000;
    bp->e820_map[i].size = 0x100000000 - 0xfc000000;
    bp->e820_map[i].type = E820_RESERVED;

    bp->e820_entries = i+1;

    bp->hdr.type_of_loader = 0xFF;

    bp->hdr.cmd_line_ptr = CMDLINE_ADDR;
    bp->hdr.cmdline_size = CMDLINE_SIZE;

    /* copy boot params */
    mapped = mapper->map(mapper, BOOTDATA_ADDR, sz_aligned);
    if (!mapped) {
        ERROR("Failed to map boot params page");
        return -1;
    }
    memcpy(mapped, bp, sizeof(struct boot_params));
    zeropad(mapped, sz);
    mapper->unmap(mapper, mapped, sz_aligned);

    if (add_page_range(builder, def, BOOTDATA_ADDR >> PAGE_SHIFT,
            PAGE_ALIGN(sz_aligned) >> PAGE_SHIFT))
        return -1;

    /* copy cmdline */
    mapped = mapper->map(mapper, CMDLINE_ADDR, CMDLINE_SIZE);
    if (!mapped) {
        ERROR("Failed to map cmdline area");
        return -1;
    }
    build_cmdline(mapped, flags, roothash);
    zeropad(mapped, CMDLINE_SIZE);
    mapper->unmap(mapper, mapped, CMDLINE_SIZE);

    if (add_page_range(builder, def, CMDLINE_ADDR >> PAGE_SHIFT,
            PAGE_ALIGN(CMDLINE_SIZE) >> PAGE_SHIFT))
        return -1;

    return 0;
}

static int
load_initramfs(struct attoimg_builder *builder,
    struct attoimg_initial_image_info *info,
    uint64_t memsize, struct boot_params *bp,
    struct attovm_definition_v1 *def)
{
    struct attoimg_guest_mapper *mapper = builder->mapper;
    void *image;
    unsigned long image_size, image_size_aligned;
    void *mapped;
    uint64_t addr;

    image = read_image(
        info->initramfs ? info->initramfs : DEFAULT_FILE_ATTOINITRAMFS,
        &image_size);
    if (!image) {
        ERROR("Failed to load initramfs file");
        return -1;
    }

    /* load initramfs to top of ram */
    image_size_aligned = PAGE_ALIGN(image_size);

    addr = memsize - image_size_aligned;
    addr &= ~(PAGE_SIZE-1);
    mapped = mapper->map(mapper, addr, image_size_aligned);
    if (!mapped) {
        ERROR("Failed to map initramfs area");
        return -1;
    }
    memcpy(mapped, image, image_size);
    zeropad(mapped, image_size);
    mapper->unmap(mapper, mapped, image_size_aligned);

    bp->hdr.ramdisk_image = addr;
    bp->hdr.ramdisk_size = image_size;

    return add_page_range(builder, def, addr >> PAGE_SHIFT, PAGE_ALIGN(image_size) >> PAGE_SHIFT);
}

static int
load_mptables(struct attoimg_builder *builder, int vcpus, int flags,
    struct attovm_definition_v1 *def)
{
    struct attoimg_guest_mapper *mapper = builder->mapper;
    void *mapped;

    mapped = mapper->map(mapper, MPTABLES_ADDR, MPTABLES_SIZE);
    if (!mapped) {
        ERROR("Failed to map mptables area");
        return -1;
    }
    create_mp_tables(MPTABLES_ADDR, mapped, vcpus, 1); //!!(flags & ATTOVM_USE_APIC));
    zeropad(mapped, MPTABLES_SIZE);
    mapper->unmap(mapper, mapped, MPTABLES_SIZE);

    return add_page_range(builder, def, MPTABLES_ADDR >> PAGE_SHIFT, PAGE_ALIGN(MPTABLES_SIZE) >> PAGE_SHIFT);
}

static int
pagerange_compare(const void *a_, const void *b_)
{
    const struct attovm_pagerange *a = a_;
    const struct attovm_pagerange *b = b_;

    if (a->pfn < b->pfn)
        return -1;
    if (a->pfn > b->pfn)
        return 1;
    return 0;
}

static int
load_kernel_structures(
    struct attoimg_builder *builder,
    struct attoimg_initial_image_info *info,
    struct attovm_definition_v1 *definition
)
{
    int ret = -1;
    struct boot_params bp = { };
    uint64_t memsize = info->memsize_mb << 20;

    definition->m.num_pages = memsize >> PAGE_SHIFT;
    definition->m.num_pageranges = 0;

    printf("loading trampoline\n");
    if (load_trampoline(builder, info, definition)) {
        ERROR("Failed to load trampoline");
        goto out;
    }

    printf("loading kernel\n");
    if (load_kernel(builder, info, definition)) {
        ERROR("Failed to load kernel");
        goto out;
    }

    printf("loading initramfs\n");
    if (load_initramfs(builder, info, memsize, &bp, definition)) {
        ERROR("Failed to load initramfs");
        goto out;
    }

    printf("loading bootdata\n");
    if (load_bootdata(builder, memsize, &bp, info->flags, info->roothash, definition)) {
        ERROR("Failed to load boot data");
        goto out;
    }

    printf("loading mptables\n");
    if (load_mptables(builder, info->nr_vcpus, info->flags, definition)) {
        ERROR("Failed to load mp tables");
        goto out;
    }

    /* sort pageranges */
    qsort(definition->m.pagerange, definition->m.num_pageranges,
        sizeof(definition->m.pagerange[0]),
        pagerange_compare);

    ret = 0;

out:
    return ret;
}

static size_t
write_bytes(FILE *f, void *buffer, size_t count)
{
    size_t wr_total = 0;

    while (wr_total != count) {
        size_t wr = fwrite(buffer, 1, count - wr_total, f);
        if (!wr)
            return 0;
        wr_total += wr;
    }

    return wr_total;
}

static size_t
read_bytes(FILE *f, void *buffer, size_t count)
{
    size_t rd_total = 0;
    while (rd_total != count) {
        size_t rd = fread(buffer, 1, count - rd_total, f);
        if (!rd)
            return 0;
        rd_total += rd;
    }

    return rd_total;
}

static int
image_write_page_range_contents(
    FILE *f,
    struct attoimg_builder *builder,
    struct attovm_definition_v1 *def)
{
    int i;
    int ret = -1;
    struct attoimg_guest_mapper *mapper = builder->mapper;

    /* write page ranges */
    for (i = 0; i < def->m.num_pageranges; i++) {
        struct attovm_pagerange *range = &def->m.pagerange[i];
        size_t size = range->count << PAGE_SHIFT;
        void *mem = mapper->map(mapper, range->pfn << PAGE_SHIFT, size);
        if (!mem) {
            ERROR("Failed to map range");
            goto out;
        }
        if (write_bytes(f, mem, size) != size) {
            ERROR("Failed to write page range %d", i);
            goto out;
        }
        mapper->unmap(mapper, mem, size);
    }

    ret = 0;

out:
    return ret;
}

static int
image_read_page_range_contents(
    FILE *f,
    struct attoimg_guest_mapper *mapper,
    struct attovm_definition_v1 *def)
{
    int i;
    int ret = -1;

    /* load pageranges */
    for (i = 0; i < def->m.num_pageranges; i++) {
        struct attovm_pagerange *range = &def->m.pagerange[i];
        size_t size = range->count << PAGE_SHIFT;
        void *mem = mapper->map(mapper, range->pfn << PAGE_SHIFT, size);
        if (!mem) {
            ERROR("Failed to map guest memory pfn %"PRIx64" pages %"PRIx64,
                range->pfn, range->count);
            goto out;
        }
        if (read_bytes(f, mem, size) != size) {
            ERROR("Failed to read pagerange memory contents");
            mapper->unmap(mapper, mem, size);
            goto out;
        }
        mapper->unmap(mapper, mem, size);
    }

    ret = 0;

out:
    return ret;
}

static int
image_write(
    struct attoimg_builder *builder,
    struct attovm_definition_v1 *def,
    const char *filename)
{
    struct attoimg_image_hdr hdr = { 0 };
    int ret = -1;
    FILE *f;

    hdr.magic = ATTOVM_IMAGE_MAGIC;
    hdr.version = ATTOVM_IMAGE_VERSION;
    hdr.definition = *def;

    f = fopen(filename, "wb");
    if (!f) {
        ERROR("Failed to open file %s for writing", filename);
        goto out;
    }

    /* write header */
    if (write_bytes(f, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        ERROR("Failed to write image file header");
        goto out;
    }

    /* write page data */
    ret = image_write_page_range_contents(f, builder, def);
    if (ret) {
        ERROR("Failed to write page range contents");
        goto out;
    }

    ret = 0;

out:
    if (f) {
        fclose(f);
    }

    return ret;
}

int attoimg_image_read(
    const char *filename,
    struct attovm_definition_v1 *definition,
    struct attoimg_guest_mapper *mapper)
{
    struct attoimg_image_hdr hdr = { 0 };

    FILE *f = NULL;
    int ret = -1;

    f = fopen(filename, "rb");
    if (!f) {
        ERROR("Failed to open image file '%s'", filename);
        goto out;
    }

    /* load header */
    if (read_bytes(f, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        ERROR("Failed to read image file header");
        goto out;
    }

    if (hdr.magic != ATTOVM_IMAGE_MAGIC) {
        ERROR("Unexpected image file format");
        goto out;
    }

    if (hdr.version != ATTOVM_IMAGE_VERSION) {
        ERROR("Image file version mismatch, expected %d, have %d", ATTOVM_IMAGE_VERSION, hdr.version);
        goto out;
    }

    if (mapper) {
        ret = image_read_page_range_contents(f, mapper, &hdr.definition);
        if (ret) {
            ERROR("Failed to read page range contents");
            goto out;
        }
    }

    /* return definition */
    memcpy(definition, &hdr.definition, sizeof(*definition));

    ret = 0;
out:
    if (f)
        fclose(f);
    return ret;
}

static int
image_measure(
    struct attoimg_builder *builder,
    struct attovm_definition_v1 *definition
)
{
    struct attoimg_guest_mapper *mapper = builder->mapper;
    uint32_t i, j;
    SHA256_CTX sha;

    sha256_init(&sha);

    /* hash header contents which need to be measured */
    sha256_update(&sha, (uint8_t*) &definition->m, sizeof(definition->m));

    /* hash page ranges */
    for (i = 0; i < definition->m.num_pageranges; i++) {
        struct attovm_pagerange *range = &definition->m.pagerange[i];
        uint8_t *memory = mapper->map(mapper,
            range->pfn   << PAGE_SHIFT,
            range->count << PAGE_SHIFT);
        for (j = 0; j < range->count; j++) {
            sha256_update(&sha, memory, PAGE_SIZE);
            memory += PAGE_SIZE;
        }
        mapper->unmap(mapper, memory, range->count << PAGE_SHIFT);
    }

    sha256_final(&sha, definition->hash);
    definition->hash_type = ATTOVM_HASHTYPE_SHA256;

    return 0;
}

static int
image_sign(
    struct attoimg_image_sign_data *sign_data,
    struct attovm_definition_v1 *def)
{
    uint64_t *sig, *hash;

    /* FIXME: real sign algorithm */
    if (!sign_data) {
        /* no signature, vm is in debug mode */
        def->debug = 1;
        printf("NO KEY PROVIDED, NOT SIGNING, VM IN DEBUG MODE\n");
        return 0;
    } else
        def->debug = 0;

    sig = (uint64_t*)def->hashsig;
    hash = (uint64_t*)def->hash;
    *sig = *hash + 1;

    return 0;
}

static int
image_measure_and_sign(
    struct attoimg_builder *builder,
    struct attoimg_image_sign_data *sign,
    struct attovm_definition_v1 *def
)
{
    int ret = image_measure(builder, def);
    if (ret)
        return ret;
    return image_sign(sign, def);
}

int attoimg_image_create(
    struct attovm_definition_v1 *def,
    struct attoimg_guest_mapper *mapper,
    const char *filename)
{
    struct attoimg_builder _builder = { };
    struct attoimg_builder *builder = &_builder;
    int ret;

    builder->mapper = mapper;

    ret = image_measure_and_sign(builder, NULL, def);
    if (ret) {
        ERROR("Failed to measure/sign image");
        goto out;
    }

    ret = image_write(builder, def, filename);
    if (ret) {
        ERROR("Failed to write out image file");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int attoimg_image_create_from_kernel_image(
  struct attoimg_image_sign_data *sign,
  struct attoimg_initial_image_info *info,
  const char *filename
)
{
    uint64_t memsize_mb = info->memsize_mb;
    uint32_t nr_vcpus = info->nr_vcpus;
    struct attoimg_builder _builder = { };
    struct attoimg_builder *builder = &_builder;
    struct attovm_definition_v1 definition = { 0 };
    struct attoimg_guest_mapper *mapper = NULL;
    uint64_t pages = ((uint64_t)memsize_mb * 1024 * 1024) >> PAGE_SHIFT;
    int ret = -1;

    mapper = attoimg_create_simple_mapper();
    if (!mapper) {
        ERROR("Failed to create guest mapper");
        goto out;
    }
    builder->mapper = mapper;

    definition.m.num_vcpus = nr_vcpus;
    definition.m.num_pages = pages;
    definition.m.has_vcpu_context = 0;

    ret = load_kernel_structures(builder, info, &definition);
    if (ret) {
        ERROR("Failed to load kernel structures");
        goto out;
    }

    ret = image_measure_and_sign(builder, sign, &definition);
    if (ret) {
        ERROR("Failed to measure/sign image");
        goto out;
    }

    ret = image_write(builder, &definition, filename);
    if (ret) {
        ERROR("Failed to write out image file");
        goto out;
    }

    ret = 0;

out:
    if (mapper)
        attoimg_free_simple_mapper(mapper);

    return ret;
}

int attoimg_image_sign_existing(
  struct attoimg_image_sign_data *sign,
  const char *input_file,
  const char *output_file
)
{
    struct attoimg_builder _builder = { };
    struct attoimg_builder *builder = &_builder;
    struct attovm_definition_v1 definition = { 0 };
    struct attoimg_guest_mapper *mapper = NULL;
    int ret = -1;

    mapper = attoimg_create_simple_mapper();
    if (!mapper) {
        ERROR("Failed to create guest mapper");
        goto out;
    }
    builder->mapper = mapper;

    if (!sign) {
        ERROR("Missing signing data");
        goto out;
    }

    if (attoimg_image_read(input_file, &definition, mapper)) {
        ERROR("Failed to load image file '%s'", input_file);
        goto out;
    }

    ret = image_measure_and_sign(builder, sign, &definition);
    if (ret) {
        ERROR("Failed to measure/sign image");
        goto out;
    }

    ret = image_write(builder, &definition, output_file);
    if (ret) {
        ERROR("Failed to write out image file");
        goto out;
    }

    ret = 0;

out:
    if (mapper)
        attoimg_free_simple_mapper(mapper);

    return ret;
}
