/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/cpu.h>
#include <attoimg/attoimg.h>
#include <attoxen-api/ax_attovm.h>
#include <dm/whpx/whpx.h>
#include <dm/whpx/util.h>

#define PAGE_ALIGN(x) (((x) + PAGE_SIZE-1) & ~(PAGE_SIZE-1))

// FIXME: free?
static void *appdef_mem;
static uint32_t appdef_size;
static uint32_t tsc_khz;

static void*
atto_whpx_map(struct attoimg_guest_mapper *m, uint64_t addr, uint64_t size)
{
    return whpx_ram_map_assert(addr, size);
}

static void
atto_whpx_unmap(struct attoimg_guest_mapper *m, void *ptr, uint64_t size)
{
    whpx_ram_unmap(ptr);
}

static struct attoimg_guest_mapper *
create_mapper(void)
{
    struct attoimg_guest_mapper *m = calloc(1, sizeof(struct attoimg_guest_mapper));
    m->map = atto_whpx_map;
    m->unmap = atto_whpx_unmap;

    return m;
}

static void
put_appdef(
    struct attovm_definition_v1 *def,
    const char *appdef, uint32_t appdef_len)
{
    uint32_t alloc_len = PAGE_ALIGN(appdef_len);
    uint32_t npages = alloc_len >> PAGE_SHIFT;

    if (!appdef || !appdef_len)
        return;

    if (npages > ATTOVM_UNSIGNED_MEM_MAX_PAGES)
        whpx_panic("attovm appdef is too long: %d bytes", appdef_len);
    appdef_mem = VirtualAlloc(NULL, alloc_len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert(appdef_mem);
    memset(appdef_mem, 0, alloc_len);
    memcpy(appdef_mem, appdef, appdef_len);
    whpx_ram_populate_with(ATTOVM_APPDEF_PHYSADDR, alloc_len, appdef_mem, WHPX_RAM_NO_DECOMMIT);
    def->appdef_size = appdef_len;
}

int
whpx_attovm_do_cpuid(
    CPUState *cpu, uint64_t leaf,
    uint64_t *eax, uint64_t *ebx, uint64_t *ecx, uint64_t *edx)
{
    if (!vm_attovm_mode)
        return 0;

    switch (leaf) {
    case ATTOCALL_QUERYOP:
        switch (*ecx) {
        case ATTOCALL_QUERYOP_FEATURES:
            *eax = 0;
            return 1;
        case ATTOCALL_QUERYOP_TSC_KHZ:
            *eax = tsc_khz;
            return 1;
        case ATTOCALL_QUERYOP_SECRET_KEY: {
            // TODO: derive key from hardware config, json & memory measurement etc
            // guest phys in rdx, salt in r8
            uint64_t addr = *edx;
            uint8_t key[ATTOVM_SECRET_KEY_BYTES];

            *eax = -1;
            memset(key, 0x77, ATTOVM_SECRET_KEY_BYTES);
            whpx_copy_to_guest_va(cpu, addr, key, ATTOVM_SECRET_KEY_BYTES);
            *eax = 0;
            return 1;
        }
        case ATTOCALL_QUERYOP_APPDEF_SIZE:
            *eax = appdef_size;
            return 1;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return 0;
}

void whpx_setup_atto(const char *image_file, const char *appdef, uint32_t appdef_len)
{
    struct attovm_definition_v1 def;
    struct attoimg_guest_mapper *mapper = create_mapper();

    if (attoimg_image_read(image_file, &def, mapper))
        whpx_panic("failed to read atto image file: %s\n", image_file);

    put_appdef(&def, appdef, appdef_len);

    free(mapper);

    tsc_khz = get_registry_cpu_mhz() * 1000;
    appdef_size = appdef_len;
}

  
