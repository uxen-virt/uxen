/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "xc_private.h"

#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xc_attovm.h"

#include <attoimg.h>
#include <attoxen-api/ax_attovm.h>
#include <xen/attovm.h>

#define PAGE_ALIGNED(x) (!((x) & (PAGE_SIZE-1)))
#define PAGE_ALIGN(x) (((x) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))
#define ATTOVM_ERROR ERROR

#define VGA_HOLE_PFN_START 0xa0
#define VGA_HOLE_PFN_END   0xbf

struct xc_mapper_data {
    xc_interface *xch;
    uint32_t domid;
    xen_pfn_t *pfns;
};

static xc_interface *log_xch;

static void
log_attoimg_error(const char *msg)
{
    if (log_xch)
        xc_report(log_xch, log_xch->error_handler, XTL_ERROR, XC_INTERNAL_ERROR,
            "%s", msg);
    else {
        printf("ERROR: ");
        printf("%s", msg);
        printf("\n");
    }
}

static void *
xc_attovm_map(struct attoimg_guest_mapper *m, uint64_t addr, uint64_t size)
{
    struct xc_mapper_data *opaque = m->opaque;
    uint64_t pfn_start, pfn_end;
    size_t pages;
    privcmd_mmap_entry_t *entries;
    int i;
    void *mapped = NULL;

    if (addr & (PAGE_SIZE-1))
        return NULL;

    pfn_start = addr >> PAGE_SHIFT;
    pfn_end   = (addr + size - 1) >> PAGE_SHIFT;

    pages = pfn_end - pfn_start + 1;
    entries = calloc(pages, sizeof(privcmd_mmap_entry_t));
    if (!entries)
        goto out;

    for (i = 0; i < pages; i++)
        entries[i].mfn = opaque->pfns[(addr >> PAGE_SHIFT) + i];

    mapped = xc_map_foreign_ranges(opaque->xch, opaque->domid,
                                   pages << PAGE_SHIFT, PROT_READ | PROT_WRITE,
                                   1 << PAGE_SHIFT, entries, pages);
out:
    free(entries);

    return mapped;
}

static void
xc_attovm_unmap(struct attoimg_guest_mapper *axm, void *ptr, uint64_t size)
{
    struct xc_mapper_data *opaque = axm->opaque;
    size_t pages = size >> PAGE_SHIFT;

    xc_munmap(opaque->xch, opaque->domid, ptr, pages << PAGE_SHIFT);
}

static struct attoimg_guest_mapper *
create_attovm_mapper(xc_interface *xch, uint32_t domid, xen_pfn_t *pfns)
{
    struct attoimg_guest_mapper *axm;
    struct xc_mapper_data *data;

    axm = malloc(sizeof(struct attoimg_guest_mapper));
    if (!axm)
        return NULL;
    memset(axm, 0, sizeof(*axm));

    data = malloc(sizeof(struct xc_mapper_data));
    if (!data) {
        free(axm);
        return NULL;
    }

    data->xch = xch;
    data->domid = domid;
    data->pfns = pfns;

    axm->opaque = data;
    axm->map = xc_attovm_map;
    axm->unmap = xc_attovm_unmap;

    return axm;
}

static void
free_attovm_mapper(struct attoimg_guest_mapper *axm)
{
    if (axm) {
        free(axm->opaque);
        free(axm);
    }
}

static int
do_attovm_op(xc_interface *xch, int op, void *buffer, size_t buffer_size)
{
    int ret = -1;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(buffer, buffer_size, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, buffer) ) {
        PERROR("Could not bounce buffer for domctl hypercall");
        goto out;
    }

    hypercall.op     = __HYPERVISOR_attovm_op;
    hypercall.arg[0] = op;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(buffer);

    ret = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_bounce_post(xch, buffer);

out:
    return ret;
}

int
attovm_seal_guest(xc_interface *xch, uint32_t domid, struct attovm_definition_v1 *definition)
{
    struct attovm_op_seal op;

    op.domain_id = domid;
    memcpy(&op.definition, definition, sizeof(op.definition));

    return do_attovm_op(xch, ATTOVMOP_seal, &op, sizeof(op));
}

int
xc_attovm_get_guest_pages(xc_interface *xch, uint32_t domid, uint64_t pfn, uint64_t count,
    void *buffer)
{
    struct attovm_op_get_guest_pages op;
    uint64_t buffer_size = count * PAGE_SIZE;
    DECLARE_HYPERCALL_BOUNCE(buffer, buffer_size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret = -1;

    if (xc_hypercall_bounce_pre(xch, buffer)) {
        PERROR("Could not bounce buffer for attovm_get_guest_pages hypercall");
        goto out;
    }

    op.domain_id = domid;
    op.pfn = pfn;
    op.count = count;
    set_xen_guest_handle(op.buffer, buffer);

    ret = do_attovm_op(xch, ATTOVMOP_get_guest_pages, &op, sizeof(op));

    xc_hypercall_bounce_post(xch, buffer);

out:
    return ret;
}

int
xc_attovm_get_guest_cpu_state(xc_interface *xch, uint32_t domid, uint32_t vcpu, void *buffer,
    uint32_t buffer_size)
{
    struct attovm_op_get_guest_cpu_state op;
    DECLARE_HYPERCALL_BOUNCE(buffer, buffer_size, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret = -1;

    if (xc_hypercall_bounce_pre(xch, buffer)) {
        PERROR("Could not bounce buffer for attovm_get_guest_pages hypercall");
        goto out;
    }

    op.domain_id = domid;
    op.vcpu_id = vcpu;
    op.buffer_size = buffer_size;
    set_xen_guest_handle(op.buffer, buffer);

    ret = do_attovm_op(xch, ATTOVMOP_get_guest_cpu_state, &op, sizeof(op));

    xc_hypercall_bounce_post(xch, buffer);

out:
    return ret;
}

int xc_attovm_change_focus(xc_interface *xch, uint32_t domid, uint32_t offer_focus)
{
    struct attovm_op_kbd_focus op;

    op.domain_id = domid;
    op.offer_focus = offer_focus;


    return do_attovm_op(xch, ATTOVMOP_kbd_focus, &op, sizeof(op));
}


static int
is_zeropage(uint8_t *b)
{
    int i;
    for (i = 0; i < PAGE_SIZE; i++)
        if (b[i])
            return 0;
    return 1;
}

static int
is_hole(uint64_t pfn)
{
    return pfn >= VGA_HOLE_PFN_START && pfn <= VGA_HOLE_PFN_END;
}

static int
add_page_range(struct attovm_definition_v1 *def,
    uint64_t pfn, uint32_t count)
{
    if (def->m.num_pageranges >= ATTOVM_MAX_PAGERANGES)
        return -1;
    def->m.pagerange[def->m.num_pageranges].pfn   = pfn;
    def->m.pagerange[def->m.num_pageranges].count = count;
    def->m.num_pageranges++;

    return 0;
}

/* scan memory 'img' for non-zero page regions and copy them into mapper */
static int
scan_memory_regions(uint8_t *img, uint64_t pages,
    struct attoimg_guest_mapper *mapper,
    struct attovm_definition_v1 *definition)
{
    const int MAX_CONT_ZERO = 128;
    uint64_t i;
    uint64_t region_begin = 0;
    uint64_t region_end = 0;
    int in_region = 1;
    int total_pages = 0;
    int cont_zero_pages = 0;
    int region = 0;
    int ret = -1;

    for (i = 0; i < pages; i++) {
        uint8_t *page = img + PAGE_SIZE*i;
        int zero = is_hole(i) || is_zeropage(page);

        if (in_region) {
            if (zero)
                cont_zero_pages++;
            else {
                region_end = i;
                cont_zero_pages = 0;
            }

            if (cont_zero_pages >= MAX_CONT_ZERO || is_hole(i) || i == pages-1) {
                uint8_t *bytes;
                int regpages = region_end - region_begin + 1;
                printf("region %d: 0x%016"PRIx64" - 0x%016"PRIx64"\n", region, region_begin << PAGE_SHIFT, (region_end+1) << PAGE_SHIFT);
                in_region = 0;
                cont_zero_pages = 0;
                total_pages += regpages;

                bytes = mapper->map(mapper, region_begin << PAGE_SHIFT, regpages << PAGE_SHIFT);
                if (!bytes)
                    goto out;
                memcpy(bytes, img + (region_begin << PAGE_SHIFT), regpages << PAGE_SHIFT);
                mapper->unmap(mapper, bytes, regpages << PAGE_SHIFT);
                ret = add_page_range(definition, region_begin, region_end - region_begin + 1);
                if (ret)
                    goto out;
                region++;
            }
        } else {
            if (!zero) {
                cont_zero_pages = 0;
                in_region = 1;
                region_begin = i;
            }
        }
    }

    ret = 0;
    printf("total image size: %d pages (%dMB)\n", (int)total_pages, (int)(total_pages * 4096 / 1024 / 1024));

out:
    return ret;
}

int
xc_attovm_image_create_from_live_vm(xc_interface *xch,
    uint32_t domid,
    uint32_t nr_vcpus,
    uint32_t memsize_mb,
    const char *filename)
{
    struct attovm_definition_v1 definition = { 0 };
    struct attoimg_guest_mapper *mapper = NULL;
    uint64_t pages = ((uint64_t)memsize_mb * 1024 * 1024) >> PAGE_SHIFT;
    uint8_t *mem = NULL;
    uint64_t i;
    int ret = -1;

    log_xch = xch;
    attoimg_set_error_log_fun(log_attoimg_error);

    mapper = attoimg_create_simple_mapper();
    if (!mapper) {
        ATTOVM_ERROR("Failed to create guest mapper");
        goto out;
    }

    definition.m.num_vcpus = nr_vcpus;
    definition.m.num_pages = pages;
    definition.m.has_vcpu_context = 1;

    /* snapshot vm memory */
    mem = calloc(PAGE_SIZE, pages);
    if (!mem)
        goto out;
    for (i = 0; i < pages; i++) {
        uint8_t *page = mem + i * PAGE_SIZE;
        if (is_hole(i)) {
            memset(page, 0, PAGE_SIZE);
        } else {
            int ret = xc_attovm_get_guest_pages(xch, domid, i, 1, page);
            if (ret) {
                ERROR("Failed to access guest page %"PRIx64", err=%d", i, ret);
                goto out;
            }
        }
    }

    /* snapshot vcpu state */
    for (i = 0; i < nr_vcpus; i++) {
        struct attovm_cpu_context_v1 ctx = { 0 };

        int ret = xc_attovm_get_guest_cpu_state(xch, domid, i, &ctx, sizeof(ctx));
        if (ret) {
            ATTOVM_ERROR("Failed to access vcpu%d state", i);
            goto out;
        }
        definition.m.vcpu[i] = ctx;
    }

    /* scan memory & create memory region structures */
    ret = scan_memory_regions(mem, pages, mapper, &definition);
    if (ret) {
        ATTOVM_ERROR("Failed to scan memory regions");
        goto out;
    }

    ret = attoimg_image_create(&definition, mapper, filename);
    if (ret) {
        ATTOVM_ERROR("Failed to measure/sign image");
        goto out;
    }

    ret = 0;

out:
    if (mapper)
        attoimg_free_simple_mapper(mapper);

    return ret;
}

/* we place appdef in highmem memory, which is not signed */
int
attovm_put_appdef(
    xc_interface *xch,
    uint32_t domid,
    struct attovm_definition_v1 *definition,
    const char *appdef,
    uint32_t appdef_len)
{
    uint32_t alloc_len, npages;
    xen_pfn_t *pfns = NULL;
    privcmd_mmap_entry_t *mmap_entries = NULL;
    void *mapped = NULL;
    int ret = 0, i;

    alloc_len = PAGE_ALIGN(appdef_len + 8);
    npages = alloc_len >> PAGE_SHIFT;

    if (npages > ATTOVM_MAX_HIGHMEM_PAGES) {
        ATTOVM_ERROR("attovm appdef is too long: %d bytes", appdef_len);
        ret = -ENOMEM;
        goto out;
    }

    pfns = calloc(npages, sizeof(xen_pfn_t));
    if (!pfns) {
        ret = -ENOMEM;
        goto out;
    }

    for (i = 0; i < npages; i++)
        pfns[i] = (0x100000000ULL >> PAGE_SHIFT) + i;
    /* actual allocate of highmem pages */
    ret = xc_domain_populate_physmap_exact(xch,
        domid, npages, 0, 0, &pfns[0]);
    if (ret)
        goto out;

    /* map highmem pages */
    mmap_entries = calloc(npages, sizeof(privcmd_mmap_entry_t));
    if (!mmap_entries) {
        ret = -ENOMEM;
        goto out;
    }

    for (i = 0; i < npages; i++)
        mmap_entries[i].mfn = pfns[i];

    mapped = xc_map_foreign_ranges(xch,
        domid, npages << PAGE_SHIFT, PROT_READ | PROT_WRITE,
        1 << PAGE_SHIFT, mmap_entries, npages);

    if (!mapped) {
        ret = -EINVAL;
        goto out;
    }

    memset(mapped, 0, npages << PAGE_SHIFT);
    *(uint64_t*)mapped = appdef_len;
    if (appdef)
        memcpy(mapped + 8, appdef, appdef_len);

    definition->num_highmem_pages = npages;

out:
    if (mapped)
        xc_munmap(xch, domid, mapped, npages << PAGE_SHIFT);
    free(pfns);
    free(mmap_entries);

    return ret;
}

int
attovm_setup_guest(
    xc_interface *xch, uint32_t domid, xen_pfn_t *pfns,
    const char *image_file,
    struct attovm_definition_v1 *out_definition)
{
    struct attoimg_guest_mapper *mapper = NULL;
    int ret = -1;

    log_xch = xch;
    attoimg_set_error_log_fun(log_attoimg_error);

    mapper = create_attovm_mapper(xch, domid, pfns);
    if (!mapper) {
        ATTOVM_ERROR("Failed to create guest mapper");
        goto out;
    }

    if (attoimg_image_read(image_file, out_definition, mapper)) {
        ATTOVM_ERROR("Failed to load image file '%s'", image_file);
        goto out;
    }

    ret = 0;
out:
    free_attovm_mapper(mapper);

    return ret;
}

