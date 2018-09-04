/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

/* 
 *  vm-save.c
 *  uxen dm
 *
 *  COPYRIGHT
 *
 */


#include "config.h"

#include <err.h>
#include <inttypes.h>
#include <stdint.h>

#include <uuid/uuid.h>

#include "async-op.h"
#include "bitops.h"
#include "control.h"
#include "dm.h"
#include "dmpdev.h"
#include "dmreq.h"
#include "filebuf.h"
#include "introspection_info.h"
#include "monitor.h"
#include "qemu_savevm.h"
#include "timer.h"
#include "vm.h"
#include "vm-save.h"
#include "vm-savefile.h"
#include "uxen.h"
#include "hw/uxen_platform.h"
#include "mapcache.h"

#ifdef SAVE_CUCKOO_ENABLED
#include "cuckoo.h"
#include "cuckoo-uxen.h"
#endif

#include <lz4.h>
#include <lz4hc.h>

#include <fingerprint.h>

#include <xenctrl.h>
#include <xc_private.h>

#include <xen/hvm/e820.h>

#include <dm/whpx/whpx.h>

#define DECOMPRESS_THREADED
#define DECOMPRESS_THREADS 2

#ifdef DEBUG
#define VERBOSE 1
#endif
// #define VERBOSE_SAVE 1
// #define VERBOSE_LOAD 1

#undef DPRINTF
#ifdef VERBOSE
#define DPRINTF(fmt, ...) debug_printf(fmt "\n", ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do { ; } while(0)
#endif
#ifdef VERBOSE_SAVE
#define SAVE_DPRINTF(fmt, ...) debug_printf(fmt "\n", ## __VA_ARGS__)
#else
#define SAVE_DPRINTF(fmt, ...) do { ; } while(0)
#endif
#ifdef VERBOSE_LOAD
#define LOAD_DPRINTF(fmt, ...) debug_printf(fmt "\n", ## __VA_ARGS__)
#else
#define LOAD_DPRINTF(fmt, ...) do { ; } while(0)
#endif
#undef APRINTF
#define APRINTF(fmt, ...) debug_printf(fmt "\n", ## __VA_ARGS__)
#undef EPRINTF
#define EPRINTF(fmt, ...) error_printf("%s: " fmt "\n", __FUNCTION__, \
                                       ## __VA_ARGS__)


struct vm_save_info vm_save_info = { };

static int
uxenvm_savevm_initiate(char **err_msg)
{
    int ret;

    if (!whpx_enable)
        ret = xc_domain_shutdown(xc_handle, vm_id, SHUTDOWN_suspend);
    else
        ret = whpx_vm_shutdown(SHUTDOWN_suspend);
    if (ret)
	asprintf(err_msg, "domain shutdown(SHUTDOWN_suspend) failed: %d",
		 ret);

    return ret;
}

typedef uint16_t cs16_t;

#define PP_BUFFER_PAGES                                                 \
    (int)((MAX_BATCH_SIZE * (sizeof(cs16_t) + PAGE_SIZE) + PAGE_SIZE - 1) \
          >> PAGE_SHIFT)

#define PCI_HOLE_START_PFN (PCI_HOLE_START >> UXEN_PAGE_SHIFT)
#define PCI_HOLE_END_PFN (PCI_HOLE_END >> UXEN_PAGE_SHIFT)
#define skip_pci_hole(pfn) ((pfn) < PCI_HOLE_END_PFN ?                  \
                            (pfn) :                                     \
                            (pfn) - (PCI_HOLE_END_PFN - PCI_HOLE_START_PFN))
#define poi_valid_pfn(poi, pfn) ((pfn) < (poi)->max_gpfn &&      \
                                 ((pfn) < PCI_HOLE_START_PFN ||  \
                                  (pfn) >= PCI_HOLE_END_PFN))
#define poi_pfn_index(poi, pfn) skip_pci_hole(pfn)

struct page_offset_info {
    uint32_t max_gpfn;
    uint64_t *pfn_off;
    struct filebuf *fb;
};
#define PAGE_OFFSET_INDEX_PFN_OFF_COMPRESSED (1ULL << 63)
#define PAGE_OFFSET_INDEX_PFN_OFF_MASK (~(PAGE_OFFSET_INDEX_PFN_OFF_COMPRESSED))

static struct page_offset_info dm_lazy_load_info = { };

#define uxenvm_read_struct_size(s) (sizeof(*(s)) - sizeof(marker))
#define uxenvm_read_struct(f, s)                                        \
    filebuf_read(f, (uint8_t *)(s) + sizeof(marker),                    \
                 uxenvm_read_struct_size(s))

static int
vm_get_context(void *buffer, size_t buffer_sz)
{
    return !whpx_enable
        ? xc_domain_hvm_getcontext(xc_handle, vm_id, buffer, buffer_sz)
        : whpx_vm_get_context(buffer, buffer_sz);
        
}

static int
vm_set_context(void *buffer, size_t buffer_sz)
{
    return !whpx_enable
        ? xc_domain_hvm_setcontext(xc_handle, vm_id, buffer, buffer_sz)
        : whpx_vm_set_context(buffer, buffer_sz);
}

static int
uxenvm_savevm_get_dm_state(uint8_t **dm_state_buf, int *dm_state_size,
                           char **err_msg)
{
    QEMUFile *mf;
    int ret = 0;

    mf = qemu_memopen(NULL, 0, "wb");
    if (mf == NULL) {
        asprintf(err_msg, "qemu_memopen() failed");
        ret = EPERM;
        goto out;
    }

    ret = qemu_savevm_state(NULL, mf);
    if (ret < 0) {
        asprintf(err_msg, "qemu_savevm_state() failed");
        ret = EPERM;
        goto out;
    }

    *dm_state_buf = qemu_meminfo(mf, dm_state_size);
    if (*dm_state_buf == NULL) {
        asprintf(err_msg, "qemu_meminfo() failed");
        ret = EPERM;
        goto out;
    }
  out:
    if (mf)
        qemu_fclose(mf);
    return ret;
}

static int
uxenvm_savevm_write_info(struct filebuf *f, uint8_t *dm_state_buf,
                         int dm_state_size, char **err_msg)
{
    int32_t hvm_buf_size;
    uint8_t *hvm_buf = NULL;
    xc_dominfo_t dom_info[1];
    xc_vcpuinfo_t vcpu_info;
    struct xc_save_version_info s_version_info;
    struct xc_save_clock_info s_clock_info;
    struct xc_save_tsc_info s_tsc_info;
    struct xc_save_vcpu_info s_vcpu_info;
    struct xc_save_hvm_params s_hvm_params;
    int nr_hvm_params = 0;
    struct {
        uint16_t idx;
        char *name;
    } saved_hvm_params[] = {
        { HVM_PARAM_IDENT_PT, "ident_pt" },
        { HVM_PARAM_VM86_TSS, "vm86_tss" },
        { HVM_PARAM_ACPI_IOPORTS_LOCATION, "acpi_ioports_location" },
        { HVM_PARAM_IO_PFN_FIRST, "io pfn first" },
        { HVM_PARAM_IO_PFN_LAST, "io pfn last" },
        { HVM_PARAM_SHARED_INFO_PFN, "shared info pfn" },
        { HVM_PARAM_DMREQ_VCPU_PFN, "dmreq vcpu pfn" }, /* dmreq vcpu first */
        { HVM_PARAM_DMREQ_PFN, "dmreq pfn" },
        { HVM_PARAM_RESTRICTED_HYPERCALLS, "restricted_hypercalls" }
    };
    struct xc_save_hvm_context s_hvm_context;
    struct xc_save_hvm_dm s_hvm_dm;
    struct xc_save_vm_uuid s_vm_uuid;
    struct xc_save_vm_template_uuid s_vm_template_uuid;
    struct xc_save_mapcache_params s_mapcache_params;
    struct xc_save_vm_template_file s_vm_template_file;
    int j;
    int ret = 0;

    s_version_info.marker = XC_SAVE_ID_VERSION;
    s_version_info.version = SAVE_FORMAT_VERSION;
    filebuf_write(f, &s_version_info, sizeof(s_version_info));

    s_clock_info.marker = XC_SAVE_ID_CLOCK_INFO;
    s_clock_info.adjust_offset = get_clock_ns(vm_clock);
    filebuf_write(f, &s_clock_info, sizeof(s_clock_info));

    if (!whpx_enable) {
        /* uxen specific */

        s_tsc_info.marker = XC_SAVE_ID_TSC_INFO;
        ret = xc_domain_get_tsc_info(xc_handle, vm_id, &s_tsc_info.tsc_mode,
                                     &s_tsc_info.nsec, &s_tsc_info.khz,
                                     &s_tsc_info.incarn);
        if (ret < 0) {
            asprintf(err_msg, "xc_domain_get_tsc_info() failed");
            ret = -EPERM;
            goto out;
        }
        APRINTF("tsc info: mode %d nsec %"PRIu64" khz %d incarn %d",
	    s_tsc_info.tsc_mode, s_tsc_info.nsec, s_tsc_info.khz,
	    s_tsc_info.incarn);
        filebuf_write(f, &s_tsc_info, sizeof(s_tsc_info));

        ret = xc_domain_getinfo(xc_handle, vm_id, 1, dom_info);
        if (ret != 1 || dom_info[0].domid != vm_id) {
            asprintf(err_msg, "xc_domain_getinfo(%d) failed", vm_id);
            ret = -EPERM;
            goto out;
        }
        s_vcpu_info.marker = XC_SAVE_ID_VCPU_INFO;
        s_vcpu_info.max_vcpu_id = dom_info[0].max_vcpu_id;
        s_vcpu_info.vcpumap = 0ULL;
        for (j = 0; j <= s_vcpu_info.max_vcpu_id; j++) {
            ret = xc_vcpu_getinfo(xc_handle, vm_id, j, &vcpu_info);
            if (ret == 0 && vcpu_info.online)
                s_vcpu_info.vcpumap |= 1ULL << j;
        }
        APRINTF("vcpus %d online %"PRIx64, s_vcpu_info.max_vcpu_id,
	    s_vcpu_info.vcpumap);
        filebuf_write(f, &s_vcpu_info, sizeof(s_vcpu_info));

        for (nr_hvm_params = 0; nr_hvm_params < ARRAY_SIZE(saved_hvm_params);
             nr_hvm_params++) {
            s_hvm_params.params[nr_hvm_params].idx =
                saved_hvm_params[nr_hvm_params].idx;
            s_hvm_params.params[nr_hvm_params].data = 0;
            xc_get_hvm_param(xc_handle, vm_id,
                             s_hvm_params.params[nr_hvm_params].idx,
                             &s_hvm_params.params[nr_hvm_params].data);
            APRINTF("hvm param %s/%d %"PRIx64,
                saved_hvm_params[nr_hvm_params].name,
                s_hvm_params.params[nr_hvm_params].idx,
                s_hvm_params.params[nr_hvm_params].data);
        }

        if (nr_hvm_params) {
            s_hvm_params.marker = XC_SAVE_ID_HVM_PARAMS;
            s_hvm_params.size = nr_hvm_params * sizeof(s_hvm_params.params[0]);
            filebuf_write(f, &s_hvm_params,
                sizeof(struct xc_save_generic) + s_hvm_params.size);
        }
    }

    hvm_buf_size = vm_get_context(NULL, 0);
    if (hvm_buf_size == -1) {
	asprintf(err_msg, "vm_get_context(0, 0) failed");
	ret = -EPERM;
	goto out;
    }
    APRINTF("hvm_buf_size is %d", hvm_buf_size);

    hvm_buf = malloc(hvm_buf_size);
    if (hvm_buf == NULL) {
	asprintf(err_msg, "hvm_buf = malloc(%d) failed", hvm_buf_size);
	ret = -ENOMEM;
	goto out;
    }

    s_hvm_context.marker = XC_SAVE_ID_HVM_CONTEXT;
    s_hvm_context.size = vm_get_context(hvm_buf, hvm_buf_size);
    if (s_hvm_context.size == -1) {
	asprintf(err_msg, "vm_get_context(%d) failed", hvm_buf_size);
	ret = -EPERM;
	goto out;
    }
    APRINTF("hvm rec size %d", s_hvm_context.size);
    filebuf_write(f, &s_hvm_context, sizeof(s_hvm_context));
    filebuf_write(f, hvm_buf, s_hvm_context.size);

#if defined(_WIN32)
    /* "set_introspect_info" should be set for template only (last boot)*/
    if (!whpx_enable && strstr(lava_options, "set_introspect_info")) {
        struct guest_introspect_info_t *guest_introspect_info;
        guest_introspect_info = get_guest_introspect_info();
        if (guest_introspect_info) {
            struct xc_save_hvm_introspec s_hvm_introspec;
            int introspect_rect_size;
            s_hvm_introspec.marker = XC_SAVE_ID_HVM_INTROSPEC;
            s_hvm_introspec.info = guest_introspect_info->hdr;
            introspect_rect_size = s_hvm_introspec.info.n_immutable_ranges *
                sizeof(struct immutable_range);
            DPRINTF("introspect rec size %d", introspect_rect_size);
            filebuf_write(f, &s_hvm_introspec, sizeof(s_hvm_introspec));
            filebuf_write(f, guest_introspect_info->ranges,
                          introspect_rect_size);
        }
    }
#endif  /* _WIN32 */

    s_hvm_dm.marker = XC_SAVE_ID_HVM_DM;
    s_hvm_dm.size = dm_state_size;
    APRINTF("dm rec size %d", s_hvm_dm.size);
    filebuf_write(f, &s_hvm_dm, sizeof(s_hvm_dm));
    vm_save_info.dm_offset = filebuf_tell(f);
    filebuf_write(f, dm_state_buf, s_hvm_dm.size);

    s_vm_uuid.marker = XC_SAVE_ID_VM_UUID;
    memcpy(s_vm_uuid.uuid, vm_uuid, sizeof(s_vm_uuid.uuid));
    filebuf_write(f, &s_vm_uuid, sizeof(s_vm_uuid));

    if (vm_has_template_uuid) {
	s_vm_template_uuid.marker = XC_SAVE_ID_VM_TEMPLATE_UUID;
	memcpy(s_vm_template_uuid.uuid, vm_template_uuid,
	       sizeof(s_vm_template_uuid.uuid));
	filebuf_write(f, &s_vm_template_uuid, sizeof(s_vm_template_uuid));
    }

    s_mapcache_params.marker = XC_SAVE_ID_MAPCACHE_PARAMS;
    mapcache_get_params(&s_mapcache_params.end_low_pfn,
                        &s_mapcache_params.start_high_pfn,
                        &s_mapcache_params.end_high_pfn);
    filebuf_write(f, &s_mapcache_params, sizeof(s_mapcache_params));

    if (vm_template_file) {
        s_vm_template_file.marker = XC_SAVE_ID_VM_TEMPLATE_FILE;
        s_vm_template_file.size = strlen(vm_template_file);
        filebuf_write(f, &s_vm_template_file, sizeof(s_vm_template_file));
        filebuf_write(f, vm_template_file, s_vm_template_file.size);
    }

  out:
    return ret;
}

int
vm_save_read_dm_offset(void *dst, off_t offset, size_t size)
{
    int ret;
    off_t o;

    o = filebuf_tell(vm_save_info.f);
    offset += vm_save_info.dm_offset;
    filebuf_seek(vm_save_info.f, offset, FILEBUF_SEEK_SET);
    ret = filebuf_read(vm_save_info.f, dst, size);
    filebuf_seek(vm_save_info.f, o, FILEBUF_SEEK_SET);
    return ret;
}

static inline int
uxenvm_compress_lz4(const void *src, void *dst, int sz)
{
    if (vm_save_info.high_compress) {
        return LZ4_compressHC(src, dst, sz);
    } else {
        return LZ4_compress(src, dst, sz);
    }
}

static inline int
compression_is_cuckoo(void)
{
#ifdef SAVE_CUCKOO_ENABLED
    return (vm_save_info.compress_mode == VM_SAVE_COMPRESS_CUCKOO ||
            vm_save_info.compress_mode == VM_SAVE_COMPRESS_CUCKOO_SIMPLE);
#else
    return 0;
#endif
}

#ifdef SAVE_CUCKOO_ENABLED
static int
save_cuckoo_pages(struct filebuf *f, struct page_fingerprint *hashes,
                  int n, int simple_mode, char **err_msg);
#endif

static int
check_aborted(void)
{
    if (vm_save_info.safe_to_abort) {
        if (vm_quit_interrupt)
            return 1;
        if (vm_save_info.save_abort) {
            vm_set_run_mode(RUNNING_VM);
            return 1;
        }
    }
    return 0;
}

void
vm_save_set_abortable(void)
{
    if (cmpxchg(&vm_save_info.safe_to_abort, 0, 1) == 0)
        check_aborted();
}

void
vm_save_abort(void)
{
    vm_save_info.save_abort = 1;
    if (ioh_event_valid(&vm_save_info.save_abort_event))
        ioh_event_set(&vm_save_info.save_abort_event);
    check_aborted();
}

static int
uxenvm_savevm_write_pages(struct filebuf *f, char **err_msg)
{
    uint8_t *hvm_buf = NULL;
    int p2m_size, pfn, batch, _batch, run, b_run, m_run, v_run, rezero, clone;
    int _zero;
    unsigned long batch_done;
    int total_pages = 0, total_zero = 0, total_rezero = 0, total_clone = 0;
    int total_compressed_pages = 0, total_compress_in_vain = 0;
    size_t total_compress_save = 0;
    int j;
    int *pfn_batch = NULL;
    uint8_t *zero_bitmap = NULL, *zero_bitmap_compressed = NULL;
    uint32_t zero_bitmap_size;
    struct xc_save_zero_bitmap s_zero_bitmap;
    char *compress_mem = NULL;
    char *compress_buf = NULL;
    uint32_t compress_size = 0;
    DECLARE_HYPERCALL_BUFFER(uint8_t, mem_buffer);
#define MEM_BUFFER_SIZE (MAX_BATCH_SIZE * PAGE_SIZE)
    xen_memory_capture_gpfn_info_t *gpfn_info_list = NULL;
    uint64_t mem_pos = 0, pos;
    struct page_offset_info poi = { 0 };
    int rezero_nr = 0;
    xen_pfn_t *rezero_pfns = NULL;
    struct xc_save_vm_page_offsets s_vm_page_offsets;
#ifdef SAVE_CUCKOO_ENABLED
    struct xc_save_cuckoo_data xc_cuckoo;
#endif
    struct xc_save_index page_offsets_index = { 0, XC_SAVE_ID_PAGE_OFFSETS };
    struct page_fingerprint *hashes = NULL;
    int hashes_nr = 0;
    int trivial_nr = 0;
    struct xc_save_vm_fingerprints s_vm_fingerprints;
    struct xc_save_index fingerprints_index = { 0, XC_SAVE_ID_FINGERPRINTS };
    int free_mem;
    int ret;

    free_mem = (vm_save_info.free_mem && !compression_is_cuckoo());

    p2m_size = xc_domain_maximum_gpfn(xc_handle, vm_id);
    if (p2m_size < 0) {
	asprintf(err_msg, "xc_domain_maximum_gpfn() failed");
	ret = -EPERM;
	goto out;
    }
    p2m_size++;
    APRINTF("p2m_size: 0x%x", p2m_size);

    zero_bitmap_size = (p2m_size + 7) / 8;
    zero_bitmap = calloc(zero_bitmap_size, 1);
    if (zero_bitmap == NULL) {
        asprintf(err_msg, "zero_bitmap = calloc(%d) failed", zero_bitmap_size);
        ret = -ENOMEM;
        goto out;
    }

    gpfn_info_list = malloc(MAX_BATCH_SIZE * sizeof(*gpfn_info_list));
    if (gpfn_info_list == NULL) {
        asprintf(err_msg, "gpfn_info_list = malloc(%"PRIdSIZE") failed",
                 MAX_BATCH_SIZE * sizeof(*gpfn_info_list));
        ret = -ENOMEM;
        goto out;
    }

    mem_buffer = xc_hypercall_buffer_alloc_pages(
        xc_handle, mem_buffer, MEM_BUFFER_SIZE >> PAGE_SHIFT);
    if (!mem_buffer) {
        asprintf(err_msg, "mem_buffer = xc_hypercall_buffer_alloc_pages(%ld)"
                 " failed", MEM_BUFFER_SIZE >> PAGE_SHIFT);
        ret = -ENOMEM;
        goto out;
    }

    pfn_batch = malloc(MAX_BATCH_SIZE * sizeof(*pfn_batch));
    if (pfn_batch == NULL) {
        asprintf(err_msg, "pfn_batch = malloc(%"PRIdSIZE") failed",
                 MAX_BATCH_SIZE * sizeof(*pfn_batch));
	ret = -ENOMEM;
	goto out;
    }

    if (!free_mem) {
        rezero_pfns = malloc(MAX_BATCH_SIZE * sizeof(*rezero_pfns));
        if (rezero_pfns == NULL) {
            asprintf(err_msg, "rezero_pfns = malloc(%"PRIdSIZE") failed",
                     MAX_BATCH_SIZE * sizeof(*rezero_pfns));
            ret = -ENOMEM;
            goto out;
        }
    }

    if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_LZ4) {
        if (!vm_save_info.single_page) {
            /* The LZ4_compressBound macro is unsafe, so we have to wrap the
             * argument. */
            compress_buf =
                (char *)malloc(LZ4_compressBound(
                                   (MAX_BATCH_SIZE << PAGE_SHIFT)));
            if (!compress_buf) {
                asprintf(err_msg, "malloc(compress_buf) failed");
                ret = -ENOMEM;
                goto out;
            }
            compress_mem = (char *)malloc(MAX_BATCH_SIZE << PAGE_SHIFT);
            if (!compress_mem) {
                asprintf(err_msg, "malloc(compress_mem) failed");
                ret = -ENOMEM;
                goto out;
            }
        } else {
            compress_buf = (char *)malloc(
                sizeof(compress_size) +
                MAX_BATCH_SIZE * (sizeof(cs16_t) + PAGE_SIZE));
            if (!compress_buf) {
                asprintf(err_msg, "malloc(compress_buf) failed");
                ret = -ENOMEM;
                goto out;
            }
        }
    }

    poi.max_gpfn = vm_mem_mb << (20 - UXEN_PAGE_SHIFT);
    poi.pfn_off = calloc(1, poi.max_gpfn * sizeof(poi.pfn_off[0]));
    /* adjust max_gpfn to account for pci hole after allocating pfn_off */
    if (poi.max_gpfn > PCI_HOLE_START_PFN)
        poi.max_gpfn += PCI_HOLE_END_PFN - PCI_HOLE_START_PFN;

    /* store start of batch file offset, to allow restoring page data
     * without parsing the entire save file */
    vm_save_info.page_batch_offset = filebuf_tell(f);
    vm_save_set_abortable();

    pfn = 0;
    while (pfn < p2m_size && !check_aborted()) {
        batch = 0;
        while ((pfn + batch) < p2m_size && batch < MAX_BATCH_SIZE) {
            gpfn_info_list[batch].gpfn = pfn + batch;
            gpfn_info_list[batch].flags = XENMEM_MCGI_FLAGS_VM |
                (free_mem ? XENMEM_MCGI_FLAGS_REMOVE_PFN : 0);
            batch++;
        }
        ret = xc_domain_memory_capture(
            xc_handle, vm_id, batch, gpfn_info_list, &batch_done,
            HYPERCALL_BUFFER(mem_buffer), MEM_BUFFER_SIZE);
        if (ret || batch_done != batch) {
            EPRINTF("xc_domain_memory_capture fail/incomple: ret %d"
                    " errno %d done %ld/%d", ret, errno, batch_done, batch);
        }
        rezero = 0;
        clone = 0;
        _batch = 0;
        _zero = 0;
        for (j = 0; j < batch_done; j++) {
            gpfn_info_list[j].type &= XENMEM_MCGI_TYPE_MASK;
            if (gpfn_info_list[j].type == XENMEM_MCGI_TYPE_NORMAL) {
                uint32_t *p = (uint32_t *)&mem_buffer[gpfn_info_list[j].offset];
                int i = 0;
                while (i < (PAGE_SIZE / sizeof(*p)) && p[i] == p[0])
                    i++;
                if (i == (PAGE_SIZE / sizeof(*p))) {
                    if (p[0] == 0) {
                        gpfn_info_list[j].type = XENMEM_MCGI_TYPE_ZERO;
                        rezero++;
                        total_rezero++;
                        /* Always re-share zero pages. */
                        if (!free_mem)
                            rezero_pfns[rezero_nr++] = pfn + j;
                    } else {
                        ++trivial_nr;
                    }
                }
            }
            if (gpfn_info_list[j].type == XENMEM_MCGI_TYPE_NORMAL) {
                pfn_batch[_batch] = pfn + j;
                _batch++;
            }
            if (gpfn_info_list[j].type == XENMEM_MCGI_TYPE_ZERO) {
                __set_bit(pfn + j, zero_bitmap);
                _zero++;
                total_zero++;
            }
            if (gpfn_info_list[j].type == XENMEM_MCGI_TYPE_POD) {
                clone++;
                total_clone++;
            }
        }
        if (rezero_nr) {
            xc_domain_populate_physmap(xc_handle, vm_id, rezero_nr, 0,
                                       XENMEMF_populate_on_demand, rezero_pfns);
            rezero_nr = 0;
        }
        if (_batch) {
            if (vm_save_compress_mode_batched(vm_save_info.compress_mode)) {
                SAVE_DPRINTF("page batch %08x:%08x = %03x pages,"
                             " rezero %03x, clone %03x, zero %03x",
                             pfn, pfn + batch, _batch, rezero, clone, _zero);
                if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_LZ4)
                    _batch += vm_save_info.single_page ?
                        2 * MAX_BATCH_SIZE : MAX_BATCH_SIZE;
                filebuf_write(f, &_batch, sizeof(_batch));
                if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_LZ4)
                    _batch -= vm_save_info.single_page ?
                        2 * MAX_BATCH_SIZE : MAX_BATCH_SIZE;
                filebuf_write(f, pfn_batch, _batch * sizeof(pfn_batch[0]));
                if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_LZ4 &&
                    vm_save_info.single_page) {
                    compress_size = 0;
                    mem_pos = filebuf_tell(f) + sizeof(compress_size);
                }
            }
            j = 0;
            m_run = 0;
            v_run = 0;
            while (j != batch) {
                while (j != batch &&
                       gpfn_info_list[j].type != XENMEM_MCGI_TYPE_NORMAL)
                    j++;
                run = j;
                while (j != batch &&
                       gpfn_info_list[j].type == XENMEM_MCGI_TYPE_NORMAL)
                    j++;
                if (run != j) {
                    b_run = j - run;
                    SAVE_DPRINTF(
                        "     write %08x:%08x = %03x pages",
                        pfn + run, pfn + j, b_run);
                    if (vm_save_info.fingerprint) {
                        int i;
                        for (i = 0; i < b_run; i++) {
                            if (!((hashes_nr - 1) & hashes_nr)) {
                                hashes = realloc(
                                    hashes, sizeof(hashes[0]) *
                                    (hashes_nr ? 2 * hashes_nr : 1));
                                if (!hashes) {
                                    EPRINTF("%s: hashes realloc failed, "
                                            "disabling fingerprinting",
                                            __FUNCTION__);
                                    vm_save_info.fingerprint = 0;
                                    break;
                                }
                            }
                            hashes[hashes_nr].pfn = pfn + run + i;
                            hashes[hashes_nr].hash =
                                page_fingerprint(
                                    &mem_buffer[gpfn_info_list[run + i].offset],
                                    &hashes[hashes_nr].rotate);
                            hashes_nr++;
                        }
                    }
                    if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_NONE) {
                        int i;
                        pos = filebuf_tell(f);
                        for (i = 0; i < b_run; i++) {
                            if (!poi_valid_pfn(&poi, pfn + run + i))
                                continue;
                            poi.pfn_off[poi_pfn_index(&poi, pfn + run + i)] =
                                pos + (i << PAGE_SHIFT);
                        }
                        filebuf_write(
                            f, &mem_buffer[gpfn_info_list[run].offset],
                            b_run << PAGE_SHIFT);
                    } else if (vm_save_info.compress_mode ==
                               VM_SAVE_COMPRESS_LZ4) {
                        if (vm_save_info.single_page) {
                            int i, cs1;
                            for (i = 0; i < b_run; i++) {
                                cs1 = uxenvm_compress_lz4(
                                    (const char *)&mem_buffer[
                                        gpfn_info_list[run + i].offset],
                                    &compress_buf[compress_size +
                                                  sizeof(cs16_t)],
                                    PAGE_SIZE);
                                if (cs1 >= PAGE_SIZE) {
                                    memcpy(&compress_buf[compress_size +
                                                         sizeof(cs16_t)],
                                           &mem_buffer[
                                               gpfn_info_list[run + i].offset],
                                           PAGE_SIZE);
                                    cs1 = PAGE_SIZE;
                                    v_run++;
                                } else
                                    m_run++;
                                /* if the page is not compressed, then
                                 * record the offset of the page data,
                                 * otherwise record the offset of the
                                 * size field and set the
                                 * PAGE_OFFSET_INDEX_PFN_OFF_COMPRESSED
                                 * indicator */
                                if (poi_valid_pfn(&poi, pfn + run + i))
                                    poi.pfn_off[
                                        poi_pfn_index(&poi,
                                                      pfn + run + i)] =
                                        (mem_pos + compress_size) +
                                        (cs1 == PAGE_SIZE ? sizeof(cs16_t) :
                                         PAGE_OFFSET_INDEX_PFN_OFF_COMPRESSED);
                                *(cs16_t *)&compress_buf[compress_size] = cs1;
                                compress_size += sizeof(cs16_t) + cs1;
                            }
                        } else if (vm_save_info.compress_mode ==
                                   VM_SAVE_COMPRESS_LZ4) {
                            memcpy(&compress_mem[m_run << PAGE_SHIFT],
                                   &mem_buffer[gpfn_info_list[run].offset],
                                   b_run << PAGE_SHIFT);
                            m_run += b_run;
                        }
                    }
                    run += b_run;
                    _batch -= b_run;
                    total_pages += b_run;
                }
            }

            if (_batch)
                debug_printf("%d stray pages\n", _batch);
            if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_LZ4) {
                if (!vm_save_info.single_page) {
                    compress_size = uxenvm_compress_lz4(
                        compress_mem, compress_buf, m_run << PAGE_SHIFT);
                    if (compress_size >= m_run << PAGE_SHIFT) {
                        SAVE_DPRINTF("compressed size larger for pages "
                                     "%08x:%08x by %d", pfn, pfn + m_run,
                                     compress_size - (m_run << PAGE_SHIFT));
                        compress_size = -1;
                    }
                    filebuf_write(f, &compress_size, sizeof(compress_size));
                    if (compress_size != -1) {
                        filebuf_write(f, compress_buf, compress_size);
                        total_compressed_pages += m_run;
                        total_compress_save +=
                            (m_run << PAGE_SHIFT) - compress_size;
                    } else {
                        filebuf_write(f, compress_mem,
                                      m_run << PAGE_SHIFT);
                        total_compress_in_vain += m_run;
                    }
                } else {
                    filebuf_write(f, &compress_size, sizeof(compress_size));
                    filebuf_write(f, compress_buf, compress_size);
                    total_compressed_pages += m_run;
                    total_compress_save +=
                        ((m_run + v_run) << PAGE_SHIFT) - compress_size;
                    total_compress_in_vain += v_run;
                }
            }
	}
	pfn += batch;
    }

    if (!check_aborted()) {

#ifdef SAVE_CUCKOO_ENABLED
        if (mem_buffer) {
            xc_hypercall_buffer_free_pages(xc_handle, mem_buffer,
                                           MEM_BUFFER_SIZE >> PAGE_SHIFT);
            mem_buffer = NULL;
        }
        if (compression_is_cuckoo()) {
            xc_cuckoo.marker = XC_SAVE_ID_CUCKOO_DATA;
            xc_cuckoo.simple_mode = (vm_save_info.compress_mode ==
                                    VM_SAVE_COMPRESS_CUCKOO_SIMPLE);
            filebuf_write(f, &xc_cuckoo, sizeof(xc_cuckoo));
            ret = save_cuckoo_pages(f, hashes, hashes_nr,
                                    xc_cuckoo.simple_mode, err_msg);
            if (ret)
                goto out;
        }
#endif

        s_zero_bitmap.marker = XC_SAVE_ID_ZERO_BITMAP;
        s_zero_bitmap.zero_bitmap_size = zero_bitmap_size;
        zero_bitmap_compressed = malloc(LZ4_compressBound((zero_bitmap_size)));
        if (!zero_bitmap_compressed)
            s_zero_bitmap.size = zero_bitmap_size;
        else {
            s_zero_bitmap.size = uxenvm_compress_lz4(
                (const char *)zero_bitmap, (char *)zero_bitmap_compressed,
                zero_bitmap_size);
            if (s_zero_bitmap.size >= zero_bitmap_size) {
                free(zero_bitmap_compressed);
                zero_bitmap_compressed = NULL;
                s_zero_bitmap.size = zero_bitmap_size;
            }
        }
        s_zero_bitmap.size += sizeof(s_zero_bitmap);
        APRINTF("zero bitmap: size %d bitmap_size %d",
                s_zero_bitmap.size, s_zero_bitmap.zero_bitmap_size);
        filebuf_write(f, &s_zero_bitmap, sizeof(s_zero_bitmap));
        filebuf_write(f, zero_bitmap_compressed ? : zero_bitmap,
                      s_zero_bitmap.size - sizeof(s_zero_bitmap));

        if (!compression_is_cuckoo()) {
            s_vm_page_offsets.marker = XC_SAVE_ID_PAGE_OFFSETS;
            s_vm_page_offsets.pfn_off_nr = poi_pfn_index(&poi, poi.max_gpfn);
            page_offsets_index.offset = filebuf_tell(f);
            APRINTF("page offset index: pos %"PRId64" size %"PRIdSIZE" "
                    "nr off %d", page_offsets_index.offset,
                    s_vm_page_offsets.pfn_off_nr *
                    sizeof(s_vm_page_offsets.pfn_off[0]),
                    s_vm_page_offsets.pfn_off_nr);
            BUILD_BUG_ON(sizeof(poi.pfn_off[0]) !=
                         sizeof(s_vm_page_offsets.pfn_off[0]));
            s_vm_page_offsets.size = sizeof(s_vm_page_offsets) +
                s_vm_page_offsets.pfn_off_nr *
                sizeof(s_vm_page_offsets.pfn_off[0]);
            filebuf_write(f, &s_vm_page_offsets, sizeof(s_vm_page_offsets));
            filebuf_write(f, poi.pfn_off, s_vm_page_offsets.pfn_off_nr *
                          sizeof(s_vm_page_offsets.pfn_off[0]));
        }

        if (vm_save_info.fingerprint && !compression_is_cuckoo()) {
            s_vm_fingerprints.marker = XC_SAVE_ID_FINGERPRINTS;
            s_vm_fingerprints.hashes_nr = hashes_nr;
            fingerprints_index.offset = filebuf_tell(f);
            BUILD_BUG_ON(sizeof(hashes[0]) !=
                         sizeof(s_vm_fingerprints.hashes[0]));
            s_vm_fingerprints.size = s_vm_fingerprints.hashes_nr *
                sizeof(s_vm_fingerprints.hashes[0]);
            s_vm_fingerprints.size += sizeof(s_vm_fingerprints);
            APRINTF("fingerprints: pos %"PRId64" size %d nr hashes %d",
                    fingerprints_index.offset, s_vm_fingerprints.size,
                    s_vm_fingerprints.hashes_nr);
            filebuf_write(f, &s_vm_fingerprints, sizeof(s_vm_fingerprints));
            filebuf_write(f, hashes,
                          s_vm_fingerprints.size - sizeof(s_vm_fingerprints));
        }
    }

    if (!check_aborted()) {
        /* 0: end marker */
        batch = 0;
        filebuf_write(f, &batch, sizeof(batch));

        /* indexes */
        filebuf_write(f, &page_offsets_index, sizeof(page_offsets_index));
        if (vm_save_info.fingerprint)
            filebuf_write(f, &fingerprints_index, sizeof(fingerprints_index));

        APRINTF("memory: pages %d zero %d rezero %d clone %d trivial %d",
                total_pages, total_zero - total_rezero, total_rezero,
                total_clone, trivial_nr);
        if (vm_save_info.compress_mode == VM_SAVE_COMPRESS_LZ4 && total_pages) {
            int pct;
            pct = 10000 * (total_compress_save >> PAGE_SHIFT) / total_pages;
            APRINTF("        compressed %d in-vain %d -- saved %"PRIdSIZE
                    " bytes (%d.%02d%%)",
                    total_compressed_pages, total_compress_in_vain,
                    total_compress_save, pct / 100, pct % 100);
        }
    } else
        APRINTF("%s: save aborted%s", __FUNCTION__,
                vm_quit_interrupt ? " (quit interrupt)" : "");

    ret = 0;
  out:
    if (mem_buffer)
        xc_hypercall_buffer_free_pages(xc_handle, mem_buffer,
                                       MEM_BUFFER_SIZE >> PAGE_SHIFT);
    free(zero_bitmap);
    free(zero_bitmap_compressed);
    free(poi.pfn_off);
    free(rezero_pfns);
    free(hashes);
    free(pfn_batch);
    free(gpfn_info_list);
    free(compress_mem);
    free(compress_buf);
    free(hvm_buf);
    return ret;
}

#define uxenvm_load_read(f, buf, size, ret, err_msg, _out) do {         \
        (ret) = filebuf_read((f), (buf), (size));                       \
        if ((ret) != (size)) {                                          \
            asprintf((err_msg), "uxenvm_load_read(%s) failed", #buf);   \
            if ((ret) >= 0)                                             \
                (ret) = -EIO;                                           \
            else                                                        \
                (ret) = -errno;                                         \
            goto _out;                                                  \
        }                                                               \
    } while(0)

static int
uxenvm_load_zero_bitmap(uint8_t *zero_bitmap, uint32_t zero_bitmap_size,
                        xen_pfn_t *pfn_type, char **err_msg)
{
    int i, j;
    int ret = 0;

    for (i = j = 0; i < 8 * zero_bitmap_size; ++i) {
        if (test_bit(i, zero_bitmap))
            pfn_type[j++] = i;
        if (j == MAX_BATCH_SIZE || i == 8 * zero_bitmap_size - 1) {
            ret = xc_domain_populate_physmap_exact(
                xc_handle, vm_id, j, 0, XENMEMF_populate_on_demand,
                pfn_type);
            if (ret) {
                asprintf(err_msg,
                         "xc_domain_populate_physmap_exact failed");
                goto out;
            }
            j = 0;
        }
    }
  out:
    return ret;
}

static int
decompress_batch(int batch, xen_pfn_t *pfn_type, uint8_t *mem,
                 char *compress_buf, uint32_t compress_size,
                 int single_page, char **err_msg)
{
    int ret;

    if (single_page) {
        int i;
        uint32_t decompress_pos = 0;
        for (i = 0; i < batch; i++) {
            cs16_t cs1;
            cs1 = *(cs16_t *)&compress_buf[decompress_pos];
            if (cs1 > PAGE_SIZE) {
                asprintf(err_msg, "invalid size %d for page %"PRIx64
                         "\n", cs1, pfn_type ? pfn_type[i] : 0);
                ret = -1;
                goto out;
            }
            decompress_pos += sizeof(cs16_t);
            if (cs1 < PAGE_SIZE) {
                ret = LZ4_decompress_safe(&compress_buf[decompress_pos],
                                          (char *)&mem[i << PAGE_SHIFT],
                                          cs1, PAGE_SIZE);
                if (ret != PAGE_SIZE) {
                    asprintf(err_msg, "decompression of page %"PRIx64
                             " failed at byte %d of %d\n",
                             pfn_type ? pfn_type[i] : 0,
                             -ret, cs1);
                    ret = -1;
                    goto out;
                }
            } else
                memcpy(&mem[i << PAGE_SHIFT],
                       &compress_buf[decompress_pos], PAGE_SIZE);
            decompress_pos += cs1;
        }
    } else {
        ret = LZ4_decompress_safe(compress_buf, (char *)mem,
                                  compress_size, batch << PAGE_SHIFT);
        if (ret != batch << PAGE_SHIFT) {
            asprintf(err_msg, "decompression of page %"PRIx64
                     ":%"PRIx64" failed at byte %d of %d\n",
                     pfn_type ? pfn_type[0] : 0,
                     pfn_type ? pfn_type[batch - 1] + 1 : 0,
                     -ret, compress_size);
            ret = -1;
            goto out;
        }
    }

    ret = 0;
  out:
    return ret;
}

#ifndef DECOMPRESS_THREADED
struct decompress_ctx {
    xc_hypercall_buffer_t pp_buffer;
};
#else  /* DECOMPRESS_THREADED */
struct decompress_ctx;

struct decompress_buf_ctx {
    int batch;
    void *compress_buf;
    int compress_size;
    int single_page;
    int populate_compressed;
    xc_hypercall_buffer_t pp_buffer;
    xen_pfn_t *pfn_type;
    struct decompress_ctx *dc;
    LIST_ENTRY(decompress_buf_ctx) elem;
};

struct decompress_ctx {
    struct async_op_ctx *async_op_ctx;
    LIST_HEAD(, decompress_buf_ctx) list;
    ioh_event process_event;
    int ret;
    xc_interface *xc_handle;
    int vm_id;
    char **err_msg;
};

static void
decompress_cb(void *opaque)
{
    struct decompress_buf_ctx *dbc = (struct decompress_buf_ctx *)opaque;
    int ret;

    if (!dbc->populate_compressed) {
        ret = decompress_batch(
            dbc->batch, dbc->pfn_type,
            HYPERCALL_BUFFER_ARGUMENT_BUFFER(&dbc->pp_buffer),
            dbc->compress_buf, dbc->compress_size, dbc->single_page,
            dbc->dc->err_msg);
        if (ret)
            goto out;
    } else
        memcpy(HYPERCALL_BUFFER_ARGUMENT_BUFFER(&dbc->pp_buffer),
               dbc->compress_buf, dbc->compress_size);

    ret = xc_domain_populate_physmap_from_buffer(
        dbc->dc->xc_handle, dbc->dc->vm_id, dbc->batch, 0,
        dbc->populate_compressed ? XENMEMF_populate_from_buffer_compressed :
        XENMEMF_populate_from_buffer, &dbc->pfn_type[0], &dbc->pp_buffer);
    if (ret)
        asprintf(dbc->dc->err_msg,
                 "xc_domain_populate_physmap_from_buffer failed");

  out:
    if (ret)
        dbc->dc->ret = ret;
}

static void
decompress_complete(void *opaque)
{
    struct decompress_buf_ctx *dbc = (struct decompress_buf_ctx *)opaque;

    free(dbc->compress_buf);
    dbc->compress_buf = NULL;
    LIST_INSERT_HEAD(&dbc->dc->list, dbc, elem);
}

static int
decompress_wait_all(struct decompress_ctx *dc, char **err_msg)
{
    struct decompress_buf_ctx *dbc;
    int i;
    int ret = 0;

    APRINTF("waiting for decompress threads");
    assert(dc->async_op_ctx);
    assert(dc->xc_handle);
    for (i = 0; i < DECOMPRESS_THREADS; i++) {
        ioh_event_reset(&dc->process_event);
        async_op_process(dc->async_op_ctx);
        dbc = LIST_FIRST(&dc->list);
        if (!dbc) {
            ioh_event_wait(&dc->process_event);
            async_op_process(dc->async_op_ctx);
            dbc = LIST_FIRST(&dc->list);
        }
        if (!dbc) {
            if (err_msg)
                asprintf(err_msg, "failed to wait for dbc");
            ret = -1;
            continue;
        }
        LIST_REMOVE(dbc, elem);
        xc__hypercall_buffer_free_pages(dc->xc_handle, &dbc->pp_buffer,
                                        PP_BUFFER_PAGES);
        free(dbc);
    }

    ioh_event_close(&dc->process_event);

    async_op_free(dc->async_op_ctx);
    dc->async_op_ctx = NULL;

    return ret;
}
#endif  /* DECOMPRESS_THREADED */

static int
uxenvm_load_readbatch(struct filebuf *f, int batch, xen_pfn_t *pfn_type,
                      int *pfn_info, int *pfn_err, int decompress,
                      struct decompress_ctx *dc, int single_page,
                      int do_lazy_load, int populate_compressed, char **err_msg)
{
    uint8_t *mem = NULL;
    int j;
    int ret;
    char *compress_buf = NULL;
    int compress_size = 0;

    LOAD_DPRINTF("page batch %03x pages", batch);

    if (!single_page)
        populate_compressed = 0;

    uxenvm_load_read(f, &pfn_info[0], batch * sizeof(pfn_info[0]),
                     ret, err_msg, out);

    /* XXX legacy -- new save files have a clean pfn_info array */
    for (j = 0; j < batch; j++) {
	pfn_type[j] = pfn_info[j] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
        if (!do_lazy_load)
            continue;
        if (pfn_type[j] >= PCI_HOLE_START_PFN && pfn_type[j] < PCI_HOLE_END_PFN)
            do_lazy_load = 0;
    }

    if (decompress) {
        uxenvm_load_read(f, &compress_size, sizeof(compress_size),
                         ret, err_msg, out);
        if (compress_size == -1)
            decompress = 0;
    }

    if (!decompress || do_lazy_load) {
        LOAD_DPRINTF("  populate %08"PRIx64":%08"PRIx64" = %03x pages",
                     pfn_type[0], pfn_type[batch - 1] + 1, batch);
        ret = xc_domain_populate_physmap_exact(
            xc_handle, vm_id, batch, 0, XENMEMF_populate_on_demand |
            (do_lazy_load ? XENMEMF_populate_on_demand_dmreq : 0),
            &pfn_type[0]);
        if (ret) {
            asprintf(err_msg, "xc_domain_populate_physmap_exact failed");
            goto out;
        }

        if (do_lazy_load) {
            uint32_t skip;
            if (decompress)
                skip = compress_size;
            else
                skip = batch << PAGE_SHIFT;
            ret = filebuf_seek(f, skip, FILEBUF_SEEK_CUR) != -1 ? 0 : -EIO;
            if (ret < 0)
                asprintf(err_msg, "page %"PRIx64":%"PRIx64" skip failed",
                         pfn_type[0], pfn_type[batch - 1] + 1);
            goto out;
        }

        mem = xc_map_foreign_bulk(xc_handle, vm_id, PROT_WRITE,
                                  &pfn_type[0], &pfn_err[0], batch);
        if (mem == NULL) {
            asprintf(err_msg, "xc_map_foreign_bulk failed");
            ret = -1;
            goto out;
        }
        for (j = 0; j < batch; j++) {
            if (pfn_err[j]) {
                asprintf(err_msg, "map fail: %d/%d gpfn %08"PRIx64" err %d",
                         j, batch, pfn_type[j], pfn_err[j]);
                ret = -1;
                goto out;
            }
        }

        LOAD_DPRINTF("      read %08"PRIx64":%08"PRIx64" = %03x pages",
                     pfn_type[0], pfn_type[batch - 1] + 1, batch);
        uxenvm_load_read(f, mem, batch << PAGE_SHIFT, ret, err_msg, out);
    } else {
#ifdef DECOMPRESS_THREADED
        struct decompress_buf_ctx *dbc;
#endif  /* DECOMPRESS_THREADED */

        compress_buf = malloc(compress_size);
        if (!compress_buf) {
            asprintf(err_msg, "malloc(compress_size) failed");
            goto out;
        }

        LOAD_DPRINTF("      read %08"PRIx64":%08"PRIx64" = %03x pages",
                     pfn_type[0], pfn_type[batch - 1] + 1, batch);
        uxenvm_load_read(f, compress_buf, compress_size, ret, err_msg, out);
#ifdef DECOMPRESS_THREADED
        ioh_event_reset(&dc->process_event);
        async_op_process(dc->async_op_ctx);
        if (dc->ret) {
            ret = -1;
            goto out;
        }
        dbc = LIST_FIRST(&dc->list);
        if (!dbc) {
            ioh_event_wait(&dc->process_event);
            async_op_process(dc->async_op_ctx);
            dbc = LIST_FIRST(&dc->list);
        }
        if (!dbc) {
            asprintf(err_msg, "no decompress_buf_ctx");
            ret = -1;
            goto out;
        }
        LIST_REMOVE(dbc, elem);
        memcpy(&dbc->pfn_type[0], &pfn_type[0], batch * sizeof(*pfn_type));
        dbc->compress_buf = compress_buf;
        compress_buf = NULL;
        dbc->compress_size = compress_size;
        dbc->batch = batch;
        dbc->single_page = single_page;
        dbc->populate_compressed = populate_compressed;
        ret = async_op_add(dc->async_op_ctx, dbc, &dc->process_event,
                           decompress_cb, decompress_complete);
        if (ret) {
            asprintf(err_msg, "async_op_add failed");
            goto out;
        }
#else  /* DECOMPRESS_THREADED */
        if (!populate_compressed) {
            ret = decompress_batch(
                batch, pfn_type,
                HYPERCALL_BUFFER_ARGUMENT_BUFFER(&dc->pp_buffer),
                compress_buf, compress_size, single_page, err_msg);
            if (ret)
                goto out;
        } else
            memcpy(HYPERCALL_BUFFER_ARGUMENT_BUFFER(&dc->pp_buffer),
                   compress_buf, compress_size);

        LOAD_DPRINTF("  populate %08"PRIx64":%08"PRIx64" = %03x pages",
                     pfn_type[0], pfn_type[batch - 1] + 1, batch);
        ret = xc_domain_populate_physmap_from_buffer(
            xc_handle, domid, batch, 0, populate_compressed ?
            XENMEMF_populate_from_buffer_compressed :
            XENMEMF_populate_from_buffer, &pfn_type[0], &dc->pp_buffer);
        if (ret) {
            asprintf(err_msg, "xc_domain_populate_physmap_from_buffer "
                     "compressed failed");
            goto out;
        }
#endif  /* DECOMPRESS_THREADED */
    }

    ret = 0;
  out:
    if (mem)
        xc_munmap(xc_handle, vm_id, mem, batch * PAGE_SIZE);
    free(compress_buf);
    return ret;
}

static uint32_t uxenvm_load_progress = 0;

static int
uxenvm_load_alloc(xen_pfn_t **pfn_type, int **pfn_err, int **pfn_info,
                  char **err_msg)
{
    int ret = 0;

    *pfn_type = malloc(MAX_BATCH_SIZE * sizeof(**pfn_type));
    if (*pfn_type == NULL) {
	asprintf(err_msg, "pfn_type = malloc(%"PRIdSIZE") failed",
		 MAX_BATCH_SIZE * sizeof(**pfn_type));
	ret = -ENOMEM;
	goto out;
    }

    *pfn_info = malloc(MAX_BATCH_SIZE * sizeof(**pfn_info));
    if (*pfn_info == NULL) {
	asprintf(err_msg, "pfn_info = malloc(%"PRIdSIZE") failed",
		 MAX_BATCH_SIZE * sizeof(**pfn_info));
	ret = -ENOMEM;
	goto out;
    }

    *pfn_err = malloc(MAX_BATCH_SIZE * sizeof(**pfn_err));
    if (*pfn_err == NULL) {
	asprintf(err_msg, "pfn_err = malloc(%"PRIdSIZE") failed",
		 MAX_BATCH_SIZE * sizeof(**pfn_err));
	ret = -ENOMEM;
	goto out;
    }

    uxenvm_load_progress = 0;

  out:
    return ret;
}

static int
uxenvm_load_batch(struct filebuf *f, int32_t marker, xen_pfn_t *pfn_type,
                  int *pfn_err, int *pfn_info, struct decompress_ctx *dc,
                  int do_lazy_load, int populate_compressed, char **err_msg)
{
    DECLARE_HYPERCALL_BUFFER(uint8_t, pp_buffer);
    int decompress;
    int single_page;
    int ret;

    decompress = 0;
    single_page = 0;
    if ((unsigned int)marker > 3 * MAX_BATCH_SIZE) {
        asprintf(err_msg, "invalid batch size: %x",
                 (unsigned int)marker);
        ret = -EINVAL;
        goto out;
    } else if (marker > 2 * MAX_BATCH_SIZE) {
        marker -= 2 * MAX_BATCH_SIZE;
        decompress = 1;
        single_page = 1;
    } else if (marker > MAX_BATCH_SIZE) {
        marker -= MAX_BATCH_SIZE;
        decompress = 1;
    }
    if (decompress) {
#ifdef DECOMPRESS_THREADED
        if (!dc->async_op_ctx) {
            struct decompress_buf_ctx *dbc;
            int i;
            dc->ret = 0;
            dc->async_op_ctx = async_op_init();
            LIST_INIT(&dc->list);
            for (i = 0; i < DECOMPRESS_THREADS; i++) {
                dbc = calloc(1, sizeof(struct decompress_buf_ctx));
                if (!dbc) {
                    asprintf(err_msg, "calloc dbc failed");
                    ret = -ENOMEM;
                    goto out;
                }
                pp_buffer = xc_hypercall_buffer_alloc_pages(
                    xc_handle, pp_buffer, PP_BUFFER_PAGES);
                if (!pp_buffer) {
                    asprintf(err_msg, "xc_hypercall_buffer_alloc_pages"
                             "(%d pages) failed", PP_BUFFER_PAGES);
                    ret = -ENOMEM;
                    goto out;
                }
                dbc->pp_buffer = *HYPERCALL_BUFFER(pp_buffer);
                dbc->pfn_type = malloc(
                    MAX_BATCH_SIZE * sizeof(*pfn_type));
                if (dbc->pfn_type == NULL) {
                    asprintf(err_msg, "dbc->pfn_type = malloc(%"
                             PRIdSIZE") failed",
                             MAX_BATCH_SIZE * sizeof(*pfn_type));
                    ret = -ENOMEM;
                    goto out;
                }
                dbc->dc = dc;
                LIST_INSERT_HEAD(&dc->list, dbc, elem);
            }
            ioh_event_init(&dc->process_event);
            dc->xc_handle = xc_handle;
            dc->vm_id = vm_id;
            dc->err_msg = err_msg;
            pp_buffer = NULL;
        }
#else
        if (!dc->pp_buffer) {
            pp_buffer = xc_hypercall_buffer_alloc_pages(
                xc_handle, pp_buffer, PP_BUFFER_PAGES);
            if (!pp_buffer) {
                asprintf(err_msg, "xc_hypercall_buffer_alloc_pages"
                         "(%d pages) failed", PP_BUFFER_PAGES);
                ret = -ENOMEM;
                goto out;
            }
            dc->pp_buffer = *HYPERCALL_BUFFER(pp_buffer);
        }
#endif  /* DECOMPRESS_THREADED */
    }
    uxenvm_load_progress += marker;
    /* output progress load message every ~10% */
    if ((uxenvm_load_progress * 10 / (vm_mem_mb << 8UL)) !=
        ((uxenvm_load_progress - marker) * 10 / (vm_mem_mb << 8UL)))
        APRINTF("memory load %d pages", uxenvm_load_progress);
    ret = uxenvm_load_readbatch(f, marker, pfn_type, pfn_info, pfn_err,
                                decompress, dc, single_page, do_lazy_load,
                                populate_compressed, err_msg);
  out:
    return ret;
}

static int
apply_immutable_memory(struct immutable_range *r, int nranges)
{
    int i;
    int ret;

    for (i = 0; i < nranges; i++) {
        ret = xc_hvm_set_mem_type(xc_handle, vm_id, HVMMEM_ram_immutable,
                                  r[i].base, r[i].size);
        if (ret) {
            EPRINTF("xc_hvm_set_mem_type(HVMMEM_ram_immutable) failed: "
                    "pfn 0x%"PRIx64" size 0x%"PRIx64, r[i].base, r[i].size);
            return ret;
        }
    }
    APRINTF("%s: done", __FUNCTION__);

    return 0;
}

#define uxenvm_load_read_struct(f, s, _marker, ret, err_msg, _out) do {	\
        (ret) = uxenvm_read_struct((f), &(s));                          \
        if ((ret) != uxenvm_read_struct_size(&(s))) {                   \
            asprintf((err_msg), "uxenvm_read_struct(%s) failed", #s);   \
	    goto _out;							\
	}								\
	(s).marker = (_marker);						\
    } while (0)
#define uxenvm_load_read_generic_struct(f, s, _marker, ret, err_msg, _out) \
    do {                                                                \
        int r;                                                          \
        r = filebuf_read(f, &(s).size, sizeof((s).size));               \
        if (r != sizeof((s).size)) {                                    \
            asprintf((err_msg), "uxenvm_read_struct(%s) size failed", #s); \
	    goto _out;							\
	}								\
        r = filebuf_read(f, (uint8_t *)&(s) +                           \
                         sizeof(struct xc_save_generic),                \
                         (s).size);                                     \
        if (r != (s).size) {                                            \
            asprintf((err_msg), "uxenvm_read_struct(%s) data failed", #s); \
	    goto _out;							\
	}								\
	(s).marker = (_marker);						\
    } while (0)

#ifdef SAVE_CUCKOO_ENABLED
static int
map_template_fingerprints(struct filebuf *t,
                          struct page_fingerprint **tfps,
                          int *n, char **err_msg)
{
    uint64_t fingerprints_pos = 0;
    struct xc_save_vm_fingerprints s_vm_fingerprints = { };
    int32_t marker = 0;
    size_t sz;
    off_t pos;
    int ret = 0;

    filebuf_seek(t, 0, FILEBUF_SEEK_END);
    for (;;) {
        struct xc_save_index index;

        pos = filebuf_seek(t, -(off_t)sizeof(index), FILEBUF_SEEK_CUR);
        uxenvm_load_read(t, &index, sizeof(index), ret, err_msg, out);
        if (!index.marker) {
            break;
        } else if (index.marker == XC_SAVE_ID_FINGERPRINTS) {
            fingerprints_pos = index.offset;
            break;
        }
        filebuf_seek(t, pos, FILEBUF_SEEK_SET);
    }

    if (!fingerprints_pos) {
        asprintf(err_msg, "no fingerprints section found in template file");
        ret = -ENOENT;
        goto out;
    }

    filebuf_seek(t, fingerprints_pos, FILEBUF_SEEK_SET);
    uxenvm_load_read(t, &s_vm_fingerprints.marker,
                     sizeof(s_vm_fingerprints.marker), ret, err_msg,
                     out);
    if (s_vm_fingerprints.marker != XC_SAVE_ID_FINGERPRINTS) {
        asprintf(err_msg, "no fingerprints section at offset %"PRId64,
                 fingerprints_pos);
        ret = -EINVAL;
        goto out;
    }
    uxenvm_load_read_struct(t, s_vm_fingerprints, marker, ret,
                            err_msg, out);

    APRINTF("found %u fingerprints at offset %"PRId64,
            s_vm_fingerprints.hashes_nr, fingerprints_pos);
    sz = s_vm_fingerprints.hashes_nr * sizeof(struct page_fingerprint);
    *n = s_vm_fingerprints.hashes_nr;
    *tfps = filebuf_mmap(t, filebuf_tell(t), sz);
    if (!*tfps) {
        asprintf(err_msg, "failed mapping fingerprints");
        ret = -ENOMEM;
        goto out;
    }
    ret = 0;

out:
    return ret;
}

static int
save_cuckoo_pages(struct filebuf *f, struct page_fingerprint *hashes,
                  int n, int simple_mode, char **err_msg)
{
    struct cuckoo_context cuckoo_context;
    struct cuckoo_callbacks ccb;
    void *opaque;
    struct page_fingerprint *tfps = NULL;
    int tn = 0;
    struct filebuf *t = NULL;
    int ret;

    if (vm_template_file) {
        t = filebuf_open(vm_template_file, "rb");
        if (!t) {
            asprintf(err_msg, "filebuf_open(vm_template_file = %s) failed",
                     vm_template_file);
            ret = -errno;
            goto out;
        }

        ret = map_template_fingerprints(t, &tfps, &tn, err_msg);
        if (ret)
            goto out;
    }

    ret = cuckoo_uxen_init(&cuckoo_context, &ccb, &opaque,
                           vm_save_info.save_abort_event);
    if (ret)
        goto out;

    if (simple_mode)
        ret = -1;
    else
        ret = cuckoo_compress_vm(&cuckoo_context, vm_uuid, f, tn, tfps,
                                 n, hashes, &ccb, opaque);

    cuckoo_uxen_close(&cuckoo_context, opaque);
out:
    if (t)
        filebuf_close(t);

    return ret < 0 ? ret : 0;
}

static int
load_cuckoo_pages(struct filebuf *f, int reusing_vm, int simple_mode)
{
    struct cuckoo_context cuckoo_context;
    struct cuckoo_callbacks ccb;
    void *opaque;
    int ret;

    ret = cuckoo_uxen_init(&cuckoo_context, &ccb, &opaque, NULL);
    if (ret)
        return ret;

    if (simple_mode)
        ret = -1;
    else
        ret = cuckoo_reconstruct_vm(&cuckoo_context, vm_uuid, f, reusing_vm,
                                    &ccb, opaque);
    cuckoo_uxen_close(&cuckoo_context, opaque);

    return ret < 0 ? ret : 0;
}
#endif /* SAVE_CUCKOO_ENABLED */

static int
load_whp_pages(struct filebuf *f, int restore_mode, struct xc_save_whp_pages *swhp)
{
    int ret;
    int no_pages = swhp->no_pages;

    debug_printf("load whp pages\n");
    if (restore_mode == VM_RESTORE_CLONE) {
        ret = whpx_clone_pages(f, vm_template_uuid, no_pages);
        if (!ret) {
            if (!vm_has_template_uuid)
                vm_has_template_uuid = 1;
            //restore_mode = VM_RESTORE_NORMAL;
        }
    } else
        ret = whpx_read_pages(f, no_pages);

    return ret;
}

static uint8_t *dm_state_load_buf = NULL;
static int dm_state_load_size = 0;

#define uxenvm_check_mapcache_init() do { \
        if (!mapcache_init_done) {                                      \
            if (s_mapcache_params.marker == XC_SAVE_ID_MAPCACHE_PARAMS) \
                mapcache_init_restore(s_mapcache_params.end_low_pfn,    \
                                      s_mapcache_params.start_high_pfn, \
                                      s_mapcache_params.end_high_pfn);  \
            else                                                        \
                mapcache_init(vm_mem_mb);                               \
            mapcache_init_done = 1;                                     \
        }                                                               \
    } while (0)

#define uxenvm_check_restore_clone(mode) do {                           \
        if (!whpx_enable && (mode) == VM_RESTORE_CLONE) {               \
            ret = xc_domain_clone_physmap(xc_handle, vm_id,             \
                                          vm_template_uuid);            \
            if (ret < 0) {                                              \
                asprintf(err_msg, "xc_domain_clone_physmap failed");    \
                goto out;                                               \
            }                                                           \
            if (!vm_has_template_uuid) {                                \
                vm_has_template_uuid = 1;                               \
                ret = 0;                                                \
                goto skip_mem;                                          \
            }                                                           \
            (mode) = VM_RESTORE_NORMAL;                                 \
        }                                                               \
    } while (0)

static int
uxenvm_loadvm_execute(struct filebuf *f, int restore_mode, char **err_msg)
{
    struct xc_save_version_info s_version_info = { };
    struct xc_save_clock_info s_clock_info = { };
    struct xc_save_tsc_info s_tsc_info = { };
    struct xc_save_vcpu_info s_vcpu_info = { };
    struct xc_save_hvm_params s_hvm_params = { };
    int nr_hvm_params = 0;
    struct xc_save_hvm_context s_hvm_context = { };
    struct xc_save_hvm_dm s_hvm_dm = { };
    struct xc_save_vm_uuid s_vm_uuid = { };
    struct xc_save_vm_template_uuid s_vm_template_uuid = { };
    struct xc_save_hvm_introspec s_hvm_introspec = { };
    struct xc_save_mapcache_params s_mapcache_params = { };
    struct xc_save_vm_template_file s_vm_template_file = { };
    struct xc_save_vm_page_offsets s_vm_page_offsets = { };
    struct xc_save_zero_bitmap s_zero_bitmap = { };
    struct xc_save_vm_fingerprints s_vm_fingerprints = { };
#ifdef SAVE_CUCKOO_ENABLED
    struct xc_save_cuckoo_data s_cuckoo = { };
#endif
    struct xc_save_whp_pages s_whppages = { };
    struct immutable_range *immutable_ranges = NULL;
    uint8_t *hvm_buf = NULL;
    uint8_t *zero_bitmap = NULL, *zero_bitmap_compressed = NULL;
    xen_pfn_t *pfn_type = NULL;
    int *pfn_err = NULL, *pfn_info = NULL;
    struct decompress_ctx dc = { 0 };
    int populate_compressed = (restore_mode == VM_RESTORE_TEMPLATE);
    int load_lazy_load_info = vm_lazy_load;
    struct page_offset_info *lli = &dm_lazy_load_info;
    int32_t marker;
    int mapcache_init_done = 0;
    int ret;
    int size;

    /* XXX init debug option */
    if (!whpx_enable && strstr(uxen_opt_debug, ",uncomptmpl,"))
        populate_compressed = 0;

    ret = uxenvm_load_alloc(&pfn_type, &pfn_err, &pfn_info, err_msg);
    if (ret < 0)
        goto out;

    uxenvm_load_read(f, &marker, sizeof(marker), ret, err_msg, out);
    if (marker == XC_SAVE_ID_VERSION)
        uxenvm_load_read_struct(f, s_version_info, marker, ret, err_msg, out);
    if (s_version_info.version != SAVE_FORMAT_VERSION) {
        asprintf(err_msg, "version info mismatch: %d != %d",
                 s_version_info.version, SAVE_FORMAT_VERSION);
        ret = -EINVAL;
        goto out;
    }
    while (!vm_quit_interrupt) {
        uxenvm_load_read(f, &marker, sizeof(marker), ret, err_msg, out);
	if (marker == 0)	/* end marker */
	    break;
	switch (marker) {
	case XC_SAVE_ID_TSC_INFO:
	    uxenvm_load_read_struct(f, s_tsc_info, marker, ret, err_msg, out);
	    APRINTF("tsc info: mode %d nsec %"PRIu64" khz %d incarn %d",
		    s_tsc_info.tsc_mode, s_tsc_info.nsec, s_tsc_info.khz,
		    s_tsc_info.incarn);
	    break;
	case XC_SAVE_ID_VCPU_INFO:
	    uxenvm_load_read_struct(f, s_vcpu_info, marker, ret, err_msg, out);
	    APRINTF("vcpus %d online %"PRIx64, s_vcpu_info.max_vcpu_id,
		    s_vcpu_info.vcpumap);
	    break;
	case XC_SAVE_ID_HVM_PARAMS:
	    uxenvm_load_read_generic_struct(f, s_hvm_params, marker, ret,
                                            err_msg, out);
            nr_hvm_params = s_hvm_params.size / sizeof(s_hvm_params.params[0]);
            if (s_hvm_params.size !=
                nr_hvm_params * sizeof(s_hvm_params.params[0])) {
		asprintf(err_msg, "hvm_params chunk malformed");
		ret = -EINVAL;
		goto out;
            }
	    APRINTF("nr_hvm_params %d", nr_hvm_params);
	    break;
	case XC_SAVE_ID_HVM_CONTEXT:
	    uxenvm_load_read_struct(f, s_hvm_context, marker, ret, err_msg,
				    out);
	    APRINTF("hvm rec size %d", s_hvm_context.size);
	    hvm_buf = malloc(s_hvm_context.size);
	    if (hvm_buf == NULL) {
		asprintf(err_msg, "hvm_buf = malloc(%d) failed",
			 s_hvm_context.size);
		ret = -ENOMEM;
		goto out;
	    }
            uxenvm_load_read(f, hvm_buf, s_hvm_context.size, ret, err_msg, out);
	    break;
	case XC_SAVE_ID_HVM_DM:
	    uxenvm_load_read_struct(f, s_hvm_dm, marker, ret, err_msg, out);
	    APRINTF("dm rec size %d", s_hvm_dm.size);
	    dm_state_load_buf = malloc(s_hvm_dm.size);
	    if (dm_state_load_buf == NULL) {
		asprintf(err_msg, "dm_state_load_buf = malloc(%d) failed",
			 s_hvm_dm.size);
		ret = -ENOMEM;
		goto out;
	    }
            uxenvm_load_read(f, dm_state_load_buf, s_hvm_dm.size,
                             ret, err_msg, out);
	    dm_state_load_size = s_hvm_dm.size;
	    break;
	case XC_SAVE_ID_VM_UUID:
	    uxenvm_load_read_struct(f, s_vm_uuid, marker, ret, err_msg, out);
            if (restore_mode == VM_RESTORE_TEMPLATE)
                memcpy(vm_uuid, s_vm_uuid.uuid, sizeof(vm_uuid));
            if (!vm_has_template_uuid)
                memcpy(vm_template_uuid, s_vm_uuid.uuid,
                       sizeof(vm_template_uuid));
	    break;
	case XC_SAVE_ID_VM_TEMPLATE_UUID:
	    uxenvm_load_read_struct(f, s_vm_template_uuid, marker, ret,
				    err_msg, out);
	    memcpy(vm_template_uuid, s_vm_template_uuid.uuid,
                   sizeof(vm_template_uuid));
	    vm_has_template_uuid = 1;

	    break;
        case XC_SAVE_ID_HVM_INTROSPEC:
            uxenvm_load_read_struct(f, s_hvm_introspec, marker, ret, err_msg,
                                    out);
            dmpdev_PsLoadedModulesList =
                s_hvm_introspec.info.PsLoadedModulesList;
            dmpdev_PsActiveProcessHead =
                s_hvm_introspec.info.PsActiveProcessHead;
            size = s_hvm_introspec.info.n_immutable_ranges *
                sizeof(struct immutable_range);
            immutable_ranges = malloc(size);
            if (!immutable_ranges) {
                asprintf(err_msg,
                         "introspec_state_load_buf = malloc(%d) failed", size);
                ret = -ENOMEM;
                goto out;
            }
            uxenvm_load_read(f, immutable_ranges, size, ret, err_msg, out);
            APRINTF("immutable_ranges size 0x%x", size);
            break;
        case XC_SAVE_ID_MAPCACHE_PARAMS:
            uxenvm_load_read_struct(f, s_mapcache_params, marker, ret, err_msg,
                                    out);
            break;
#ifdef SAVE_CUCKOO_ENABLED
        case XC_SAVE_ID_CUCKOO_DATA:
            uxenvm_load_read_struct(f, s_cuckoo, marker, ret, err_msg, out);
            uxenvm_check_restore_clone(restore_mode);
            uxenvm_check_mapcache_init();
            ret = load_cuckoo_pages(f, 0, s_cuckoo.simple_mode);
            if (ret)
                goto out;
            break;
#endif
        case XC_SAVE_ID_WHP_PAGES:
            uxenvm_load_read_struct(f, s_whppages, marker, ret, err_msg, out);
            uxenvm_check_restore_clone(restore_mode);
            uxenvm_check_mapcache_init();
            ret = load_whp_pages(f, restore_mode, &s_whppages);
            if (ret)
                goto out;
            break;
        case XC_SAVE_ID_VM_TEMPLATE_FILE:
            uxenvm_load_read_struct(f, s_vm_template_file, marker, ret,
                                    err_msg, out);
            vm_template_file = calloc(1, s_vm_template_file.size + 1);
            if (vm_template_file == NULL) {
                asprintf(err_msg, "vm_template_file = calloc(%d) failed",
                         s_vm_template_file.size + 1);
                ret = -ENOMEM;
                goto out;
            }
            uxenvm_load_read(f, vm_template_file, s_vm_template_file.size,
                             ret, err_msg, out);
            vm_template_file[s_vm_template_file.size] = 0;
            APRINTF("vm template file: %s", vm_template_file);
            vm_lazy_load = 0;
            break;
        case XC_SAVE_ID_PAGE_OFFSETS:
            uxenvm_load_read_struct(f, s_vm_page_offsets, marker, ret,
                                    err_msg, out);
            ret = filebuf_seek(f, s_vm_page_offsets.pfn_off_nr *
                               sizeof(s_vm_page_offsets.pfn_off[0]),
                               FILEBUF_SEEK_CUR) != -1 ? 0 : -EIO;
            if (ret < 0) {
                asprintf(err_msg, "filebuf_seek(vm_page_offsets) failed");
                goto out;
            }
            APRINTF("page offset index: %d pages, skipped %"PRIdSIZE
                    " bytes at %"PRId64,
                    s_vm_page_offsets.pfn_off_nr,
                    s_vm_page_offsets.pfn_off_nr *
                    sizeof(s_vm_page_offsets.pfn_off[0]),
                    filebuf_tell(f) - s_vm_page_offsets.size);
            break;
        case XC_SAVE_ID_ZERO_BITMAP:
            uxenvm_load_read_struct(f, s_zero_bitmap, marker, ret, err_msg,
                                    out);
            zero_bitmap_compressed =
                malloc(s_zero_bitmap.size - sizeof(s_zero_bitmap));
            if (zero_bitmap_compressed == NULL) {
                asprintf(err_msg, "zero_bitmap_compressed = "
                         "malloc(%"PRIdSIZE") failed",
                         s_zero_bitmap.size - sizeof(s_zero_bitmap));
                ret = -ENOMEM;
                goto out;
            }
            zero_bitmap = malloc(s_zero_bitmap.zero_bitmap_size);
            if (zero_bitmap == NULL) {
                asprintf(err_msg, "zero_bitmap = malloc(%d) failed",
                         s_zero_bitmap.zero_bitmap_size);
                ret = -ENOMEM;
                goto out;
            }
            uxenvm_load_read(f, zero_bitmap_compressed, s_zero_bitmap.size -
                             sizeof(s_zero_bitmap), ret, err_msg, out);
            ret = LZ4_decompress_safe((const char *)zero_bitmap_compressed,
                                      (char *)zero_bitmap,
                                      s_zero_bitmap.size - sizeof(s_zero_bitmap),
                                      s_zero_bitmap.zero_bitmap_size);
            if (ret != s_zero_bitmap.zero_bitmap_size) {
                asprintf(err_msg, "LZ4_decompress_safe(zero_bitmap) failed:"
                         " %d != %u", ret,
                         s_zero_bitmap.zero_bitmap_size);
                ret = -EINVAL;
                goto out;
            }
            uxenvm_check_restore_clone(restore_mode);
            uxenvm_check_mapcache_init();
            ret = uxenvm_load_zero_bitmap(
                zero_bitmap, s_zero_bitmap.zero_bitmap_size, pfn_type, err_msg);
            if (ret)
                goto out;
            break;
        case XC_SAVE_ID_FINGERPRINTS:
            uxenvm_load_read_struct(f, s_vm_fingerprints, marker, ret,
                                    err_msg, out);
            ret = filebuf_seek(
                f, s_vm_fingerprints.size - sizeof(s_vm_fingerprints),
                FILEBUF_SEEK_CUR) != -1 ? 0 : -EIO;
            if (ret < 0) {
                asprintf(err_msg, "filebuf_seek(vm_fingerprints) failed");
                goto out;
            }
            APRINTF("fingerprints: %d hashes, skipped %"PRIdSIZE" bytes",
                    s_vm_fingerprints.hashes_nr,
                    s_vm_fingerprints.size - sizeof(s_vm_fingerprints));
            break;
        case XC_SAVE_ID_CLOCK_INFO:
            /* vm_clock offset */
            uxenvm_load_read_struct(f, s_clock_info, marker, ret,
                                    err_msg, out);
            clock_save_adjust = s_clock_info.adjust_offset;
            break;
	default:
            uxenvm_check_restore_clone(restore_mode);
            uxenvm_check_mapcache_init();
            ret = uxenvm_load_batch(f, marker, pfn_type, pfn_err, pfn_info,
                                    &dc, vm_lazy_load, populate_compressed,
                                    err_msg);
            if (ret)
                goto out;
            break;
        }
    }
#ifdef DECOMPRESS_THREADED
    if (dc.async_op_ctx) {
        ret = decompress_wait_all(&dc, err_msg);
        if (ret)
            goto out;
    }
#endif  /* DECOMPRESS_THREADED */

  skip_mem:
    if (vm_quit_interrupt)
        goto out;
    if (restore_mode == VM_RESTORE_TEMPLATE) {		/* template load */
        ret = xc_domain_sethandle(xc_handle, vm_id, vm_uuid);
        if (ret < 0) {
            asprintf(err_msg,
                     "xc_domain_sethandle(template uuid) failed");
            goto out;
        }
        /* we need to do apply_immutable_memory() only for the template.
        The HVMMEM_ram_immutable attribute is stored in the loaded template
        p2m structures, not in the guest's.
        It is checked only when unsharing a page.
        So, if we save/restore a ucVM, then this information is still
        preserved in loaded template p2m structures, not in ucvm's savefile.
        */
        if (immutable_ranges)
            ret = apply_immutable_memory(
                immutable_ranges, s_hvm_introspec.info.n_immutable_ranges);
	goto out;
    }

    uxenvm_check_mapcache_init();

    if (load_lazy_load_info) {
        uint64_t page_offsets_pos = 0;

        if (vm_template_file) {
            lli->fb = filebuf_open(vm_template_file, "rb");
            if (!lli->fb) {
                ret = -errno;
                asprintf(err_msg,
                         "uxenvm_open(vm_template_file = %s) failed",
                         vm_template_file);
                goto out;
            }
        } else
            lli->fb = filebuf_openref(f);

        filebuf_buffer_max(lli->fb, PAGE_SIZE);
        filebuf_seek(lli->fb, 0, FILEBUF_SEEK_END);
        while (1) {
            struct xc_save_index index;

            filebuf_seek(lli->fb, -(off_t)sizeof(index), FILEBUF_SEEK_CUR);
            uxenvm_load_read(lli->fb, &index, sizeof(index), ret, err_msg, out);
            if (!index.marker)
                break;
            switch (index.marker) {
            case XC_SAVE_ID_PAGE_OFFSETS:
                page_offsets_pos = index.offset;
                break;
            }
            filebuf_seek(lli->fb, -(off_t)sizeof(index), FILEBUF_SEEK_CUR);
        }

        if (page_offsets_pos) {
            filebuf_seek(lli->fb, page_offsets_pos, FILEBUF_SEEK_SET);
            uxenvm_load_read(lli->fb, &s_vm_page_offsets.marker,
                             sizeof(s_vm_page_offsets.marker), ret, err_msg,
                             out);
            if (s_vm_page_offsets.marker != XC_SAVE_ID_PAGE_OFFSETS) {
                asprintf(err_msg, "page_offsets index corrupt, no page offsets "
                         "index at offset %"PRId64, page_offsets_pos);
                ret = -EINVAL;
                goto out;
            }
            uxenvm_load_read_struct(lli->fb, s_vm_page_offsets,
                                    XC_SAVE_ID_PAGE_OFFSETS, ret, err_msg, out);
            lli->max_gpfn = s_vm_page_offsets.pfn_off_nr;
            if (lli->max_gpfn > PCI_HOLE_START_PFN)
                lli->max_gpfn += PCI_HOLE_END_PFN - PCI_HOLE_START_PFN;
            page_offsets_pos += sizeof(s_vm_page_offsets);
            APRINTF("lazy load index: pos %"PRId64" size %"PRIdSIZE
                    " nr off %d", page_offsets_pos,
                    s_vm_page_offsets.pfn_off_nr * sizeof(lli->pfn_off[0]),
                    s_vm_page_offsets.pfn_off_nr);
            lli->pfn_off = (uint64_t *)filebuf_mmap(
                lli->fb, page_offsets_pos,
                s_vm_page_offsets.pfn_off_nr * sizeof(lli->pfn_off[0]));
        }
    }

    if (s_tsc_info.marker == XC_SAVE_ID_TSC_INFO)
	xc_domain_set_tsc_info(xc_handle, vm_id, s_tsc_info.tsc_mode,
			       s_tsc_info.nsec, s_tsc_info.khz,
			       s_tsc_info.incarn);
    if (s_vcpu_info.marker == XC_SAVE_ID_VCPU_INFO)
	;
    if (s_hvm_params.marker == XC_SAVE_ID_HVM_PARAMS) {
        int param;
        uint64_t io_pfn_first = ~0ULL;
        int dmreq_init_state = 0;
        for (param = 0; param < nr_hvm_params; param++) {
            APRINTF("hvm param %d: %"PRIx64, s_hvm_params.params[param].idx,
                    s_hvm_params.params[param].data);
            switch (s_hvm_params.params[param].idx) {
            case HVM_PARAM_IO_PFN_FIRST:
                io_pfn_first = s_hvm_params.params[param].data;
                break;
            case HVM_PARAM_IO_PFN_LAST:
                if (io_pfn_first > s_hvm_params.params[param].data) {
                    asprintf(err_msg, "io pfn first/last invalid: %"
                             PRIx64"/%"PRIx64, io_pfn_first,
                             s_hvm_params.params[param].data);
                    goto out;
                }
                while (io_pfn_first <= s_hvm_params.params[param].data) {
                    xc_clear_domain_page(xc_handle, vm_id, io_pfn_first);
                    io_pfn_first++;
                }
                break;
            case HVM_PARAM_SHARED_INFO_PFN:
                if (!s_hvm_params.params[param].data ||
                    s_hvm_params.params[param].data == -1)
                    continue;
                ret = xc_domain_add_to_physmap(
                    xc_handle, vm_id, XENMAPSPACE_shared_info, 0,
                    s_hvm_params.params[param].data);
                if (ret < 0) {
                    asprintf(err_msg, "add_to_physmap(shared_info) failed");
                    goto out;
                }
                continue;
            case HVM_PARAM_DMREQ_VCPU_PFN:
                dmreq_init_state = 1;
                break;
            case HVM_PARAM_DMREQ_PFN:
                if (dmreq_init_state != 1) {
                    asprintf(err_msg, "dmreq-vcpu/dmreq pfn order invalid");
                    goto out;
                }
                xc_clear_domain_page(xc_handle, vm_id,
                                     s_hvm_params.params[param].data);
                dmreq_init_state = 2;
                break;
            }
            xc_set_hvm_param(xc_handle, vm_id, s_hvm_params.params[param].idx,
                             s_hvm_params.params[param].data);
        }
        if (dmreq_init_state == 2) {
            APRINTF("%s: dmreq init\n", __FUNCTION__);
            dmreq_init();
        }
    }
    if (s_hvm_context.marker == XC_SAVE_ID_HVM_CONTEXT)
        vm_set_context(hvm_buf, s_hvm_context.size);

    /* XXX pae? */

    ret = 0;
  out:
#ifndef DECOMPRESS_THREADED
    if (HYPERCALL_BUFFER_ARGUMENT_BUFFER(dc.pp_buffer))
        xc__hypercall_buffer_free_pages(xc_handle, dc.pp_buffer,
                                        PP_BUFFER_PAGES);
#else  /* DECOMPRESS_THREADED */
    if (dc.async_op_ctx)
        (void)decompress_wait_all(&dc, NULL);
#endif  /* DECOMPRESS_THREADED */
    free(pfn_err);
    free(pfn_info);
    free(pfn_type);
    free(hvm_buf);
    free(zero_bitmap);
    free(zero_bitmap_compressed);
    return ret;
}

static int
uxenvm_loadvm_execute_finish(char **err_msg)
{
    QEMUFile *mf = NULL;
    int ret;

    if (dm_state_load_size) {
	mf = qemu_memopen(dm_state_load_buf, dm_state_load_size, "rb");
	if (mf == NULL) {
	    asprintf(err_msg, "qemu_memopen(dm_state_load_buf, %d) failed",
		     dm_state_load_size);
	    ret = -ENOMEM;
	    goto out;
	}
	ret = qemu_loadvm_state(mf);
	if (ret < 0) {
	    asprintf(err_msg, "qemu_loadvm_state() failed");
	    goto out;
	}
    }

    vm_time_update();

    ret = 0;

  out:
    if (mf)
	qemu_fclose(mf);
    if (dm_state_load_buf) {
	free(dm_state_load_buf);
	dm_state_load_buf = NULL;
	dm_state_load_size = 0;
    }
    return ret;
}

int
vm_lazy_load_page(uint32_t gpfn, uint8_t *va, int compressed)
{
    int ret;
    uint64_t offset;
    static int lazy_compressed = 0;

    if (gpfn >= PCI_HOLE_START_PFN && gpfn < PCI_HOLE_END_PFN)
        errx(1, "%s: gpfn %x in pci hole", __FUNCTION__, gpfn);
    if (gpfn >= dm_lazy_load_info.max_gpfn)
        errx(1, "%s: gpfn %x too large, max_gpfn %x", __FUNCTION__,
             gpfn, dm_lazy_load_info.max_gpfn);

    offset = dm_lazy_load_info.pfn_off[skip_pci_hole(gpfn)];

    /* dprintf("%s: gpfn %x at file offset %"PRIu64" to %p\n", __FUNCTION__, */
    /*         gpfn, offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK, va); */

    filebuf_seek(dm_lazy_load_info.fb, offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK,
                 FILEBUF_SEEK_SET);

    if (offset & PAGE_OFFSET_INDEX_PFN_OFF_COMPRESSED) {
        cs16_t cs1;
        ret = filebuf_read(dm_lazy_load_info.fb, &cs1, sizeof(cs1));
        if (ret != sizeof(cs1)) {
            ret = -errno;
            warn("%s: filebuf_read(lazy load page) gpfn %x offset %"PRIu64
                 " read page size failed", __FUNCTION__, gpfn,
                 offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK);
            goto out;
        }
        if (cs1 > PAGE_SIZE) {
            warnx("%s: filebuf_read(lazy load page) gpfn %x offset %"PRIu64
                  " invalid size: %d", __FUNCTION__, gpfn,
                  offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK, cs1);
            ret = -EINVAL;
            goto out;
        }
        if (cs1 == PAGE_SIZE) {
            /* this codepath should not be taken, unless the save file
             * doesn't have the optimisation to not set
             * LAZY_LOAD_PFN_OFF_COMPRESSED for compressed in vain pages */
            ret = filebuf_read(dm_lazy_load_info.fb, va, PAGE_SIZE);
            if (ret != PAGE_SIZE) {
                ret = -errno;
                warn("%s: filebuf_read(lazy load page) gpfn %x offset %"PRIu64
                     " read %ld failed", __FUNCTION__, gpfn,
                     offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK, PAGE_SIZE);
            }
            goto out;
        }
        if (lazy_compressed && compressed && cs1 <= (PAGE_SIZE - 256)) {
            /* load compressed data, decompress in uxen */
            ret = filebuf_read(dm_lazy_load_info.fb, va, cs1);
            if (ret != cs1) {
                ret = -errno;
                warn("%s: filebuf_read(lazy load page) gpfn %x offset %"PRIu64
                     " read %d failed", __FUNCTION__, gpfn,
                     offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK, cs1);
                goto out;
            }
        } else {
            char page[PAGE_SIZE];
            ret = filebuf_read(dm_lazy_load_info.fb, &page[0], cs1);
            if (ret != cs1) {
                ret = -errno;
                warn("%s: filebuf_read(lazy load page) gpfn %x offset %"PRIu64
                     " read %d failed", __FUNCTION__, gpfn,
                     offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK, cs1);
                goto out;
            }
            ret = LZ4_decompress_safe(&page[0], (char *)va, cs1, PAGE_SIZE);
            if (ret != PAGE_SIZE) {
                ret = -EINVAL;
                warnx("%s: decompress gpfn %x offset %"PRIu64" failed",
                      __FUNCTION__, gpfn,
                      offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK);
                goto out;
            }
            ret = PAGE_SIZE;
        }
    } else {
        ret = filebuf_read(dm_lazy_load_info.fb, va, PAGE_SIZE);
        if (ret != PAGE_SIZE) {
            ret = -errno;
            warn("%s: filebuf_read(lazy load page) gpfn %x offset %"PRIu64
                 " failed", __FUNCTION__, gpfn,
                 offset & PAGE_OFFSET_INDEX_PFN_OFF_MASK);
        }
    }

  out:
    return ret;
}

/* 
 * globals used:
 * xc_handle: xc interface handle
 * vm_id: domain id
 * debug_printf: output error message
 * awaiting_suspend: flag indicating that suspend has been requested
 */
void
vm_save(void)
{
    char *err_msg = NULL;
    int ret;

    /* XXX init debug option */
    if (!whpx_enable && strstr(uxen_opt_debug, ",compbatch,"))
        vm_save_info.single_page = 0;
    vm_save_info.fingerprint = (!vm_template_file || compression_is_cuckoo());

    ioh_event_init(&vm_save_info.save_abort_event);

    vm_save_info.save_abort = 0;
    vm_save_info.safe_to_abort = 0;

    vm_save_info.awaiting_suspend = 1;
    vm_set_run_mode(SUSPEND_VM);

    ret = uxenvm_savevm_initiate(&err_msg);
    if (ret) {
	if (err_msg)
            EPRINTF("%s: ret %d", err_msg, ret);
	return;
    }
}

#ifdef MONITOR
void
mc_savevm(Monitor *mon, const dict args)
{
    const char *filename;
    const char *c;

    filename = dict_get_string(args, "filename");
    vm_save_info.filename = filename ? strdup(filename) : NULL;

    vm_save_info.compress_mode = VM_SAVE_COMPRESS_NONE;
    c = dict_get_string(args, "compress");
    if (c) {
        if (!strcmp(c, "lz4"))
            vm_save_info.compress_mode = VM_SAVE_COMPRESS_LZ4;
#ifdef SAVE_CUCKOO_ENABLED
        else if (!strcmp(c, "cuckoo"))
          vm_save_info.compress_mode = VM_SAVE_COMPRESS_CUCKOO;
        else if (!strcmp(c, "cuckoo-simple"))
          vm_save_info.compress_mode = VM_SAVE_COMPRESS_CUCKOO_SIMPLE;
#endif
    }

    vm_save_info.single_page = dict_get_boolean_default(args, "single-page", 1);
    vm_save_info.free_mem = dict_get_boolean_default(args, "free-mem", 1);
    vm_save_info.high_compress = dict_get_boolean_default(args,
                                                          "high-compress", 0);

    vm_save();
}

void
mc_resumevm(Monitor *mon, const dict args)
{

    vm_save_info.resume_delete =
        dict_get_boolean_default(args, "delete-savefile", 1);

    vm_save_abort();
}
#endif  /* MONITOR */

int
vm_process_suspend(xc_dominfo_t *info)
{
    if (!whpx_enable) { /* no xc_dominfo_t on whpx */
        if (!info->shutdown || info->shutdown_reason != SHUTDOWN_suspend)
            return 0;
    }

    APRINTF("vm is suspended");

    vm_save_info.save_requested = 1;
    vm_save_info.awaiting_suspend = 0;
    control_send_status("vm-runstate", "suspended", NULL);

    return 1;
}

char *vm_save_file_name(const uuid_t uuid)
{
    char *fn;
    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);
    asprintf(&fn, "%s%s.save", save_file_prefix, uuid_str);
    return fn;
}

char *vm_save_file_temp_filename(char *name)
{
    char *fn;
    asprintf(&fn, "%s.temp", name);
    return fn;
}

#define ERRMSG(fmt, ...) do {			 \
	EPRINTF(fmt, ## __VA_ARGS__);		 \
	asprintf(&err_msg, fmt, ## __VA_ARGS__); \
    } while (0)

void
vm_save_execute(void)
{
    struct filebuf *f = NULL;
    char *err_msg = NULL;
    uint8_t *dm_state_buf = NULL;
    int dm_state_size;
    struct cuckoo_page_fingerprint *hashes = NULL;
    int ret;

    if (!vm_save_info.filename)
        vm_save_info.filename = vm_save_file_name(vm_uuid);

    APRINTF("device model saving state: %s", vm_save_info.filename);

    if (!vm_save_info.save_via_temp)
        f = filebuf_open(vm_save_info.filename, "wb");
    else {
        char *temp = vm_save_file_temp_filename(vm_save_info.filename);
        f = filebuf_open(temp, "wb");
        free(temp);
    }
    if (f == NULL) {
	ret = errno;
	ERRMSG("filebuf_open(%s) failed", vm_save_info.filename);
	goto out;
    }
    filebuf_delete_on_close(f, 1);
    vm_save_info.f = f;

    ret = uxenvm_savevm_get_dm_state(&dm_state_buf, &dm_state_size, &err_msg);
    if (ret) {
	if (!err_msg)
	    asprintf(&err_msg, "uxenvm_savevm_get_dm_state() failed");
        EPRINTF("%s: ret %d", err_msg, ret);
	ret = -ret;
	goto out;
    }

    ret = uxenvm_savevm_write_info(f, dm_state_buf, dm_state_size, &err_msg);
    if (ret) {
	if (!err_msg)
	    asprintf(&err_msg, "uxenvm_savevm_write_info() failed");
        EPRINTF("%s: ret %d", err_msg, ret);
	ret = -ret;
	goto out;
    }

    while (!check_aborted()) {
        off_t o = filebuf_tell(f);
        ret = !whpx_enable
            ? uxenvm_savevm_write_pages(f, &err_msg)
            : whpx_write_pages(f);
        if (ret && compression_is_cuckoo()) {
            if (ret == -ENOSPC)
                vm_save_info.compress_mode = VM_SAVE_COMPRESS_LZ4;
            else if (ret == -EINTR) {
                vm_save_info.free_mem = 0;
                ret = 0;
                break;
            } else if (ret != -EAGAIN)
                break;
            filebuf_seek(f, o, FILEBUF_SEEK_SET);
        } else
            break;
    }

    if (ret) {
        if (!err_msg)
            asprintf(&err_msg, "uxenvm_savevm_write_pages() failed");
        EPRINTF("%s: ret %d", err_msg, ret);
        ret = -ret;
        goto out;
    }

  out:

    if (ret == 0) {
        APRINTF("total file size: %"PRIu64" bytes", (uint64_t)filebuf_tell(f));
        filebuf_flush(f);
        if (vm_save_info.save_via_temp) {
            filebuf_delete_on_close(f, 0);
            filebuf_close(f);
#ifdef _WIN32
            char *temp = vm_save_file_temp_filename(vm_save_info.filename);
            if (!MoveFileEx(temp, vm_save_info.filename, MOVEFILE_REPLACE_EXISTING))
                debug_printf("MoveFile failed: %x\n", (int)GetLastError());
#endif
            /* reopen for potential resume */
            vm_save_info.f = filebuf_open(vm_save_info.filename, "rb");
        }
    } else {
        if (f)
            filebuf_close(f);
        f = vm_save_info.f = NULL;
    }

    if (vm_save_info.command_cd)
	control_command_save_finish(ret, err_msg);
    free(hashes);
    if (dm_state_buf)
        free(dm_state_buf);
    if (err_msg)
	free(err_msg);
    free(vm_save_info.filename);
    vm_save_info.filename = NULL;
    ioh_event_set(&vm_save_info.save_abort_event);
    ioh_event_close(&vm_save_info.save_abort_event);
}

void
vm_save_finalize(void)
{
    if (vm_save_info.f) {
        if (!vm_quit_interrupt)
            filebuf_delete_on_close(vm_save_info.f, 0);
        filebuf_close(vm_save_info.f);
        vm_save_info.f = NULL;
    }
}

static int
vm_restore_memory(void)
{
    struct filebuf *f;
    xen_pfn_t *pfn_type = NULL;
    int *pfn_err = NULL, *pfn_info = NULL;
    struct decompress_ctx dc = { };
    int populate_compressed = 0;
    int32_t marker;
    struct xc_save_generic s_generic;
#ifdef SAVE_CUCKOO_ENABLED
    struct xc_save_cuckoo_data s_cuckoo;
#endif
    struct xc_save_whp_pages s_whppages;
    char *err_msg = NULL;
#ifdef VERBOSE
    int count = 0;
#endif  /* VERBOSE */
    int ret = 0;

    if (!vm_save_info.f)
        errx(1, "%s: no file", __FUNCTION__);
    f = vm_save_info.f;

    if (!vm_save_info.page_batch_offset)
        errx(1, "%s: no page batch offset", __FUNCTION__);

    ret = filebuf_seek(f, vm_save_info.page_batch_offset,
                       FILEBUF_SEEK_SET) != -1 ? 0 : -1;
    if (ret < 0) {
        asprintf(&err_msg, "filebuf_seek(vm_page_offsets) failed");
        goto out;
    }

    ret = uxenvm_load_alloc(&pfn_type, &pfn_err, &pfn_info, &err_msg);
    if (ret < 0)
        goto out;

    while (1) {
        uxenvm_load_read(f, &marker, sizeof(marker), ret, &err_msg, out);
	if (marker == 0)	/* end marker */
	    break;
        switch (marker) {
        case XC_SAVE_ID_PAGE_OFFSETS:
        case XC_SAVE_ID_ZERO_BITMAP:
        case XC_SAVE_ID_FINGERPRINTS:
            uxenvm_load_read_struct(f, s_generic, marker, ret, &err_msg,
                                    out);
            ret = filebuf_seek(f, s_generic.size - sizeof(s_generic),
                               FILEBUF_SEEK_CUR) != -1 ? 0 : -EIO;
            if (ret < 0) {
                asprintf(&err_msg, "filebuf_seek(%d, SEEK_CUR) failed",
                         s_generic.size);
                goto out;
            }
            break;
#ifdef SAVE_CUCKOO_ENABLED
        case XC_SAVE_ID_CUCKOO_DATA:
            uxenvm_load_read_struct(f, s_cuckoo, marker, ret, &err_msg, out);
            ret = load_cuckoo_pages(f, 1, s_cuckoo.simple_mode);
            goto out;
#endif
        case XC_SAVE_ID_WHP_PAGES:
            uxenvm_load_read_struct(f, s_whppages, marker, ret, &err_msg, out);
            ret = load_whp_pages(f, vm_restore_mode, &s_whppages);
            goto out;
        default:
            ret = uxenvm_load_batch(f, marker, pfn_type, pfn_err, pfn_info,
                                    &dc, 0 /* lazy_load */, populate_compressed,
                                    &err_msg);
            if (ret)
                goto out;
#ifdef VERBOSE
            while (marker > MAX_BATCH_SIZE)
                marker -= MAX_BATCH_SIZE;
            count += marker;
#endif  /* VERBOSE */
            break;
        }
    }
#ifdef VERBOSE
    DPRINTF("%s: %d pages", __FUNCTION__, count);
#endif  /* VERBOSE */

  out:
#ifndef DECOMPRESS_THREADED
    if (HYPERCALL_BUFFER_ARGUMENT_BUFFER(dc.pp_buffer))
        xc__hypercall_buffer_free_pages(xc_handle, dc.pp_buffer,
                                        PP_BUFFER_PAGES);
#else  /* DECOMPRESS_THREADED */
    if (dc.async_op_ctx)
        (void)decompress_wait_all(&dc, NULL);
#endif  /* DECOMPRESS_THREADED */
    free(pfn_err);
    free(pfn_info);
    free(pfn_type);
    if (ret < 0 && err_msg)
        EPRINTF("%s: ret %d", err_msg, ret);
    free(err_msg);
    return ret;
}

int
vm_load(const char *name, int restore_mode)
{
    struct filebuf *f;
    char *err_msg = NULL;
    int ret = 0;

    APRINTF("device model loading state: %s", name);

    f = filebuf_open(name, "rb");
    if (f == NULL) {
	ret = -errno;
        asprintf(&err_msg, "filebuf_open(%s) failed", name);
        EPRINTF("%s: ret %d", err_msg, ret);
	goto out;
    }

    ret = uxenvm_loadvm_execute(f, restore_mode, &err_msg);
    if (ret) {
	if (err_msg)
            EPRINTF("%s: ret %d", err_msg, ret);
	goto out;
    }

    /* 1st generation clone, record name as template filename */
    if (restore_mode == VM_RESTORE_CLONE && !vm_template_file)
        vm_template_file = strdup(name);

  out:
    filebuf_close(f);

    if (ret) {
        _set_errno(-ret);
        return -1;
    }
    return 0;
}

int
vm_load_finish(void)
{
    char *err_msg = NULL;
    int ret;

    ret = uxenvm_loadvm_execute_finish(&err_msg);
    if (ret) {
	if (err_msg)
            EPRINTF("%s: ret %d", err_msg, ret);
    }

    return ret;
}

int
vm_resume(void)
{
    int ret;
    char *err_msg = NULL;

    if (vm_save_info.f) {

        filebuf_set_readable(vm_save_info.f);

        if (vm_save_info.free_mem)
            vm_restore_memory();

        qemu_savevm_resume();

        if (!vm_save_info.resume_delete)
            filebuf_delete_on_close(vm_save_info.f, 0);
        filebuf_close(vm_save_info.f);
        vm_save_info.f = NULL;
    }

    ret = !whpx_enable
        ? xc_domain_resume(xc_handle, vm_id)
        : whpx_vm_resume();
    if (ret) {
        if (!err_msg)
            asprintf(&err_msg, "xc_domain_resume failed");
        EPRINTF("%s: ret %d", err_msg, -ret);
        ret = -ret;
        goto out;
    }

  out:
    if (vm_save_info.resume_cd)
        control_command_resume_finish(ret, err_msg);
    return ret;
}
