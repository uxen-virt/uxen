/*
 * Copyright 2012-2015, Bromium, Inc.
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
#include "control.h"
#include "dm.h"
#include "dmpdev.h"
#include "filebuf.h"
#include "introspection_info.h"
#include "monitor.h"
#include "qemu_savevm.h"
#include "vm.h"
#include "vm-save.h"
#include "uxen.h"
#include "hw/uxen_platform.h"
#include "mapcache.h"

#include <lz4.h>

#include <xenctrl.h>
#include <xc_private.h>

#define SAVE_FORMAT_VERSION 3

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

// #include <xg_save_restore.h>
#define XC_SAVE_ID_VCPU_INFO          -2 /* Additional VCPU info */
#define XC_SAVE_ID_HVM_IDENT_PT       -3 /* (HVM-only) */
#define XC_SAVE_ID_HVM_VM86_TSS       -4 /* (HVM-only) */
#define XC_SAVE_ID_TSC_INFO           -7
#define XC_SAVE_ID_HVM_CONSOLE_PFN    -8 /* (HVM-only) */
#define XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION -10
#define XC_SAVE_ID_HVM_MAGIC_PFNS     -11
#define XC_SAVE_ID_HVM_CONTEXT        -12
#define XC_SAVE_ID_HVM_DM             -13
#define XC_SAVE_ID_VM_UUID            -14
#define XC_SAVE_ID_VM_TEMPLATE_UUID   -15
#define XC_SAVE_ID_VERSION            -16
#define XC_SAVE_ID_HVM_INTROSPEC      -17
#define XC_SAVE_ID_MAPCACHE_PARAMS    -18
#define XC_SAVE_ID_VM_TEMPLATE_FILE   -19

struct vm_save_info vm_save_info = { };

static int
uxenvm_savevm_initiate(char **err_msg)
{
    int ret;

    ret = xc_domain_shutdown(xc_handle, vm_id, SHUTDOWN_suspend);
    if (ret)
	asprintf(err_msg, "xc_domain_shutdown(SHUTDOWN_suspend) failed: %d",
		 ret);

    return ret;
}

struct xc_save_version_info {
    int marker;
    uint32_t version;
};

struct xc_save_tsc_info {
    int marker;
    uint32_t tsc_mode;
    uint64_t nsec;
    uint32_t khz;
    uint32_t incarn;
};

struct xc_save_vcpu_info {
    int marker;
    int max_vcpu_id;
    uint64_t vcpumap;
};

struct xc_save_hvm_generic_chunk {
    int marker;
    uint32_t pad;
    uint64_t data;
};

struct xc_save_hvm_magic_pfns {
    int marker;
    uint64_t magic_pfns[3];
};

struct xc_save_hvm_context {
    int marker;
    uint32_t size;
    uint8_t context[];
};

struct xc_save_hvm_dm {
    int marker;
    uint32_t size;
    uint8_t state[];
};

struct xc_save_vm_uuid {
    int marker;
    uint8_t uuid[16];
};

struct xc_save_vm_template_uuid {
    int marker;
    uint8_t uuid[16];
};

struct xc_save_hvm_introspec {
    int marker;
    struct guest_introspect_info_header info;
};

struct xc_save_mapcache_params {
    int marker;
    uint32_t end_low_pfn;
    uint32_t start_high_pfn;
    uint32_t end_high_pfn;
};

struct xc_save_vm_template_file {
    int marker;
    uint16_t size;
    char file[];
};

#define MAX_BATCH_SIZE 1023

typedef uint16_t cs16_t;

#define PP_BUFFER_PAGES                                                 \
    (int)((MAX_BATCH_SIZE * (sizeof(cs16_t) + PAGE_SIZE) + PAGE_SIZE - 1) \
          >> PAGE_SHIFT)

#define uxenvm_read_struct_size(s) (sizeof(*(s)) - sizeof(marker))
#define uxenvm_read_struct(f, s)                                        \
    filebuf_read(f, (uint8_t *)(s) + sizeof(marker),                    \
                 uxenvm_read_struct_size(s))

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
    struct xc_save_tsc_info s_tsc_info;
    struct xc_save_vcpu_info s_vcpu_info;
    struct xc_save_hvm_generic_chunk s_hvm_ident_pt;
    struct xc_save_hvm_generic_chunk s_hvm_vm86_tss;
    struct xc_save_hvm_generic_chunk s_hvm_console_pfn;
    struct xc_save_hvm_generic_chunk s_hvm_acpi_ioports_location;
    struct xc_save_hvm_magic_pfns s_hvm_magic_pfns;
    struct xc_save_hvm_context s_hvm_context;
    struct xc_save_hvm_dm s_hvm_dm;
    struct xc_save_vm_uuid s_vm_uuid;
    struct xc_save_vm_template_uuid s_vm_template_uuid;
    struct xc_save_mapcache_params s_mapcache_params;
    struct xc_save_vm_template_file s_vm_template_file;
    int j;
    int ret;

    s_version_info.marker = XC_SAVE_ID_VERSION;
    s_version_info.version = SAVE_FORMAT_VERSION;
    filebuf_write(f, &s_version_info, sizeof(s_version_info));

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

    s_hvm_ident_pt.marker = XC_SAVE_ID_HVM_IDENT_PT;
    s_hvm_ident_pt.data = 0;
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_IDENT_PT,
		     &s_hvm_ident_pt.data);
    APRINTF("ident_pt %"PRIx64, s_hvm_ident_pt.data);
    if (s_hvm_ident_pt.data)
	filebuf_write(f, &s_hvm_ident_pt, sizeof(s_hvm_ident_pt));

    s_hvm_vm86_tss.marker = XC_SAVE_ID_HVM_VM86_TSS;
    s_hvm_vm86_tss.data = 0;
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_VM86_TSS,
		     &s_hvm_vm86_tss.data);
    APRINTF("vm86_tss %"PRIx64, s_hvm_vm86_tss.data);
    if (s_hvm_vm86_tss.data)
	filebuf_write(f, &s_hvm_vm86_tss, sizeof(s_hvm_vm86_tss));

    s_hvm_console_pfn.marker = XC_SAVE_ID_HVM_CONSOLE_PFN;
    s_hvm_console_pfn.data = 0;
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_CONSOLE_PFN,
		     &s_hvm_console_pfn.data);
    APRINTF("console_pfn %"PRIx64, s_hvm_console_pfn.data);
    if (s_hvm_console_pfn.data)
	filebuf_write(f, &s_hvm_console_pfn, sizeof(s_hvm_console_pfn));

    s_hvm_acpi_ioports_location.marker = XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION;
    s_hvm_acpi_ioports_location.data = 0;
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_ACPI_IOPORTS_LOCATION,
		     &s_hvm_acpi_ioports_location.data);
    APRINTF("acpi_ioports_location %"PRIx64, s_hvm_acpi_ioports_location.data);
    if (s_hvm_acpi_ioports_location.data)
	filebuf_write(f, &s_hvm_acpi_ioports_location,
                      sizeof(s_hvm_acpi_ioports_location));

    s_hvm_magic_pfns.marker = XC_SAVE_ID_HVM_MAGIC_PFNS;
    memset(s_hvm_magic_pfns.magic_pfns, 0, sizeof(s_hvm_magic_pfns.magic_pfns));
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_IO_PFN_FIRST,
		     &s_hvm_magic_pfns.magic_pfns[0]);
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_IO_PFN_LAST,
		     &s_hvm_magic_pfns.magic_pfns[1]);
    xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_SHARED_INFO_PFN,
		     &s_hvm_magic_pfns.magic_pfns[2]);
    APRINTF("ioreq pfn %"PRIx64"-%"PRIx64
            " shared info pfn %"PRIx64, s_hvm_magic_pfns.magic_pfns[0],
            s_hvm_magic_pfns.magic_pfns[1], s_hvm_magic_pfns.magic_pfns[2]);
    filebuf_write(f, &s_hvm_magic_pfns, sizeof(s_hvm_magic_pfns));

    hvm_buf_size = xc_domain_hvm_getcontext(xc_handle, vm_id, 0, 0);
    if (hvm_buf_size == -1) {
	asprintf(err_msg, "xc_domain_hvm_getcontext(0, 0) failed");
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
    s_hvm_context.size = xc_domain_hvm_getcontext(xc_handle, vm_id,
						  hvm_buf, hvm_buf_size);
    if (s_hvm_context.size == -1) {
	asprintf(err_msg, "xc_domain_hvm_getcontext(%d) failed", hvm_buf_size);
	ret = -EPERM;
	goto out;
    }
    APRINTF("hvm rec size %d", s_hvm_context.size);
    filebuf_write(f, &s_hvm_context, sizeof(s_hvm_context));
    filebuf_write(f, hvm_buf, s_hvm_context.size);

#if defined(_WIN32)
    /* "set_introspect_info" should be set for template only (last boot)*/
    if (strstr(lava_options, "set_introspect_info")) {
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

static int
uxenvm_savevm_write_pages(struct filebuf *f, int compress, int free_after_save,
                          int single_page, char **err_msg)
{
    uint8_t *hvm_buf = NULL;
    int p2m_size, pfn, batch, _batch, run, b_run, m_run, v_run, rezero, clone;
    int total_pages = 0, total_zero = 0, total_rezero = 0, total_clone = 0;
    int total_compressed_pages = 0, total_compress_in_vain = 0;
    size_t total_compress_save = 0;
    int j;
    xen_pfn_t *free_pfns = NULL;
    xen_pfn_t *pfn_type = NULL;
    int *pfn_err = NULL;
    int *pfn_zero = NULL;
    int zero_batch = 0;
    int map_err;
    uint8_t *mem = NULL;
    int mem_nr = 0;
    int free_nr = 0;
    char *compress_mem = NULL;
    char *compress_buf = NULL;
    uint32_t compress_size = 0;
    int ret;

    p2m_size = xc_domain_maximum_gpfn(xc_handle, vm_id);
    if (p2m_size < 0) {
	asprintf(err_msg, "xc_domain_maximum_gpfn() failed");
	ret = -EPERM;
	goto out;
    }
    p2m_size++;
    APRINTF("p2m_size: 0x%x", p2m_size);

    pfn_type = malloc(MAX_BATCH_SIZE * sizeof(*pfn_type));
    if (pfn_type == NULL) {
	asprintf(err_msg, "pfn_type = malloc(%"PRIdSIZE") failed",
		 MAX_BATCH_SIZE * sizeof(*pfn_type));
	ret = -ENOMEM;
	goto out;
    }

    if (free_after_save) {
        free_pfns = malloc(MAX_BATCH_SIZE * sizeof(*free_pfns));
        if (free_pfns == NULL) {
            asprintf(err_msg, "free_pfns = malloc(%"PRIdSIZE") failed",
                     MAX_BATCH_SIZE * sizeof(*free_pfns));
            ret = -ENOMEM;
            goto out;
        }
    }

    pfn_err = malloc(MAX_BATCH_SIZE * sizeof(*pfn_err));
    if (pfn_err == NULL) {
	asprintf(err_msg, "pfn_err = malloc(%"PRIdSIZE") failed",
		 MAX_BATCH_SIZE * sizeof(*pfn_err));
	ret = -ENOMEM;
	goto out;
    }

    pfn_zero = malloc(MAX_BATCH_SIZE * sizeof(*pfn_zero));
    if (pfn_zero == NULL) {
        asprintf(err_msg, "pfn_zero = malloc(%"PRIdSIZE") failed",
                 MAX_BATCH_SIZE * sizeof(*pfn_zero));
        ret = -ENOMEM;
        goto out;
    }

    if (compress && !single_page) {
        /* The LZ4_compressBound macro is unsafe, so we have to wrap the
         * argument. */
        compress_buf =
            (char *)malloc(LZ4_compressBound((MAX_BATCH_SIZE << PAGE_SHIFT)));
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
    } else if (compress && single_page) {
        compress_buf = (char *)malloc(
            sizeof(compress_size) +
            MAX_BATCH_SIZE * (sizeof(cs16_t) + PAGE_SIZE));
        if (!compress_buf) {
            asprintf(err_msg, "malloc(compress_buf) failed");
            ret = -ENOMEM;
            goto out;
        }
    }

    /* store start of batch file offset, to allow restoring page data
     * without parsing the entire save file */
    vm_save_info.page_batch_offset = filebuf_tell(f);

    pfn = 0;
    while (pfn < p2m_size && !vm_save_info.save_abort && !vm_quit_interrupt) {
	batch = 0;
	while ((pfn + batch) < p2m_size && batch < MAX_BATCH_SIZE) {
	    pfn_type[batch] = pfn + batch;
	    batch++;
	}
	if (mem)
	    xc_munmap(xc_handle, vm_id, mem, mem_nr * PAGE_SIZE);
	mem = xc_map_foreign_bulk(xc_handle, vm_id, PROT_READ,
				  pfn_type, pfn_err, batch);
	if (mem == NULL) {
	    asprintf(err_msg, "xc_map_foreign_bulk(%d, %d) failed",
		     pfn, batch);
	    ret = -EPERM;
	    goto out;
	}
	mem_nr = batch;
	ret = xc_get_pfn_type_batch(xc_handle, vm_id, batch, pfn_type);
	if (ret) {
	    asprintf(err_msg, "xc_get_pfn_type_batch(%d, %d) failed",
		     pfn, batch);
	    ret = -EPERM;
	    goto out;
	}
	rezero = 0;
	clone = 0;
        _batch = 0;
	for (j = 0; j < batch; j++) {
	    map_err = pfn_err[j];
            if (!map_err && !pfn_type[j] && free_after_save)
                free_pfns[free_nr++] = pfn + j;
	    if (!map_err && !pfn_type[j]) {
		uint64_t *p = (uint64_t *)&mem[j << PAGE_SHIFT];
		int i = 0;
		while (i < (PAGE_SIZE >> 3) && !p[i])
		    i++;
		if (i == (PAGE_SIZE >> 3)) {
		    pfn_type[j] = XEN_DOMCTL_PFINFO_XALLOC;
		    rezero++;
                    total_rezero++;
                    map_err = 1;
		}
            }
            if (!map_err && !pfn_type[j]) {
                pfn_err[_batch] = pfn + j;
                _batch++;
            } else if (map_err && pfn_type[j] == XEN_DOMCTL_PFINFO_XALLOC) {
		map_err = 0;
                pfn_zero[zero_batch] = pfn_type[j] | (pfn + j);
                zero_batch++;
                if (zero_batch == MAX_BATCH_SIZE) {
                    int _zero_batch = zero_batch + 3 * MAX_BATCH_SIZE;
                    filebuf_write(f, &_zero_batch, sizeof(zero_batch));
                    filebuf_write(f, &pfn_zero[0],
                                  zero_batch * sizeof(pfn_zero[0]));
                    zero_batch = 0;
                }
                total_zero++;
            } else if (pfn_type[j] == XEN_DOMCTL_PFINFO_XPOD) {
                /* ignore map errors -- PROT_READ mapped pod pages are
                 * only mapped if they are not cow */
                map_err = 0;
		clone++;
                total_clone++;
            }
	    if (map_err) {
		if (pfn_type[j] == XEN_DOMCTL_PFINFO_XTAB)
		    continue;
		EPRINTF("map fail: gpfn %08x err %d type %"PRIx64, pfn + j,
			map_err, pfn_type[j]);
		pfn_type[j] = XEN_DOMCTL_PFINFO_XTAB;
		continue;
	    }
	    if (pfn_type[j] == XEN_DOMCTL_PFINFO_XTAB) {
		EPRINTF("type fail: gpfn %08x", pfn + j);
		continue;
	    }
	}
        if (_batch) {
            SAVE_DPRINTF("page batch %08x:%08x = %03x pages,"
                         " rezero %03x, clone %03x",
                         pfn, pfn + batch, _batch, rezero, clone);
            if (compress)
                _batch += single_page ? 2 * MAX_BATCH_SIZE : MAX_BATCH_SIZE;
            filebuf_write(f, &_batch, sizeof(_batch));
            if (compress)
                _batch -= single_page ? 2 * MAX_BATCH_SIZE : MAX_BATCH_SIZE;
            filebuf_write(f, pfn_err, _batch * sizeof(pfn_err[0]));
            if (compress && single_page)
                compress_size = 0;
            j = 0;
            m_run = 0;
            v_run = 0;
            while (j != batch) {
                while (j != batch && pfn_type[j])
                    j++;
                run = j;
                while (j != batch && !pfn_type[j])
                    j++;
                if (run != j) {
                    b_run = j - run;
                    SAVE_DPRINTF(
                        "     write %08x:%08x = %03x pages",
                        pfn + run, pfn + j, b_run);
                    if (!compress)
                        filebuf_write(f, &mem[run << PAGE_SHIFT],
                                      b_run << PAGE_SHIFT);
                    else {
                        if (single_page) {
                            int i, cs1;
                            for (i = 0; i < b_run; i++) {
                                cs1 = LZ4_compress(
                                    (const char *)&mem[(run + i) << PAGE_SHIFT],
                                    &compress_buf[compress_size +
                                                  sizeof(cs16_t)],
                                    PAGE_SIZE);
                                if (cs1 >= PAGE_SIZE) {
                                    memcpy(&compress_buf[compress_size +
                                                         sizeof(cs16_t)],
                                           &mem[(run + i) << PAGE_SHIFT],
                                           PAGE_SIZE);
                                    cs1 = PAGE_SIZE;
                                    v_run++;
                                } else
                                    m_run++;
                                *(cs16_t *)&compress_buf[compress_size] = cs1;
                                compress_size += sizeof(cs16_t) + cs1;
                            }
                        } else {
                            memcpy(&compress_mem[m_run << PAGE_SHIFT],
                                   &mem[run << PAGE_SHIFT],
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
            if (compress) {
                if (!single_page) {
                    compress_size = LZ4_compress(
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
        if (free_nr) {
            xc_domain_populate_physmap(xc_handle, vm_id, free_nr, 0,
                                       XENMEMF_populate_on_demand, free_pfns);
            free_nr = 0;
        }
	pfn += batch;
    }

    if (!vm_save_info.save_abort && !vm_quit_interrupt) {
        if (zero_batch) {
            int _zero_batch = zero_batch + 3 * MAX_BATCH_SIZE;
            filebuf_write(f, &_zero_batch, sizeof(zero_batch));
            filebuf_write(f, &pfn_zero[0],
                          zero_batch * sizeof(pfn_zero[0]));
        }
    }

    if (!vm_save_info.save_abort && !vm_quit_interrupt) {
        /* 0: end marker */
        batch = 0;
        filebuf_write(f, &batch, sizeof(batch));

        APRINTF("memory: pages %d zero %d rezero %d clone %d", total_pages,
                total_zero - total_rezero, total_rezero, total_clone);
        if (compress && total_pages) {
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
    if (mem)
	xc_munmap(xc_handle, vm_id, mem, mem_nr * PAGE_SIZE);
    free(pfn_zero);
    free(pfn_err);
    free(pfn_type);
    free(free_pfns);
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
uxenvm_load_zerobatch(struct filebuf *f, int batch, xen_pfn_t *pfn_type,
                      int *pfn_zero, char **err_msg)
{
    int j;
    int ret;

    LOAD_DPRINTF("zero batch %03x pages", batch);

    uxenvm_load_read(f, &pfn_zero[0], batch * sizeof(pfn_zero[0]),
                     ret, err_msg, out);

    for (j = 0; j < batch; j++)
        pfn_type[j] = pfn_zero[j] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;

    ret = xc_domain_populate_physmap_exact(
        xc_handle, vm_id, batch, 0, XENMEMF_populate_on_demand, &pfn_type[0]);
    if (ret) {
        asprintf(err_msg, "xc_domain_populate_physmap_exact failed");
        goto out;
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
                ret = LZ4_decompress_fast(&compress_buf[decompress_pos],
                                          (char *)&mem[i << PAGE_SHIFT],
                                          PAGE_SIZE);
                if (ret != cs1) {
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
        ret = LZ4_decompress_fast(compress_buf, (char *)mem,
                                  batch << PAGE_SHIFT);
        if (ret != compress_size) {
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
                      int populate_compressed, char **err_msg)
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

    for (j = 0; j < batch; j++)
	pfn_type[j] = pfn_info[j] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;

    if (decompress) {
        uxenvm_load_read(f, &compress_size, sizeof(compress_size),
                         ret, err_msg, out);
        if (compress_size == -1)
            decompress = 0;
    }

    if (!decompress) {
        LOAD_DPRINTF("  populate %08"PRIx64":%08"PRIx64" = %03x pages",
                     pfn_type[0], pfn_type[batch - 1] + 1, batch);
        ret = xc_domain_populate_physmap_exact(
            xc_handle, vm_id, batch, 0, XENMEMF_populate_on_demand,
            &pfn_type[0]);
        if (ret) {
            asprintf(err_msg, "xc_domain_populate_physmap_exact failed");
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
uxenvm_load_batch(struct filebuf *f, int marker, xen_pfn_t *pfn_type,
                  int *pfn_err, int *pfn_info, struct decompress_ctx *dc,
                  int populate_compressed, char **err_msg)
{
    DECLARE_HYPERCALL_BUFFER(uint8_t, pp_buffer);
    int decompress;
    int single_page;
    int zero_batch;
    int ret;

    decompress = 0;
    single_page = 0;
    zero_batch = 0;
    if ((unsigned int)marker > 4 * MAX_BATCH_SIZE) {
        asprintf(err_msg, "invalid batch size: %x",
                 (unsigned int)marker);
        ret = -EINVAL;
        goto out;
    } else if (marker > 3 * MAX_BATCH_SIZE) {
        marker -= 3 * MAX_BATCH_SIZE;
        zero_batch = 1;
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
    if (zero_batch)
        ret = uxenvm_load_zerobatch(f, marker, pfn_type, pfn_info,
                                    err_msg);
    else
        ret = uxenvm_load_readbatch(f, marker, pfn_type, pfn_info,
                                    pfn_err, decompress, dc,
                                    single_page, populate_compressed,
                                    err_msg);
  out:
    return ret;
}

static int
apply_immutable_memory(struct immutable_range *r, int nranges)
{
    int i;

    for (i = 0; i < nranges; i++)
        if (xc_hvm_set_mem_type(xc_handle, vm_id, HVMMEM_ram_immutable,
                                r[i].base, r[i].size))
            EPRINTF("xc_hvm_set_mem_type(HVMMEM_ram_immutable) failed: "
                    "pfn 0x%"PRIx64" size 0x%"PRIx64, r[i].base, r[i].size);
    APRINTF("%s: done", __FUNCTION__);

    return 0;
}

#define uxenvm_load_read_struct(f, s, marker, ret, err_msg, _out) do {	\
        (ret) = uxenvm_read_struct((f), &(s));                          \
        if ((ret) != uxenvm_read_struct_size(&(s))) {                   \
            asprintf((err_msg), "uxenvm_read_struct(%s) failed", #s);   \
	    goto _out;							\
	}								\
	(s).marker = marker;						\
    } while(0)

static uint8_t *dm_state_load_buf = NULL;
static int dm_state_load_size = 0;

static int
uxenvm_loadvm_execute(struct filebuf *f, int restore_mode, char **err_msg)
{
    struct xc_save_version_info s_version_info = { };
    struct xc_save_tsc_info s_tsc_info = { };
    struct xc_save_vcpu_info s_vcpu_info = { };
    struct xc_save_hvm_generic_chunk s_hvm_ident_pt = { };
    struct xc_save_hvm_generic_chunk s_hvm_vm86_tss = { };
    struct xc_save_hvm_generic_chunk s_hvm_console_pfn = { };
    struct xc_save_hvm_generic_chunk s_hvm_acpi_ioports_location = { };
    struct xc_save_hvm_magic_pfns s_hvm_magic_pfns = { };
    struct xc_save_hvm_context s_hvm_context = { };
    struct xc_save_hvm_dm s_hvm_dm = { };
    struct xc_save_vm_uuid s_vm_uuid = { };
    struct xc_save_vm_template_uuid s_vm_template_uuid = { };
    struct xc_save_hvm_introspec s_hvm_introspec = { };
    struct xc_save_mapcache_params s_mapcache_params = { };
    struct xc_save_vm_template_file s_vm_template_file = { };
    struct immutable_range *immutable_ranges = NULL;
    uint8_t *hvm_buf = NULL;
    xen_pfn_t *pfn_type = NULL;
    int *pfn_err = NULL, *pfn_info = NULL;
    struct decompress_ctx dc = { };
    int populate_compressed = (restore_mode == VM_RESTORE_TEMPLATE);
    int marker;
    int ret;
    int size;

    /* XXX init debug option */
    if (strstr(uxen_opt_debug, ",uncomptmpl,"))
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
	case XC_SAVE_ID_HVM_IDENT_PT:
	    uxenvm_load_read_struct(f, s_hvm_ident_pt, marker, ret, err_msg,
				    out);
	    APRINTF("ident_pt %"PRIx64, s_hvm_ident_pt.data);
	    break;
	case XC_SAVE_ID_HVM_VM86_TSS:
	    uxenvm_load_read_struct(f, s_hvm_vm86_tss, marker, ret, err_msg,
				    out);
	    APRINTF("vm86_tss %"PRIx64, s_hvm_vm86_tss.data);
	    break;
	case XC_SAVE_ID_HVM_CONSOLE_PFN:
	    uxenvm_load_read_struct(f, s_hvm_console_pfn, marker, ret, err_msg,
				    out);
	    APRINTF("console_pfn %"PRIx64, s_hvm_console_pfn.data);
	    break;
	case XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION:
	    uxenvm_load_read_struct(f, s_hvm_acpi_ioports_location, marker,
				    ret, err_msg, out);
	    APRINTF("acpi_ioports_location %"PRIx64,
		    s_hvm_acpi_ioports_location.data);
	    break;
	case XC_SAVE_ID_HVM_MAGIC_PFNS:
	    uxenvm_load_read_struct(f, s_hvm_magic_pfns, marker, ret, err_msg,
				    out);
	    APRINTF("ioreq pfn %"PRIx64"-%"PRIx64" shared info pfn %"PRIx64,
                    s_hvm_magic_pfns.magic_pfns[0],
		    s_hvm_magic_pfns.magic_pfns[1],
		    s_hvm_magic_pfns.magic_pfns[2]);
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
            break;
	default:
	    if (restore_mode == VM_RESTORE_CLONE) {
                ret = xc_domain_clone_physmap(xc_handle, vm_id,
                                              vm_template_uuid);
                if (ret < 0) {
                    asprintf(err_msg, "xc_domain_clone_physmap failed");
                    goto out;
                }
		if (!vm_has_template_uuid) {
		    vm_has_template_uuid = 1;
		    ret = 0;
		    goto skip_mem;
		}
		restore_mode = VM_RESTORE_NORMAL;
	    }
            ret = uxenvm_load_batch(f, marker, pfn_type, pfn_err, pfn_info,
                                    &dc, populate_compressed, err_msg);
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
            apply_immutable_memory(immutable_ranges,
                                   s_hvm_introspec.info.n_immutable_ranges);
	goto out;
    }

    if (s_mapcache_params.marker == XC_SAVE_ID_MAPCACHE_PARAMS)
        mapcache_init_restore(s_mapcache_params.end_low_pfn,
                              s_mapcache_params.start_high_pfn,
                              s_mapcache_params.end_high_pfn);
    else
        mapcache_init(vm_mem_mb);
    if (s_tsc_info.marker == XC_SAVE_ID_TSC_INFO)
	xc_domain_set_tsc_info(xc_handle, vm_id, s_tsc_info.tsc_mode,
			       s_tsc_info.nsec, s_tsc_info.khz,
			       s_tsc_info.incarn);
    if (s_vcpu_info.marker == XC_SAVE_ID_VCPU_INFO)
	;
    if (s_hvm_ident_pt.marker == XC_SAVE_ID_HVM_IDENT_PT)
	xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_IDENT_PT,
			 s_hvm_ident_pt.data);
    if (s_hvm_vm86_tss.marker == XC_SAVE_ID_HVM_VM86_TSS)
	xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_VM86_TSS,
			 s_hvm_vm86_tss.data);
    if (s_hvm_console_pfn.marker == XC_SAVE_ID_HVM_CONSOLE_PFN) {
	xc_clear_domain_page(xc_handle, vm_id, s_hvm_console_pfn.data);
	xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_CONSOLE_PFN,
			 s_hvm_console_pfn.data);
    }
    if (s_hvm_acpi_ioports_location.marker ==
	XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION)
	xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_ACPI_IOPORTS_LOCATION,
			 s_hvm_acpi_ioports_location.data);
    if (s_hvm_magic_pfns.marker == XC_SAVE_ID_HVM_MAGIC_PFNS) {
	uint64_t pfn;
	xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_IO_PFN_FIRST,
			 s_hvm_magic_pfns.magic_pfns[0]);
	xc_set_hvm_param(xc_handle, vm_id, HVM_PARAM_IO_PFN_LAST,
			 s_hvm_magic_pfns.magic_pfns[1]);
	for (pfn = s_hvm_magic_pfns.magic_pfns[0];
	     pfn <= s_hvm_magic_pfns.magic_pfns[1]; pfn++)
	    xc_clear_domain_page(xc_handle, vm_id, pfn);
        if (!s_hvm_magic_pfns.magic_pfns[2]) /* XXX ignore 0 for now */
            s_hvm_magic_pfns.magic_pfns[2] = -1;
        if (s_hvm_magic_pfns.magic_pfns[2] != -1) {
            ret = xc_domain_add_to_physmap(xc_handle, vm_id,
                                           XENMAPSPACE_shared_info, 0,
                                           s_hvm_magic_pfns.magic_pfns[2]);
            if (ret < 0) {
                asprintf(err_msg, "add_to_physmap(shared_info) failed");
                goto out;
            }
        }
    }
    if (s_hvm_context.marker == XC_SAVE_ID_HVM_CONTEXT)
	xc_domain_hvm_setcontext(xc_handle, vm_id, hvm_buf, s_hvm_context.size);

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
    if (strstr(uxen_opt_debug, ",compbatch,"))
        vm_save_info.single_page = 0;

    vm_save_info.save_abort = 0;

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

    filename = dict_get_string(args, "filename");
    vm_save_info.filename = filename ? strdup(filename) : NULL;

    vm_save_info.compress = dict_get_string(args, "compress") ? 1 : 0;
    vm_save_info.single_page = dict_get_boolean_default(args, "single-page", 1);
    vm_save_info.free_mem = dict_get_boolean_default(args, "free-mem", 1);

    vm_save();
}

void
mc_resumevm(Monitor *mon, const dict args)
{

    vm_save_info.resume_delete =
        dict_get_boolean_default(args, "delete-savefile", 1);

    vm_set_run_mode(RUNNING_VM);
}
#endif  /* MONITOR */

int
vm_process_suspend(xc_dominfo_t *info)
{
 
    if (!info->shutdown || info->shutdown_reason != SHUTDOWN_suspend)
        return 0;

    vm_save_info.awaiting_suspend = 0;

    APRINTF("vm is suspended");

    vm_save_info.save_requested = 1;

    return 1;
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
    char uuid[37];
    uint8_t *dm_state_buf = NULL;
    int dm_state_size;
    int ret;

    if (!vm_save_info.filename) {
        uuid_unparse_lower(vm_uuid, uuid);
        asprintf(&vm_save_info.filename, "uxenvm-%s.save", uuid);
    }

    APRINTF("device model saving state: %s", vm_save_info.filename);

    f = filebuf_open(vm_save_info.filename, "wb");
    if (f == NULL) {
	ret = errno;
	ERRMSG("filebuf_open(%s) failed", vm_save_info.filename);
	goto out;
    }
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

    ret = uxenvm_savevm_write_pages(f, vm_save_info.compress,
                                    vm_save_info.free_mem,
                                    vm_save_info.single_page, &err_msg);
    if (ret) {
        if (!err_msg)
            asprintf(&err_msg, "uxenvm_savevm_write_pages() failed");
        EPRINTF("%s: ret %d", err_msg, ret);
        ret = -ret;
        goto out;
    }

  out:
    if (vm_save_info.command_cd)
	control_command_save_finish(ret, err_msg);
    if (dm_state_buf)
        free(dm_state_buf);
    if (f)
        filebuf_flush(f);
    if (err_msg)
	free(err_msg);
    free(vm_save_info.filename);
    vm_save_info.filename = NULL;
}

void
vm_save_finalize(void)
{

    if (vm_save_info.f) {
        if (vm_quit_interrupt)
            filebuf_delete_on_close(vm_save_info.f, 1);
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
    int marker;
    char *err_msg = NULL;
#ifdef VERBOSE
    int count = 0;
#endif  /* VERBOSE */
    int ret = 0;

    if (!vm_save_info.f)
        errx(1, "%s: no file", __FUNCTION__);
    f = vm_save_info.f;
    vm_save_info.f = NULL;

    if (!vm_save_info.page_batch_offset)
        errx(1, "%s: no page batch offset", __FUNCTION__);

    filebuf_set_readable(f);

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
        ret = uxenvm_load_batch(f, marker, pfn_type, pfn_err, pfn_info,
                                &dc, populate_compressed, &err_msg);
        if (ret)
            goto out;
#ifdef VERBOSE
        while (marker > MAX_BATCH_SIZE)
            marker -= MAX_BATCH_SIZE;
        count += marker;
#endif  /* VERBOSE */
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
    if (f) {
        if (vm_save_info.resume_delete)
            filebuf_delete_on_close(f, 1);
	filebuf_close(f);
    }
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

    f = filebuf_open(name, restore_mode == VM_RESTORE_TEMPLATE ? "rbn" : "rb");
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
    if (f)
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

    if (vm_save_info.free_mem)
        vm_restore_memory();

    qemu_savevm_resume();

    ret = xc_domain_resume(xc_handle, vm_id);
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
