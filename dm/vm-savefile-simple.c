/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <xc_private.h>

#include "filebuf.h"
#include "vm-savefile.h"

#undef DPRINTF
#undef EPRINTF
#ifdef STDERR_LOG
#define DPRINTF(fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__)
#define EPRINTF(fmt, ...) fprintf(stderr, "ERROR - %s: " fmt "\n", __FUNCTION__, \
                                          ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) debug_printf(fmt "\n", ## __VA_ARGS__)
#define EPRINTF(fmt, ...) error_printf("%s: " fmt "\n", __FUNCTION__, \
                                          ## __VA_ARGS__)
#endif

#if VERBOSE_SAVE
#define SAVE_DPRINTF(fmt, ...) DPRINTF(fmt, ## __VA_ARGS__)
#else
#define SAVE_DPRINTF(...)
#endif

#define MAX_BATCH_SIZE 1023

int
vmsavefile_save_simple(xc_interface *_xc_handle, const char *savefile,
                       uint8_t *uuid, int domid)
{
    struct filebuf *f = NULL;
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
    struct xc_save_vm_uuid s_vm_uuid;
    int p2m_size;
    unsigned int pfn, batch, _batch, run, b_run, rezero;
    int total_pages = 0, total_rezero = 0, total_clone = 0;
    int j;
    xen_pfn_t *pfn_type = NULL;
    int *pfn_err = NULL;
    int *pfn_zero = NULL;
    int zero_batch = 0;
    int map_err;
    uint8_t *mem = NULL;
    int mem_nr;
    int ret;

    f = filebuf_open(savefile, "wb");
    if (f == NULL) {
	ret = errno;
        EPRINTF("filebuf_open(%s) failed", savefile);
	goto out;
    }

    s_version_info.marker = XC_SAVE_ID_VERSION;
    s_version_info.version = SAVE_FORMAT_VERSION;
    filebuf_write(f, &s_version_info, sizeof(s_version_info));

    s_tsc_info.marker = XC_SAVE_ID_TSC_INFO;
    ret = xc_domain_get_tsc_info(_xc_handle, domid, &s_tsc_info.tsc_mode,
				 &s_tsc_info.nsec, &s_tsc_info.khz,
				 &s_tsc_info.incarn);
    if (ret < 0) {
	EPRINTF("xc_domain_get_tsc_info() failed");
	ret = -EPERM;
	goto out;
    }
    DPRINTF("tsc info: mode %d nsec %"PRIu64" khz %d incarn %d",
	    s_tsc_info.tsc_mode, s_tsc_info.nsec, s_tsc_info.khz,
	    s_tsc_info.incarn);
    filebuf_write(f, &s_tsc_info, sizeof(s_tsc_info));

    ret = xc_domain_getinfo(_xc_handle, domid, 1, dom_info);
    if (ret != 1 || dom_info[0].domid != domid) {
	EPRINTF("xc_domain_getinfo(%d) failed", domid);
	ret = -EPERM;
	goto out;
    }
    s_vcpu_info.marker = XC_SAVE_ID_VCPU_INFO;
    s_vcpu_info.max_vcpu_id = dom_info[0].max_vcpu_id;
    s_vcpu_info.vcpumap = 0ULL;
    for (j = 0; j <= s_vcpu_info.max_vcpu_id; j++) {
	ret = xc_vcpu_getinfo(_xc_handle, domid, j, &vcpu_info);
	if (ret == 0 && vcpu_info.online)
	    s_vcpu_info.vcpumap |= 1ULL << j;
    }
    DPRINTF("vcpus %d online %"PRIx64, s_vcpu_info.max_vcpu_id,
	    s_vcpu_info.vcpumap);
    filebuf_write(f, &s_vcpu_info, sizeof(s_vcpu_info));

    s_hvm_ident_pt.marker = XC_SAVE_ID_HVM_IDENT_PT;
    s_hvm_ident_pt.data = 0;
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_IDENT_PT,
		     &s_hvm_ident_pt.data);
    DPRINTF("ident_pt %"PRIx64, s_hvm_ident_pt.data);
    if (s_hvm_ident_pt.data)
	filebuf_write(f, &s_hvm_ident_pt, sizeof(s_hvm_ident_pt));

    s_hvm_vm86_tss.marker = XC_SAVE_ID_HVM_VM86_TSS;
    s_hvm_vm86_tss.data = 0;
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_VM86_TSS,
		     &s_hvm_vm86_tss.data);
    DPRINTF("vm86_tss %"PRIx64, s_hvm_vm86_tss.data);
    if (s_hvm_vm86_tss.data)
	filebuf_write(f, &s_hvm_vm86_tss, sizeof(s_hvm_vm86_tss));

    s_hvm_console_pfn.marker = XC_SAVE_ID_HVM_CONSOLE_PFN;
    s_hvm_console_pfn.data = 0;
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_CONSOLE_PFN,
		     &s_hvm_console_pfn.data);
    DPRINTF("console_pfn %"PRIx64, s_hvm_console_pfn.data);
    if (s_hvm_console_pfn.data)
	filebuf_write(f, &s_hvm_console_pfn, sizeof(s_hvm_console_pfn));

    s_hvm_acpi_ioports_location.marker = XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION;
    s_hvm_acpi_ioports_location.data = 0;
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_ACPI_IOPORTS_LOCATION,
		     &s_hvm_acpi_ioports_location.data);
    DPRINTF("acpi_ioports_location %"PRIx64, s_hvm_acpi_ioports_location.data);
    if (s_hvm_acpi_ioports_location.data)
	filebuf_write(f, &s_hvm_acpi_ioports_location,
                      sizeof(s_hvm_acpi_ioports_location));

    s_hvm_magic_pfns.marker = XC_SAVE_ID_HVM_MAGIC_PFNS;
    memset(s_hvm_magic_pfns.magic_pfns, 0, sizeof(s_hvm_magic_pfns.magic_pfns));
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_IO_PFN_FIRST,
		     &s_hvm_magic_pfns.magic_pfns[0]);
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_IO_PFN_LAST,
		     &s_hvm_magic_pfns.magic_pfns[1]);
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_SHARED_INFO_PFN,
		     &s_hvm_magic_pfns.magic_pfns[2]);
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_DMREQ_PFN,
                     &s_hvm_magic_pfns.magic_pfns[3]);
    xc_get_hvm_param(_xc_handle, domid, HVM_PARAM_DMREQ_VCPU_PFN,
                     &s_hvm_magic_pfns.magic_pfns[4]);
    DPRINTF("ioreq pfn %"PRIx64"-%"PRIx64
            " shared info pfn %"PRIx64" dmreq pfn %"PRIx64"/%"PRIx64,
            s_hvm_magic_pfns.magic_pfns[0], s_hvm_magic_pfns.magic_pfns[1],
            s_hvm_magic_pfns.magic_pfns[2], s_hvm_magic_pfns.magic_pfns[3],
            s_hvm_magic_pfns.magic_pfns[4]);
    filebuf_write(f, &s_hvm_magic_pfns, sizeof(s_hvm_magic_pfns));

    hvm_buf_size = xc_domain_hvm_getcontext(_xc_handle, domid, 0, 0);
    if (hvm_buf_size == -1) {
	EPRINTF("xc_domain_hvm_getcontext(0, 0) failed");
	ret = -EPERM;
	goto out;
    }
    DPRINTF("hvm_buf_size is %d", hvm_buf_size);

    hvm_buf = malloc(hvm_buf_size);
    if (hvm_buf == NULL) {
	EPRINTF("hvm_buf = malloc(%d) failed", hvm_buf_size);
	ret = -ENOMEM;
	goto out;
    }

    s_hvm_context.marker = XC_SAVE_ID_HVM_CONTEXT;
    s_hvm_context.size = xc_domain_hvm_getcontext(_xc_handle, domid,
						  hvm_buf, hvm_buf_size);
    if (s_hvm_context.size == -1) {
	EPRINTF("xc_domain_hvm_getcontext(%d) failed", hvm_buf_size);
	ret = -EPERM;
	goto out;
    }
    DPRINTF("hvm rec size %d", s_hvm_context.size);
    filebuf_write(f, &s_hvm_context, sizeof(s_hvm_context));
    filebuf_write(f, hvm_buf, s_hvm_context.size);

    s_vm_uuid.marker = XC_SAVE_ID_VM_UUID;
    memcpy(s_vm_uuid.uuid, uuid, sizeof(s_vm_uuid.uuid));
    filebuf_write(f, &s_vm_uuid, sizeof(s_vm_uuid));

    p2m_size = xc_domain_maximum_gpfn(_xc_handle, domid);
    if (p2m_size < 0) {
	EPRINTF("xc_domain_maximum_gpfn() failed");
	ret = -EPERM;
	goto out;
    }
    p2m_size++;

    DPRINTF("p2m_size: 0x%x", p2m_size);
    pfn_type = malloc(MAX_BATCH_SIZE * sizeof(*pfn_type));
    if (pfn_type == NULL) {
	EPRINTF("pfn_type = malloc(%"PRId64") failed",
                (uint64_t)MAX_BATCH_SIZE * sizeof(*pfn_type));
	ret = -ENOMEM;
	goto out;
    }

    pfn_err = malloc(MAX_BATCH_SIZE * sizeof(*pfn_err));
    if (pfn_err == NULL) {
	EPRINTF("pfn_err = malloc(%"PRId64") failed",
                (uint64_t)MAX_BATCH_SIZE * sizeof(*pfn_err));
	ret = -ENOMEM;
	goto out;
    }

    pfn_zero = malloc(MAX_BATCH_SIZE * sizeof(*pfn_zero));
    if (pfn_zero == NULL) {
        EPRINTF("pfn_zero = malloc(%"PRId64") failed",
                (uint64_t)MAX_BATCH_SIZE * sizeof(*pfn_zero));
        ret = -ENOMEM;
        goto out;
    }

    mem = NULL;
    pfn = 0;
    while (pfn < p2m_size) {
	batch = 0;
	while ((pfn + batch) < p2m_size && batch < MAX_BATCH_SIZE) {
	    pfn_type[batch] = pfn + batch;
	    batch++;
	}
	if (mem)
	    xc_munmap(_xc_handle, domid, mem, mem_nr * PAGE_SIZE);
	mem = xc_map_foreign_bulk(_xc_handle, domid, PROT_WRITE,
				  pfn_type, pfn_err, batch);
	if (mem == NULL) {
	    EPRINTF("xc_map_foreign_bulk(%d, %d) failed",
		     pfn, batch);
	    ret = -EPERM;
	    goto out;
	}
	mem_nr = batch;
	ret = xc_get_pfn_type_batch(_xc_handle, domid, batch, pfn_type);
	if (ret) {
	    EPRINTF("xc_get_pfn_type_batch(%d, %d) failed",
		     pfn, batch);
	    ret = -EPERM;
	    goto out;
	}
	rezero = 0;
        _batch = 0;
	for (j = 0; j < batch; j++) {
	    map_err = pfn_err[j];
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
                    int _zero_batch = zero_batch + 2 * MAX_BATCH_SIZE;
                    filebuf_write(f, &_zero_batch, sizeof(zero_batch));
                    filebuf_write(f, &pfn_zero[0],
                                 zero_batch * sizeof(pfn_zero[0]));
                    zero_batch = 0;
                }
            } else if (pfn_type[j] == XEN_DOMCTL_PFINFO_XPOD) {
		/* Save cloned pages as well */
                map_err = 0;
		pfn_err[_batch] = pfn + j;
		_batch++;
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
            filebuf_write(f, &_batch, sizeof(_batch));
            filebuf_write(f, pfn_err, _batch * sizeof(pfn_err[0]));
            j = 0;
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
		    filebuf_write(f, &mem[run << PAGE_SHIFT],
				 b_run << PAGE_SHIFT);
                    run += b_run;
                    _batch -= b_run;
                    total_pages += b_run;
		}
            }
	}
	pfn += batch;
    }

    if (zero_batch) {
        int _zero_batch = zero_batch + 2 * MAX_BATCH_SIZE;
        filebuf_write(f, &_zero_batch, sizeof(zero_batch));
        filebuf_write(f, &pfn_zero[0],
                     zero_batch * sizeof(pfn_zero[0]));
    }

    /* 0: end marker */
    batch = 0;
    filebuf_write(f, &batch, sizeof(batch));

    DPRINTF("memory: pages %d rezero %d clone %d", total_pages, total_rezero,
            total_clone);

    ret = 0;
  out:
    if (mem)
	xc_munmap(_xc_handle, domid, mem, mem_nr * PAGE_SIZE);
    free(pfn_zero);
    free(pfn_err);
    free(pfn_type);
    free(hvm_buf);
    if (f)
        filebuf_close(f);
    return ret;
}
