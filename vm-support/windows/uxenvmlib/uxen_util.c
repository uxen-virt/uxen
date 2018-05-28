/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <stdarg.h>
#include <Ntstrsafe.h>

#include "uxen_types.h"
#include "../common/debug.h"
#include "../../../common/include/whpx-shared.h"
#include "uxen_hypercall.h"
#include "uxen_util.h"
#include "uxen_hypercall_sup.h"
#include <xen/xen.h>

#pragma warning(disable: 4200)
#define __XEN_TOOLS__
#include <xen/xen.h>
#include <xen/memory.h>
#pragma warning(default: 4200)

#define UXEN_DBGPRINT_LOG_DBGVIEW 1


#define VIRIDIAN_CPUID_SIGNATURE_EBX 0x7263694d
#define VIRIDIAN_CPUID_SIGNATURE_ECX 0x666f736f
#define VIRIDIAN_CPUID_SIGNATURE_EDX 0x76482074

void *
uxen_malloc_locked_pages(unsigned int nr_pages, unsigned int *mfn_list,
			 unsigned int max_mfn)
{
    PHYSICAL_ADDRESS low_address;
    PHYSICAL_ADDRESS high_address;
    PHYSICAL_ADDRESS skip_bytes;
    PFN_NUMBER *mfnarray;
    PMDL mdl;
    unsigned int i;
    void *addr = NULL;

    if (max_mfn == 0)
	max_mfn = 0x100000; /* 4GB */

    low_address.QuadPart = 0;
    high_address.QuadPart = (max_mfn << PAGE_SHIFT) - 1;
    skip_bytes.QuadPart = 0;

    mdl = MmAllocatePagesForMdl(low_address, high_address, skip_bytes,
				nr_pages << PAGE_SHIFT);
    if (mdl == NULL) {
	uxen_err("uxen_malloc_locked_pages: MmAllocatePagesForMdl failed");
	goto out;
    }
    if (mdl->ByteCount != nr_pages << PAGE_SHIFT) {
	uxen_err("uxen_malloc_locked_pages: MmAllocatePagesForMdl incomplete");
	goto out;
    }
    mfnarray = MmGetMdlPfnArray(mdl);
    for (i = 0; i < nr_pages; i++) {
        mfn_list[i] = (unsigned int)mfnarray[i];
        if (mfn_list[i] > max_mfn) {
	    uxen_err("uxen_malloc_locked_pages: MmAllocatePagesForMdl invalid");
	    goto out;
	}
    }

    try {
	addr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL,
					    FALSE, LowPagePriority);
    } except (EXCEPTION_EXECUTE_HANDLER) {
	uxen_err("uxen_malloc_locked_pages: "
		 "MmMapLockedPagesSpecifyCache failed %x\n",
		 GetExceptionCode());
	addr = NULL;
    }

  out:
    if (mdl) {
	if (addr == NULL)
	    MmFreePagesFromMdl(mdl);
	ExFreePool(mdl);
    }

    return addr;
}

void *
uxen_user_map_page_range(unsigned int n, unsigned int *mfn, MDL **_mdl)
{
    PFN_NUMBER *pfn;
    MDL *mdl;
    void *addr = NULL;
    unsigned int i;

    mdl = IoAllocateMdl(NULL, n << PAGE_SHIFT, FALSE, FALSE, NULL);
    if (!mdl) {
        uxen_err("IoAllocateMdl failed");
        goto out;
    }

    ASSERT(mdl->ByteCount == n << PAGE_SHIFT);
    mdl->MdlFlags = MDL_PAGES_LOCKED;

    pfn = MmGetMdlPfnArray(mdl);
    for (i = 0; i < n; i++)
	pfn[i] = mfn[i];

    try {
        addr = MmMapLockedPagesSpecifyCache(
            mdl, UserMode, MmCached, NULL, FALSE, LowPagePriority);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        uxen_err("MmMapLockedPagesSpecifyCache exception: 0x%08X",
                 GetExceptionCode());
	addr = NULL;
    }

    if (addr && _mdl)
        *_mdl = mdl;

  out:
    if (!addr && mdl)
        IoFreeMdl(mdl);
    return addr;
}

void
cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    int info[4];

    info[0] = *eax;
    info[1] = *ebx;
    info[2] = *ecx;
    info[3] = *edx;
    __cpuid(info, idx);
    *eax = info[0];
    *ebx = info[1];
    *ecx = info[2];
    *edx = info[3];
}

void
wrmsr(uint32_t reg, uint64_t val)
{
    __writemsr(reg, val);
}


int
uxen_DbgPrint(const char *fmt, ...)
{
    int ret;
    va_list ap;

#ifdef UXEN_DBGPRINT_LOG_XEN
    xen_hvm_xenlog_t xl;

    va_start(ap, fmt);
    ret = RtlStringCbVPrintfA(xl.msg, sizeof(xl.msg) - 1, fmt, ap);
    va_end(ap);

    xl.len = strlen(xl.msg);
    if (xl.msg[xl.len - 1] == '\n')
	xl.msg[--xl.len] = 0;
    ret = uxen_hypercall_hvm_op(HVMOP_xenlog, &xl);
    if (ret != 0) {
	int i;
	for (i = 0; i < xl.len; i++)
	    __outbyte(0xe9, xl.msg[i]);
	if (xl.msg[i - 1] != '\n')
	    __outbyte(0xe9, '\n');
    }

    ret = STATUS_SUCCESS;
#endif

#ifdef UXEN_DBGPRINT_LOG_DBGVIEW
    va_start(ap, fmt);
    ret = vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ap);
    va_end(ap);
#endif

    return ret;
}

struct shared_info *
uxen_get_shared_info(unsigned int *_gpfn)
{
    static struct shared_info *shared_info = NULL;
    static unsigned int gpfn = 0;
    struct xen_add_to_physmap xatp;
    void *map_addr;
    int ret;

    if (shared_info)
        goto out;

    map_addr = uxen_malloc_locked_pages(1, &gpfn, 0);
    if (!map_addr) {
        uxen_err("uxen_malloc_locked_pages failed");
        return NULL;
    }

    xatp.domid = DOMID_SELF;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx = 0;
    xatp.gpfn = gpfn;
    ret = uxen_hypercall_memory_op(XENMEM_add_to_physmap, &xatp);
    if (ret) {
        uxen_err("hypercall_memory_op failed");
        return NULL;
    }

    shared_info = (struct shared_info *)map_addr;

  out:
    if (_gpfn)
        *_gpfn = gpfn;

    return shared_info;
}

int
uxen_is_whp_present_64(void)
{
    static int tested = 0;
    static int whp_present = 0;

    if (!tested) {
        uint32_t base = 0x40000000;
        uint32_t eax, ebx, ecx, edx;

        cpuid(base, &eax, &ebx, &ecx, &edx);

        /* if viridian is enabled, use 0x40000100 */
        if (ebx == VIRIDIAN_CPUID_SIGNATURE_EBX &&
            ecx == VIRIDIAN_CPUID_SIGNATURE_ECX &&
            edx == VIRIDIAN_CPUID_SIGNATURE_EDX)
        {
            base = 0x40000100;
            cpuid(base, &eax, &ebx, &ecx, &edx);
        }

        whp_present = (ebx == WHP_CPUID_SIGNATURE_EBX &&
            ecx == WHP_CPUID_SIGNATURE_ECX &&
            edx == WHP_CPUID_SIGNATURE_EDX);
        KeMemoryBarrier();

        tested = 1;
    }

    return whp_present;
}
