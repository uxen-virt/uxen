/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>

#include "uxen_types.h"

#include "../common/debug.h"
#include "uxen_hypercall.h"
#include "uxen_util.h"
#include "uxen_hypercall_sup.h"

#include <xen/version.h>
#include <xen/xen.h>

#define HV_CPUID_LEAF_BASE 0x40000000
#define HV_CPUID_LEAF_RANGE 0x10000
#define HV_CPUID_LEAD_SKIP 0x100

#define ENOENT 2
#define  ENOSYS          38

extern void *hypercall_page;
unsigned int *hypercall_page_mfn;

int
uxen_hypercall_init(void)
{
    uint32_t eax = 0, ebx, ecx, edx;
    uint32_t leaf;
    char signature[13];
    xen_extraversion_t extraversion;
    unsigned int i;

    if (uxen_is_whp_present())
        return 0; /* nothing to do */

    if (hypercall_page != NULL && hypercall_page_mfn != NULL) {
        uxen_msg("hypercall already initialized:");
        uxen_msg("  hypercall_page: 0x%p", hypercall_page);
        uxen_msg("  hypercall_page_mfn: 0x%X", * hypercall_page_mfn);

        return 0;
    }

    for (leaf = 0; leaf < HV_CPUID_LEAF_RANGE; leaf += HV_CPUID_LEAD_SKIP) {
	cpuid(HV_CPUID_LEAF_BASE + leaf, &eax, (uint32_t *)&signature[0],
	      (uint32_t *)&signature[4], (uint32_t *)&signature[8]);
	signature[12] = 0;

	if (!strcmp(signature, "uXenisnotXen"))
	    break;
    }

    if (leaf >= HV_CPUID_LEAF_RANGE ||
	(eax - (HV_CPUID_LEAF_BASE + leaf)) < 2) {
	uxen_err("hypervisor not found: leaf %x eax %x", leaf, eax);
	return 1;
    }

    uxen_msg("hypervisor found at %x eax %x", HV_CPUID_LEAF_BASE + leaf, eax);

    cpuid(HV_CPUID_LEAF_BASE + leaf + 2, &eax, &ebx, &ecx, &edx);

    hypercall_page_mfn = uxen_malloc(eax * sizeof(hypercall_page_mfn[0]));
    if (!hypercall_page_mfn) {
	uxen_err("uxen_malloc failed");
	return 1;
    }
    hypercall_page = uxen_malloc_locked_pages(eax, hypercall_page_mfn, 0);
    if (hypercall_page == NULL) {
	uxen_err("uxen_malloc_locked_pages failed");
        uxen_free(hypercall_page_mfn);
        hypercall_page_mfn = NULL;
        return 1;
    }
    uxen_msg("hypercall pages mapped at %p mfn %x", hypercall_page,
	     hypercall_page_mfn[0]);

    memset(hypercall_page, 0xc3	/* ret */, PAGE_SIZE);

    for (i = 0; i < eax; i++)
	wrmsr(ebx, (hypercall_page_mfn[i] << PAGE_SHIFT) + i);

    cpuid(HV_CPUID_LEAF_BASE + leaf + 1, &eax, &ebx, &ecx, &edx);
    uxen_hypercall_version(XENVER_extraversion, extraversion);
    uxen_msg("hypervisor version uXen v%u.%u%s", eax >> 16, eax & 0xffff,
	     extraversion);


    return 0;
}

#define hcall(name) \
    ((uintptr_t)hypercall_page + __HYPERVISOR_##name * 32)
#define hcall_by_nr(nr) \
    ((uintptr_t)hypercall_page + (nr) * 32)
#define hcall_arg(x) ((uintptr_t)(x))

int
uxen_hypercall_version(int cmd, void *arg)
{
    if (!hypercall_page)
	return -ENOENT;
    return (int)_hypercall2(hcall(xen_version), hcall_arg(cmd), hcall_arg(arg));
}

int
uxen_hypercall_memory_op(int cmd, void *arg)
{
    if (!hypercall_page)
	return -ENOENT;
    return (int)_hypercall2(hcall(memory_op), hcall_arg(cmd), hcall_arg(arg));
}

int
uxen_hypercall_hvm_op(int cmd, void *arg)
{
    if (!hypercall_page)
	return -ENOENT;
    return (int)_hypercall2(hcall(hvm_op), hcall_arg(cmd), hcall_arg(arg));
}

uintptr_t uxen_hypercall1(unsigned int nr, uintptr_t a1)
{
    if (!hypercall_page)
	return (uintptr_t) -ENOENT;
    return _hypercall1(hcall_by_nr(nr), a1);
}
 
uintptr_t uxen_hypercall2(unsigned int nr, uintptr_t a1, uintptr_t a2)
{
    if (!hypercall_page)
	return (uintptr_t) -ENOENT;
    return _hypercall2(hcall_by_nr(nr), a1, a2);
}
 
uintptr_t uxen_hypercall3(unsigned int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3)
{
    if (!hypercall_page)
	return (uintptr_t) -ENOENT;
    return _hypercall3(hcall_by_nr(nr), a1, a2, a3);
}
 
uintptr_t uxen_hypercall4(unsigned int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4)
{
    if (!hypercall_page)
	return (uintptr_t) -ENOENT;
    return _hypercall4(hcall_by_nr(nr), a1, a2, a3, a4);
}
 
uintptr_t uxen_hypercall5(unsigned int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
    if (!hypercall_page)
	return (uintptr_t) -ENOENT;
    return _hypercall5(hcall_by_nr(nr), a1, a2, a3, a4, a5);
}

uintptr_t uxen_hypercall6(unsigned int nr, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
    if (!uxen_is_whp_present()) {
        if (!hypercall_page)
            return (uintptr_t) -ENOSYS; 
        return _hypercall6(hcall_by_nr(nr), a1, a2, a3, a4, a5, a6);
    } else
        return _whpx_hypercall6(nr, a1, a2, a3, a4, a5, a6);
}
