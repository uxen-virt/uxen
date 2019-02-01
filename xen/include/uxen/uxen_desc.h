/*
 *  uxen_desc.h
 *  uxen
 *
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_DESC_H_
#define _UXEN_DESC_H_

#ifdef __XEN__
#include <public/xen.h>
#include <public/memory.h>
#include <public/version.h>
#else
#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__
#endif
#if defined(_MSC_VER)
#if defined(_M_X64)
#define __x86_64__
#elif defined(_M_IX86)
#define __i386__
#endif
#endif
#include <xen/xen.h>
#include <xen/memory.h>
#include <xen/version.h>
#endif

#define UXEN_PTR(type, name) union { \
	type *name;		     \
	uint64_t name ## pad;	     \
    }

#define UXEN_UNRESTRICTED_ACCESS_HYPERCALL 0x01
#define UXEN_ADMIN_HYPERCALL 0x02
#define UXEN_SYSTEM_HYPERCALL 0x04
#define UXEN_VMI_OWNER 0x08

/* this must match struct privcmd_hypercall below */
struct uxen_hypercall_desc {
    uint64_t uhd_op;
    union {
	uint64_t uhd_arg[6];
	XEN_GUEST_HANDLE(uint64_t) uhd_hnd[6];
    };
};

struct uxen_createvm_desc {
    xen_domain_handle_t ucd_vmuuid; /* uuid of the guest to target */
    xen_domain_handle_t ucd_v4v_token; /* v4v token */
    uint32_t ucd_create_flags;      /* xc_domain_create flags */
    uint32_t ucd_create_ssidref;    /* xc_domain_create ssidref */
    uint32_t ucd_max_vcpus;         /* xc_domain_max_vcpus max */
    uint32_t ucd_nr_pages_hint;     /* nr_pages hint */
    domid_t ucd_domid;              /* returned domain id */
};

struct uxen_execute_desc {
    uint32_t ued_vcpu;
};

typedef struct privcmd_hypercall {
    uint64_t op;
    uint64_t arg[6];
} privcmd_hypercall_t;

union uxen_memop_arg {
    xen_memory_reservation_t reservation;
    xen_memory_exchange_t exchange;
    domid_t domid;
    xen_add_to_physmap_t add_to_physmap;
    xen_foreign_memory_map_t foreign_memory_map;
    xen_machphys_mfn_list_t machphys_mfn_list;
    xen_machphys_mapping_t machphys_mapping;
    xen_memory_map_t memory_map;
    xen_translate_gpfn_list_for_map_t translate_gpfn_list_for_map;
};
typedef union uxen_memop_arg uxen_memop_arg_u;
DEFINE_XEN_GUEST_HANDLE(uxen_memop_arg_u);

typedef struct privcmd_mmap_entry {
    uint64_t va;
    uint64_t mfn;
    uint64_t npages;
} privcmd_mmap_entry_t;

#define UXEN_MMAPBATCH_PROT_READ  0x1
#define UXEN_MMAPBATCH_PROT_WRITE 0x2
struct uxen_mmapbatch_desc {
    uint64_t umd_addr;	   /* virtual address */
    UXEN_PTR(xen_pfn_t, umd_arr); /* array of mfns */
    UXEN_PTR(int, umd_err); /* array of errors  */
    uint32_t umd_num;	   /* number of pages to populate */
    uint16_t umd_prot;	   /* map mode read/write */
};

struct uxen_munmap_desc {
    uint64_t umd_addr;		/* virtual address */
    uint32_t umd_num;		/* number of pages to unmap */
};

struct uxen_targetvm_desc {
    xen_domain_handle_t utd_vmuuid; /* uuid of the guest to target */
    domid_t utd_domid;              /* returned domain id */
};

struct uxen_destroyvm_desc {
    xen_domain_handle_t udd_vmuuid;
};

struct uxen_queryvm_desc {
    xen_domain_handle_t uqd_vmuuid;
    domid_t uqd_domid;
};

/* NB: This structure needs to be packed the same way on all
 * compilers.  Each field in the structure, has an associated mask
 * bit.  Setting the mask bit causes the corresponding field value to
 * override the default.  Add new fields to the end of the structure
 * as when the structure is passed between different parts of the
 * system it is truncated or padded with zeros.  In this way old tools
 * can talk to new uxen and vice-versa.
 */
 
struct uxen_init_desc {
    uint64_t mask0;

    uint64_t use_hidden_mem;
#     define UXEN_INIT_use_hidden_mem			(1ULL << 0)
#     define UXEN_INIT_use_hidden_mem_MASK		mask0
    char opt_console[32];
#     define UXEN_INIT_opt_console			(1ULL << 1)
#     define UXEN_INIT_opt_console_MASK			mask0
    char opt_com1[40];
#     define UXEN_INIT_opt_com1				(1ULL << 2)
#     define UXEN_INIT_opt_com1_MASK			mask0
    char opt_com2[40];
#     define UXEN_INIT_opt_com2				(1ULL << 3)
#     define UXEN_INIT_opt_com2_MASK			mask0
    uint64_t opt_sync_console;
#     define UXEN_INIT_opt_sync_console			(1ULL << 4)
#     define UXEN_INIT_opt_sync_console_MASK		mask0
    char opt_gdb[32];
#     define UXEN_INIT_opt_gdb				(1ULL << 5)
#     define UXEN_INIT_opt_gdb_MASK			mask0
    uint64_t opt_console_timestamps;
#     define UXEN_INIT_opt_console_timestamps		(1ULL << 6)
#     define UXEN_INIT_opt_console_timestamps_MASK	mask0
    uint64_t opt_ler;
#     define UXEN_INIT_opt_ler				(1ULL << 7)
#     define UXEN_INIT_opt_ler_MASK			mask0
    uint64_t use_xsave;
#     define UXEN_INIT_use_xsave			(1ULL << 8)
#     define UXEN_INIT_use_xsave_MASK			mask0
    uint64_t opt_cpu_info;
#     define UXEN_INIT_opt_cpu_info			(1ULL << 9)
#     define UXEN_INIT_opt_cpu_info_MASK		mask0
    uint64_t opt_hap_1gb;
#     define UXEN_INIT_opt_hap_1gb			(1ULL << 10)
#     define UXEN_INIT_opt_hap_1gb_MASK			mask0
    uint64_t opt_hap_2mb;
#     define UXEN_INIT_opt_hap_2mb			(1ULL << 11)
#     define UXEN_INIT_opt_hap_2mb_MASK			mask0
    uint64_t opt_bootscrub;
#     define UXEN_INIT_opt_bootscrub			(1ULL << 12)
#     define UXEN_INIT_opt_bootscrub_MASK		mask0
    uint64_t debug_stack_lines;
#     define UXEN_INIT_debug_stack_lines		(1ULL << 13)
#     define UXEN_INIT_debug_stack_lines_MASK	        mask0
    uint64_t opt_cpuid_mask_ecx;
#     define UXEN_INIT_opt_cpuid_mask_ecx		(1ULL << 14)
#     define UXEN_INIT_opt_cpuid_mask_ecx_MASK	        mask0
    uint64_t opt_cpuid_mask_edx;
#     define UXEN_INIT_opt_cpuid_mask_edx   		(1ULL << 15)
#     define UXEN_INIT_opt_cpuid_mask_edx_MASK	        mask0
    uint64_t opt_cpuid_mask_xsave_eax;
#     define UXEN_INIT_opt_cpuid_mask_xsave_eax 	(1ULL << 16)
#     define UXEN_INIT_opt_cpuid_mask_xsave_eax_MASK    mask0
    uint64_t opt_cpuid_mask_ext_ecx;
#     define UXEN_INIT_opt_cpuid_mask_ext_ecx   	(1ULL << 17)
#     define UXEN_INIT_opt_cpuid_mask_ext_ecx_MASK      mask0
    uint64_t opt_cpuid_mask_ext_edx;
#     define UXEN_INIT_opt_cpuid_mask_ext_edx		(1ULL << 18)
#     define UXEN_INIT_opt_cpuid_mask_ext_edx_MASK      mask0
    uint64_t opt_hvm_debug_level;
#     define UXEN_INIT_opt_hvm_debug_level		(1ULL << 19)
#     define UXEN_INIT_opt_hvm_debug_level_MASK         mask0
    uint64_t ple_gap;
#     define UXEN_INIT_ple_gap          		(1ULL << 20)
#     define UXEN_INIT_ple_gap_MASK                     mask0
    uint64_t ple_window;
#     define UXEN_INIT_ple_window       		(1ULL << 21)
#     define UXEN_INIT_ple_window_MASK                  mask0
    uint64_t disable_pv_vmx;
#     define UXEN_INIT_disable_pv_vmx       		(1ULL << 22)
#     define UXEN_INIT_disable_pv_vmx_MASK              mask0
    uint64_t __retired1; /* was opt_xfeatures */
/* #     define UXEN_INIT_opt_xfeatures			(1ULL << 23) */
/* #     define UXEN_INIT_opt_xfeatures_MASK		mask0 */
    char opt_debug[XEN_OPT_DEBUG_LEN];
#     define UXEN_INIT_opt_debug			(1ULL << 24)
#     define UXEN_INIT_opt_debug_MASK			mask0
    uint64_t opt_hvmonoff;
#     define UXEN_INIT_opt_hvmonoff       		(1ULL << 25)
#     define UXEN_INIT_opt_hvmonoff_MASK                mask0
    uint64_t opt_crash_on;
#     define UXEN_INIT_opt_crash_on			(1ULL << 26)
#     define UXEN_INIT_opt_crash_on_MASK                mask0
    uint64_t opt_v4v_thread_priority;
#     define UXEN_INIT_opt_v4v_thread_priority		(1ULL << 27)
#     define UXEN_INIT_opt_v4v_thread_priority_MASK     mask0
    uint64_t opt_spec_ctrl;
#     define UXEN_INIT_opt_spec_ctrl			(1ULL << 28)
#     define UXEN_INIT_opt_spec_ctrl_MASK		mask0
    uint64_t opt_whp;
#     define UXEN_INIT_opt_whp       			(1ULL << 29)
#     define UXEN_INIT_opt_whp_MASK			mask0
};

#endif
