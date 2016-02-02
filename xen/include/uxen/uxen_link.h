/*
 *  uxen_link.h
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_LINK_H_
#define _UXEN_LINK_H_

#include "uxen_os.h"

#if defined(UXEN_DEFINE_SYMBOLS_PROTO) || defined(UXEN_DEFINE_SYMBOLS_CODE)

#include "uxen_desc.h"

#if defined(UXEN_DEFINE_SYMBOLS_CODE)
#define UXEN_LINK_PROTO_TYPE
#else
#define UXEN_LINK_PROTO_TYPE extern
#endif

UXEN_LINK_PROTO_TYPE struct uxen_info *uxen_info;
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_start_xen) (const struct uxen_init_desc *, uint64_t);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_add_heap_memory) (uint64_t, uint64_t);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_lookup_vm) (xen_domain_handle_t);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_setup_vm) (struct uxen_createvm_desc *,
                                      struct vm_info_shared *,
                                      struct vm_vcpu_info_shared **);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_run_vcpu) (uint32_t, uint32_t);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_destroy_vm) (xen_domain_handle_t);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_dispatch_ipi) (unsigned int);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_run_idle_thread) (uint32_t);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_handle_keypress) (unsigned char);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_shutdown_xen) (void);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_suspend_xen_prepare) (void);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_suspend_xen) (void);
UXEN_LINK_PROTO_TYPE
void (__cdecl *uxen_do_resume_xen) (void);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_hypercall) (
    struct uxen_hypercall_desc *, struct vm_info_shared *, void *, uint32_t);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_process_ud2) (struct cpu_user_regs *);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_lookup_symbol) (uint64_t, char *, uint32_t);
UXEN_LINK_PROTO_TYPE
intptr_t (__cdecl *uxen_do_flush_rcu) (uint32_t);
UXEN_LINK_PROTO_TYPE
uint8_t *uxen_addr_per_cpu_start;
UXEN_LINK_PROTO_TYPE
uint8_t *uxen_addr_per_cpu_data_end;

#endif

#if defined(UXEN_DEFINE_SYMBOLS_CODE)
#define NO_XEN_ELF_NOTE
#include <libelf/libelf.h>

#ifndef PRIx64
#if defined(_WIN32)
#define PRIx64 "I64x"
#elif defined(__APPLE__) && defined(KERNEL)
#define PRIx64 "qx"
#else
#error unsupported os
#endif
#endif

#if !defined(__UXEN_EMBEDDED__)
static int get_elf_sym(struct elf_binary *elf, unsigned char *hv,
		       const char *n, int vsize, void *vp)
{
    uint64_t v;
    uint64_t base;
    int shndx;
    const elf_sym *sym;
    const elf_shdr *shdr;

    sym = elf_sym_by_name(elf, n);
    if (sym == NULL)
	return -1;
    shndx = elf_uval(elf, sym, st_shndx);
    switch (shndx) {
    case SHN_UNDEF:
    case SHN_ABS:
	base = 0;
	break;
    case SHN_COMMON:
	return -1;
	break;
    default:
	shdr = elf_shdr_by_index(elf, shndx);
	if ( shdr == NULL )
	    return -1;
	base = elf_uval(elf, shdr, sh_addr) + (uint64_t)(uintptr_t)hv;
	break;
    }
    v = elf_uval(elf, sym, st_value) + base;
    dprintk("sym %s = %" PRIx64 " (base %" PRIx64 ")\n", n, v, base);
    memcpy(vp, &v, vsize);
    return 0;
}

#define UXEN_GET_SYM(n, t, v) do {				\
	int ret = get_elf_sym(elf, hv, #n, sizeof(t), &v);	\
	if (ret) {						\
	    if (missing_symbol)					\
		*missing_symbol = #n;				\
	    return ret;						\
	}							\
    } while (/* CONSTCOND */0)
#else
#define UXEN_GET_SYM(n, t, v) do {					\
	extern t;                                                       \
	v = &n;                                                         \
	dprintk("sym %s = %p\n", #v, v);				\
    } while (/* CONSTCOND */0)
#endif

#define UXEN_GET_SYMS(fn_name, prefix) int                              \
    fn_name(struct elf_binary *elf, unsigned char *hv,			\
            const char **missing_symbol)				\
{									\
									\
    /* _uxen_info resolves to _uxen_info, while __uxen_info would */    \
    /* resolve to uxen_info */                                          \
    UXEN_GET_SYM(_uxen_info, struct uxen_info _uxen_info, uxen_info);   \
    UXEN_GET_SYM(prefix ## uxen_start_xen,                              \
                 intptr_t __cdecl prefix ## uxen_start_xen              \
		 (const struct uxen_init_desc *, uint64_t),             \
                 uxen_do_start_xen);	                                \
    UXEN_GET_SYM(prefix ## uxen_add_heap_memory,                        \
                 void __cdecl prefix ## uxen_add_heap_memory            \
                 (uint64_t, uint64_t), uxen_do_add_heap_memory);        \
    UXEN_GET_SYM(prefix ## uxen_lookup_vm,                              \
                 intptr_t __cdecl prefix ## uxen_lookup_vm              \
		 (xen_domain_handle_t), uxen_do_lookup_vm);             \
    UXEN_GET_SYM(prefix ## uxen_setup_vm,                               \
                 intptr_t __cdecl prefix ## uxen_setup_vm               \
		 (struct uxen_createvm_desc *, struct vm_info_shared *, \
                  struct vm_vcpu_info_shared **), uxen_do_setup_vm);    \
    UXEN_GET_SYM(prefix ## uxen_run_vcpu,                               \
                 intptr_t __cdecl prefix ## uxen_run_vcpu               \
		 (uint32_t, uint32_t), uxen_do_run_vcpu);               \
    UXEN_GET_SYM(prefix ## uxen_destroy_vm,                             \
                 intptr_t __cdecl prefix ## uxen_destroy_vm             \
		 (xen_domain_handle_t), uxen_do_destroy_vm);            \
    UXEN_GET_SYM(prefix ## uxen_dispatch_ipi,                           \
                 void __cdecl prefix ## uxen_dispatch_ipi               \
		 (unsigned int), uxen_do_dispatch_ipi);			\
    UXEN_GET_SYM(prefix ## uxen_run_idle_thread,                        \
                 void __cdecl prefix ## uxen_run_idle_thread            \
		 (uint32_t), uxen_do_run_idle_thread);                  \
    UXEN_GET_SYM(prefix ## uxen_handle_keypress,                        \
                 intptr_t __cdecl prefix ## uxen_handle_keypress        \
		 (unsigned char), uxen_do_handle_keypress);		\
    UXEN_GET_SYM(prefix ## uxen_shutdown_xen,                           \
                 void __cdecl prefix ## uxen_shutdown_xen               \
		 (void), uxen_do_shutdown_xen);				\
    UXEN_GET_SYM(prefix ## uxen_suspend_xen_prepare,                    \
                 void __cdecl prefix ## uxen_suspend_xen_prepare        \
		 (void), uxen_do_suspend_xen_prepare);                  \
    UXEN_GET_SYM(prefix ## uxen_suspend_xen,                            \
                 void __cdecl prefix ## uxen_suspend_xen                \
		 (void), uxen_do_suspend_xen);				\
    UXEN_GET_SYM(prefix ## uxen_resume_xen,                             \
                 void __cdecl prefix ## uxen_resume_xen                 \
		 (void), uxen_do_resume_xen);				\
    UXEN_GET_SYM(prefix ## uxen_hypercall,                              \
                 intptr_t __cdecl prefix ## uxen_hypercall              \
                 (struct uxen_hypercall_desc *, struct vm_info_shared *, \
                  void *, uint32_t), uxen_do_hypercall);                \
    UXEN_GET_SYM(prefix ## uxen_process_ud2,                            \
                 intptr_t __cdecl prefix ## uxen_process_ud2            \
		 (struct cpu_user_regs *), uxen_do_process_ud2);        \
    UXEN_GET_SYM(prefix ## uxen_lookup_symbol,                          \
                 intptr_t __cdecl prefix ## uxen_lookup_symbol          \
		 (uint64_t, char *, uint32_t), uxen_do_lookup_symbol);	\
    UXEN_GET_SYM(prefix ## uxen_flush_rcu,                              \
                 intptr_t __cdecl prefix ## uxen_flush_rcu              \
                 (uint32_t), uxen_do_flush_rcu);                        \
    UXEN_GET_SYM(__per_cpu_start, uint8_t __per_cpu_start,              \
		 uxen_addr_per_cpu_start);                              \
    UXEN_GET_SYM(__per_cpu_data_end, uint8_t __per_cpu_data_end,        \
		 uxen_addr_per_cpu_data_end);                           \
    return 0;								\
}

#define UXEN_CLEAR_SYMS(fn_name) void					\
    fn_name(void)							\
{									\
									\
    uxen_info = NULL;							\
    uxen_do_start_xen = NULL;						\
    uxen_do_add_heap_memory = NULL;                                     \
    uxen_do_lookup_vm = NULL;						\
    uxen_do_setup_vm = NULL;						\
    uxen_do_run_vcpu = NULL;						\
    uxen_do_destroy_vm = NULL;						\
    uxen_do_dispatch_ipi = NULL;					\
    uxen_do_run_idle_thread = NULL;                                     \
    uxen_do_handle_keypress = NULL;					\
    uxen_do_shutdown_xen = NULL;					\
    uxen_do_suspend_xen_prepare = NULL;                                 \
    uxen_do_suspend_xen = NULL;                                         \
    uxen_do_resume_xen = NULL;                                          \
    uxen_do_hypercall = NULL;						\
    uxen_do_process_ud2 = NULL;						\
    uxen_do_lookup_symbol = NULL;					\
    uxen_do_flush_rcu = NULL;                                           \
    uxen_addr_per_cpu_start = 0;                                        \
    uxen_addr_per_cpu_data_end = 0;                                     \
}
#endif

#endif
