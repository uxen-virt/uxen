/*
 *  uxen_link.h
 *  uxen
 *
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_LINK_H_
#define _UXEN_LINK_H_

#include "uxen_os.h"

#if defined(__x86_64__)
#define UXEN_INTERFACE_FN(fn) __interface_fn fn
#else  /* __x86_64__ */
#define UXEN_INTERFACE_FN(fn) __interface_fn _ ## fn
#endif  /* __x86_64__ */

#if defined(UXEN_DEFINE_SYMBOLS_PROTO) || defined(UXEN_DEFINE_SYMBOLS_CODE)

#include "uxen_desc.h"

#if defined(UXEN_DEFINE_SYMBOLS_CODE)
#define UXEN_LINK_PROTO_TYPE
#else
#define UXEN_LINK_PROTO_TYPE extern
#endif

UXEN_LINK_PROTO_TYPE struct uxen_info *uxen_info;

intptr_t __cdecl __uxen_start_xen(const struct uxen_init_desc *, uint64_t,
                                  struct vm_info_shared *,
                                  struct vm_vcpu_info_shared **);
#define uxen_do_start_xen __uxen_start_xen

void __cdecl __uxen_add_heap_memory(uint64_t, uint64_t);
#define uxen_do_add_heap_memory __uxen_add_heap_memory

intptr_t __cdecl __uxen_lookup_vm(xen_domain_handle_t);
#define uxen_do_lookup_vm __uxen_lookup_vm

intptr_t __cdecl __uxen_setup_vm(struct uxen_createvm_desc *,
                                 struct vm_info_shared *,
                                 struct vm_vcpu_info_shared **);
#define uxen_do_setup_vm __uxen_setup_vm

intptr_t __cdecl __uxen_run_vcpu(uint32_t, uint32_t);
#define uxen_do_run_vcpu __uxen_run_vcpu

intptr_t __cdecl __uxen_destroy_vm(xen_domain_handle_t);
#define uxen_do_destroy_vm __uxen_destroy_vm

void __cdecl __uxen_dispatch_ipi(unsigned int);
#define uxen_do_dispatch_ipi __uxen_dispatch_ipi

void __cdecl __uxen_run_idle_thread(uint32_t);
#define uxen_do_run_idle_thread __uxen_run_idle_thread

intptr_t __cdecl __uxen_handle_keypress(unsigned char);
#define uxen_do_handle_keypress __uxen_handle_keypress

void __cdecl __uxen_shutdown_xen(void);
#define uxen_do_shutdown_xen __uxen_shutdown_xen

void __cdecl __uxen_suspend_xen_prepare(void);
#define uxen_do_suspend_xen_prepare __uxen_suspend_xen_prepare

void __cdecl __uxen_suspend_xen(void);
#define uxen_do_suspend_xen __uxen_suspend_xen

void __cdecl __uxen_resume_xen(void);
#define uxen_do_resume_xen __uxen_resume_xen

intptr_t __cdecl __uxen_hypercall(struct uxen_hypercall_desc *,
                                  struct vm_info_shared *,
                                  void *, uint32_t);
#define uxen_do_hypercall __uxen_hypercall

intptr_t __cdecl __uxen_process_ud2(struct cpu_user_regs *);
#define uxen_do_process_ud2 __uxen_process_ud2

intptr_t __cdecl __uxen_lookup_symbol(uint64_t, char *, uint32_t);
#define uxen_do_lookup_symbol __uxen_lookup_symbol

intptr_t __cdecl __uxen_flush_rcu(uint32_t);
#define uxen_do_flush_rcu __uxen_flush_rcu

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

#define UXEN_GET_SYM(n, t, v) do {					\
	extern t;                                                       \
	v = &n;                                                         \
	dprintk("sym %s = %p\n", #v, v);				\
    } while (/* CONSTCOND */0)

#define UXEN_GET_SYMS(fn_name, prefix) int                              \
    fn_name(struct elf_binary *elf, unsigned char *hv,			\
            const char **missing_symbol)				\
{									\
									\
    /* _uxen_info resolves to _uxen_info, while __uxen_info would */    \
    /* resolve to uxen_info */                                          \
    UXEN_GET_SYM(prefix ## _uxen_info,                                  \
                 struct uxen_info prefix ## _uxen_info, uxen_info);     \
    UXEN_GET_SYM(prefix ## _per_cpu_start, uint8_t prefix ## _per_cpu_start, \
		 uxen_addr_per_cpu_start);                              \
    UXEN_GET_SYM(prefix ## _per_cpu_data_end,                           \
                 uint8_t prefix ## _per_cpu_data_end,                   \
		 uxen_addr_per_cpu_data_end);                           \
    return 0;								\
}

#define UXEN_CLEAR_SYMS(fn_name) void					\
    fn_name(void)							\
{									\
									\
    uxen_info = NULL;							\
    uxen_addr_per_cpu_start = 0;                                        \
    uxen_addr_per_cpu_data_end = 0;                                     \
}
#endif

#endif
