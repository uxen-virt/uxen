/*
 * hvm.h: Hardware virtual machine assist interface definitions.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __ASM_X86_HVM_HVM_H__
#define __ASM_X86_HVM_HVM_H__

#include <asm/current.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/asid.h>
#include <public/domctl.h>
#include <public/hvm/save.h>

struct p2m_domain;

/* Interrupt acknowledgement sources. */
enum hvm_intsrc {
    hvm_intsrc_none,
    hvm_intsrc_pic,
    hvm_intsrc_lapic,
    hvm_intsrc_nmi,
    hvm_intsrc_mce,
    hvm_intsrc_vector
};
struct hvm_intack {
    uint8_t source; /* enum hvm_intsrc */
    uint8_t vector;
};
#define hvm_intack(src, vec)   ((struct hvm_intack) { hvm_intsrc_##src, vec })
#define hvm_intack_none        hvm_intack(none, 0)
#define hvm_intack_pic(vec)    hvm_intack(pic, vec)
#define hvm_intack_lapic(vec)  hvm_intack(lapic, vec)
#define hvm_intack_nmi         hvm_intack(nmi, 2)
#define hvm_intack_mce         hvm_intack(mce, 18)
#define hvm_intack_vector(vec) hvm_intack(vector, vec)
enum hvm_intblk {
    hvm_intblk_none,      /* not blocked (deliverable) */
    hvm_intblk_shadow,    /* MOV-SS or STI shadow */
    hvm_intblk_rflags_ie, /* RFLAGS.IE == 0 */
    hvm_intblk_tpr,       /* LAPIC TPR too high */
    hvm_intblk_nmi_iret,  /* NMI blocked until IRET */
    hvm_intblk_arch,      /* SVM/VMX specific reason */
};

/* These happen to be the same as the VMX interrupt shadow definitions. */
#define HVM_INTR_SHADOW_STI    0x00000001
#define HVM_INTR_SHADOW_MOV_SS 0x00000002
#define HVM_INTR_SHADOW_SMI    0x00000004
#define HVM_INTR_SHADOW_NMI    0x00000008

/*
 * HAP super page capabilities:
 * bit0: if 2MB super page is allowed?
 * bit1: if 1GB super page is allowed?
 */
#define HVM_HAP_SUPERPAGE_2MB   0x00000001
#define HVM_HAP_SUPERPAGE_1GB   0x00000002

enum hvmon {
    hvmon_off = 0,
    hvmon_on = 1,
    hvmon_always = 2,           /* leave hvmon across schedule */
};

DECLARE_PER_CPU(enum hvmon, hvmon);
extern enum hvmon hvmon_default;

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    char *name;

    /* Support Hardware-Assisted Paging? */
    int hap_supported;

    /* Indicate HAP capabilities. */
    int hap_capabilities;
};

extern struct hvm_function_table hvm_funcs;

#define EXIT_INFO_guest_linear_address 0
#define EXIT_INFO_per_cpu_segment_base 1

#define HVM_FUNCS_proto(prefix) \
    /* Initialise/destroy HVM domain/vcpu resources */                  \
    int prefix ## _domain_initialise(struct domain *d);                 \
    void prefix ## _domain_destroy(struct domain *d);                   \
    void prefix ## _domain_relinquish_memory(struct domain *d);         \
    int prefix ## _vcpu_initialise(struct vcpu *v);                     \
    void prefix ## _vcpu_destroy(struct vcpu *v);                       \
                                                                        \
    /* save and load hvm guest cpu context for save/restore */          \
    void prefix ## _save_cpu_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt); \
    int prefix ## _load_cpu_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt); \
                                                                        \
    /* Examine specifics of the guest state. */                         \
    unsigned int prefix ## _get_interrupt_shadow(struct vcpu *v);       \
    void prefix ## _set_interrupt_shadow(struct vcpu *v,                \
                                         unsigned int intr_shadow);     \
    int prefix ## _guest_x86_mode(struct vcpu *v);                      \
    void prefix ## _get_segment_register(struct vcpu *v, enum x86_segment seg, \
                                         struct segment_register *reg); \
    void prefix ## _set_segment_register(struct vcpu *v, enum x86_segment seg, \
                                         struct segment_register *reg); \
                                                                        \
    /* Re-set the value of CR3 that Xen runs on when handling VM exits. */ \
    void prefix ## _update_host_cr3(struct vcpu *v);                    \
                                                                        \
    /* Called to inform HVM layer that a guest CRn or EFER has changed. */ \
    int prefix ## _update_guest_cr(struct vcpu *v, unsigned int cr);    \
    void prefix ## _update_guest_efer(struct vcpu *v);                  \
                                                                        \
    void prefix ## _set_tsc_offset(struct vcpu *v, u64 offset);         \
    void prefix ## _inject_exception(unsigned int trapnr, int errcode,  \
                                     unsigned long cr2);                \
    void prefix ## _init_hypercall_page(struct domain *d,               \
                                        void *hypercall_page);          \
    int prefix ## _event_pending(struct vcpu *v);                       \
    int prefix ## _do_pmu_interrupt(struct cpu_user_regs *regs);        \
    void prefix ## _do_execute(struct vcpu *v);                         \
    void prefix ## _do_suspend(struct vcpu *v);                         \
    void prefix ## _pt_maybe_sync_cpu_no_lock(struct domain *d,         \
                                              unsigned int cpu);        \
    int prefix ## _cpu_up_prepare(unsigned int cpu);                    \
    void prefix ## _cpu_dead(unsigned int cpu);                         \
    int prefix ## _cpu_on(void);                                        \
    void prefix ## _cpu_off(void);                                      \
    int prefix ## _cpu_up(enum hvmon);                                  \
    void prefix ## _cpu_down(void);                                     \
    void prefix ## _dump_vcpu(struct vcpu *v, const char *from);        \
    uintptr_t prefix ## _exit_info(struct vcpu *v, unsigned int field); \
                                                                        \
    /* Copy up to 15 bytes from cached instruction bytes at current rIP. */ \
    unsigned int prefix ## _get_insn_bytes(struct vcpu *v, uint8_t *buf); \
                                                                        \
    /* Instruction intercepts: non-void return values are X86EMUL codes. */ \
    void prefix ## _cpuid_intercept(unsigned int *eax, unsigned int *ebx, \
                                    unsigned int *ecx, unsigned int *edx); \
    void prefix ## _wbinvd_intercept(void);                             \
    void prefix ## _fpu_dirty_intercept(void);                          \
    int prefix ## _msr_read_intercept(unsigned int msr,                 \
                                      uint64_t *msr_content);           \
    int prefix ## _msr_write_intercept(unsigned int msr,                \
                                       uint64_t msr_content);           \
    void prefix ## _invlpg_intercept(unsigned long vaddr);              \
                                                                        \
    void prefix ## _set_uc_mode(struct vcpu *v);                        \
    void prefix ## _set_info_guest(struct vcpu *v);                     \
    void prefix ## _set_rdtsc_exiting(struct vcpu *v, bool_t);          \
    bool_t prefix ## _ple_enabled(struct vcpu *v);                      \
                                                                        \
    void prefix ## _ctxt_switch_from(struct vcpu *v);                   \
    void prefix ## _ctxt_switch_to(struct vcpu *v);

#ifndef __UXEN_NOT_YET__
    /* Nested HVM */                                                    \
    int prefix ## _nhvm_vcpu_initialise(struct vcpu *v);                \
    void prefix ## _nhvm_vcpu_destroy(struct vcpu *v);                  \
    int prefix ## _nhvm_vcpu_reset(struct vcpu *v);                     \
    int prefix ## _nhvm_vcpu_hostrestore(struct vcpu *v,                \
                                         struct cpu_user_regs *regs);   \
    int prefix ## _nhvm_vcpu_vmexit(struct vcpu *v,                     \
                                    struct cpu_user_regs *regs,         \
                                    uint64_t exitcode);                 \
    int prefix ## _nhvm_vcpu_vmexit_trap(struct vcpu *v,                \
                                         unsigned int trapnr,           \
                                         int errcode,                   \
                                         unsigned long cr2);            \
    uint64_t prefix ## _nhvm_vcpu_guestcr3(struct vcpu *v);             \
    uint64_t prefix ## _nhvm_vcpu_hostcr3(struct vcpu *v);              \
    uint32_t prefix ## _nhvm_vcpu_asid(struct vcpu *v);                 \
    int prefix ## _nhvm_vmcx_guest_intercepts_trap(struct vcpu *v,      \
                                                   unsigned int trapnr, \
                                                   int errcode);        \
    bool_t prefix ## _nhvm_vmcx_hap_enabled(struct vcpu *v);            \
    enum hvm_intblk prefix ## _nhvm_intr_blocked(struct vcpu *v);
#endif  /* __UXEN_NOT_YET__ */

HVM_FUNCS_proto(vmx)
HVM_FUNCS_proto(svm)

#define HVM_FUNCS(fn, ...) (                              \
        (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) ?  \
        vmx_ ## fn(__VA_ARGS__) : svm_ ## fn(__VA_ARGS__) \
        )
/* intel only */
// #define HVM_FUNCS(fn, args) (vmx_ ## fn(args))
/* amd only */
// #define HVM_FUNCS(fn, args) (svm_ ## fn(args))

extern bool_t hvm_enabled;
extern bool_t cpu_has_lmsl;
#ifndef __UXEN__
extern s8 hvm_port80_allowed;
#else  /* __UXEN__ */
#define hvm_port80_allowed 1
#endif  /* __UXEN__ */

extern struct hvm_function_table *start_svm(void);
extern struct hvm_function_table *start_vmx(void);

int hvm_domain_initialise(struct domain *d);
void hvm_relinquish_memory(struct domain *d);
void hvm_domain_relinquish_resources(struct domain *d);
void hvm_domain_destroy(struct domain *d);

int hvm_vcpu_initialise(struct vcpu *v);
void hvm_vcpu_destroy(struct vcpu *v);
void hvm_vcpu_down(struct vcpu *v);
int hvm_vcpu_cacheattr_init(struct vcpu *v);
void hvm_vcpu_cacheattr_destroy(struct vcpu *v);
void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip);

bool_t hvm_send_assist_req(struct vcpu *v);
bool_t hvm_send_dmreq(struct vcpu *v);
bool_t hvm_send_dom0_dmreq(struct domain *d);

void hvm_set_zp_prefix(struct domain *d);

void hvm_set_guest_tsc(struct vcpu *v, u64 guest_tsc);
u64 hvm_get_guest_tsc(struct vcpu *v);

void hvm_init_guest_time(struct domain *d);
void hvm_set_guest_time(struct vcpu *v, u64 guest_time);
u64 hvm_get_guest_time(struct vcpu *v);

int vmsi_deliver(
    struct domain *d, int vector,
    uint8_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode);
struct hvm_pirq_dpci;
int vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *);
int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode);

#define hvm_paging_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG))
#define hvm_wp_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[0] & X86_CR0_WP))
#define hvm_pae_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PAE))
#define hvm_smep_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_SMEP))
#define hvm_nx_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_efer & EFER_NX))

/* Can we use superpages in the HAP p2m table? */
#define hvm_hap_has_1gb(d) \
    (hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_1GB)
#define hvm_hap_has_2mb(d) \
    (hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_2MB)

/* Can the guest use 1GB superpages in its own pagetables? */
#define hvm_pse1gb_supported(d) \
    (cpu_has_page1gb && paging_mode_hap(d))

#ifdef __x86_64__
#define hvm_long_mode_enabled(v) \
    ((v)->arch.hvm_vcpu.guest_efer & EFER_LMA)
#else
#define hvm_long_mode_enabled(v) (v,0)
#endif

enum hvm_intblk
hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack);

static inline int
hvm_guest_x86_mode(struct vcpu *v)
{
    ASSERT(v == current);
    return HVM_FUNCS(guest_x86_mode, v);
}

static inline void
hvm_update_host_cr3(struct vcpu *v)
{
    HVM_FUNCS(update_host_cr3, v);
}

static inline int hvm_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    return HVM_FUNCS(update_guest_cr, v, cr);
}

static inline void hvm_update_guest_efer(struct vcpu *v)
{
    HVM_FUNCS(update_guest_efer, v);
}

/*
 * Called to ensure than all guest-specific mappings in a tagged TLB are 
 * flushed; does *not* flush Xen's TLB entries, and on processors without a 
 * tagged TLB it will be a noop.
 */
static inline void hvm_flush_guest_tlbs(void)
{
    if ( hvm_enabled )
        hvm_asid_flush_core();
}

void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page);

static inline void
hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    HVM_FUNCS(get_segment_register, v, seg, reg);
}

static inline void
hvm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    HVM_FUNCS(set_segment_register, v, seg, reg);
}

#define is_viridian_domain(_d)                                             \
 (is_hvm_domain(_d) && ((_d)->arch.hvm_domain.params[HVM_PARAM_VIRIDIAN]))

#define restricted_hvm_hypercalls(_d)                                   \
    (is_hvm_domain(_d) &&                                               \
     (_d)->arch.hvm_domain.params[HVM_PARAM_RESTRICTED_HYPERCALLS])

void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx);
void hvm_migrate_timers(struct vcpu *v);
void hvm_do_suspend(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);
void hvm_do_resume_trap(struct vcpu *v);
void hvm_migrate_pirqs(struct vcpu *v);

void hvm_inject_exception(unsigned int trapnr, int errcode, unsigned long cr2);

static inline int hvm_event_pending(struct vcpu *v)
{
    return HVM_FUNCS(event_pending, v);
}

static inline int hvm_do_pmu_interrupt(struct cpu_user_regs *regs)
{
    return HVM_FUNCS(do_pmu_interrupt, regs);
}

static inline void hvm_execute(struct vcpu *v)
{
    HVM_FUNCS(do_execute, v);
}

/* These reserved bits in lower 32 remain 0 after any load of CR0 */
#define HVM_CR0_GUEST_RESERVED_BITS             \
    (~((unsigned long)                          \
       (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM |  \
        X86_CR0_TS | X86_CR0_ET | X86_CR0_NE |  \
        X86_CR0_WP | X86_CR0_AM | X86_CR0_NW |  \
        X86_CR0_CD | X86_CR0_PG)))

/* These bits in CR4 are owned by the host. */
#define HVM_CR4_HOST_MASK (mmu_cr4_features & \
    (X86_CR4_VMXE | X86_CR4_PAE | X86_CR4_MCE))

#ifndef __UXEN__
#define HVM_CR4_GUEST_RESERVED_BITS_NESTED(_v)          \
       ((nestedhvm_enabled((_v)->domain) && cpu_has_vmx)\
                      ? X86_CR4_VMXE : 0)
#else   /* __UXEN__ */
#define HVM_CR4_GUEST_RESERVED_BITS_NESTED(_v) 0
#endif  /* __UXEN__ */

/* These bits in CR4 cannot be set by the guest. */
#define HVM_CR4_GUEST_RESERVED_BITS(_v)                 \
    (~((unsigned long)                                  \
       (X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD |       \
        X86_CR4_DE  | X86_CR4_PSE | X86_CR4_PAE |       \
        X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE |       \
        X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT |           \
        (cpu_has_smep ? X86_CR4_SMEP : 0) |             \
        (cpu_has_fsgsbase ? X86_CR4_FSGSBASE : 0) |     \
        HVM_CR4_GUEST_RESERVED_BITS_NESTED(_v) |        \
        (cpu_has_pcid ? X86_CR4_PCID : 0) |             \
        (xsave_enabled(_v) ? X86_CR4_OSXSAVE : 0))))

/* These exceptions must always be intercepted. */
#define HVM_TRAP_MASK ((1U << TRAP_debug)           | \
                       (1U << TRAP_alignment_check) | \
                       (1U << TRAP_machine_check))

/*
 * x86 event types. This enumeration is valid for:
 *  Intel VMX: {VM_ENTRY,VM_EXIT,IDT_VECTORING}_INTR_INFO[10:8]
 *  AMD SVM: eventinj[10:8] and exitintinfo[10:8] (types 0-4 only)
 */
#define X86_EVENTTYPE_EXT_INTR              0    /* external interrupt */
#define X86_EVENTTYPE_NMI                   2    /* NMI                */
#define X86_EVENTTYPE_HW_EXCEPTION          3    /* hardware exception */
#define X86_EVENTTYPE_SW_INTERRUPT          4    /* software interrupt */
#define X86_EVENTTYPE_SW_EXCEPTION          6    /* software exception */

int hvm_event_needs_reinjection(uint8_t type, uint8_t vector);

uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2);

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable);

bool_t hvm_ple_enabled(struct vcpu *v);

static inline int hvm_cpu_on(void)
{
    return HVM_FUNCS(cpu_on);
}

static inline void hvm_cpu_off(void)
{
    HVM_FUNCS(cpu_off);
}

static inline int hvm_cpu_up(enum hvmon hvmon_mode)
{
    return HVM_FUNCS(cpu_up, hvmon_mode);
}

static inline void hvm_cpu_down(void)
{
    HVM_FUNCS(cpu_down);
}

static inline void
hvm_dump_vcpu(struct vcpu *v, const char *from)
{
    HVM_FUNCS(dump_vcpu, v, from);
}

static inline uintptr_t
hvm_exit_info(struct vcpu *v, unsigned int field)
{
    return HVM_FUNCS(exit_info, v, field);
}

static inline unsigned int hvm_get_insn_bytes(struct vcpu *v, uint8_t *buf)
{
    return HVM_FUNCS(get_insn_bytes, v, buf);
}

enum hvm_task_switch_reason { TSW_jmp, TSW_iret, TSW_call_or_int };
void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode);

enum hvm_access_type {
    hvm_access_insn_fetch,
    hvm_access_none,
    hvm_access_read,
    hvm_access_write
};
int hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    unsigned int addr_size,
    unsigned long *linear_addr);

void *hvm_map_guest_frame_rw(unsigned long gfn);
void *hvm_map_guest_frame_ro(unsigned long gfn);
void hvm_unmap_guest_frame(void *p);

static inline void hvm_set_info_guest(struct vcpu *v)
{
    return HVM_FUNCS(set_info_guest, v);
}

int hvm_debug_op(struct vcpu *v, int32_t op);

int hvm_hap_nested_page_fault(unsigned long gpa,
                              bool_t gla_valid, unsigned long gla,
                              bool_t access_r,
                              bool_t access_w,
                              bool_t access_x);

/* We expose RDTSCP feature to guest only when
   tsc_mode == TSC_MODE_DEFAULT and host_tsc_is_safe() returns 1 */
#define hvm_has_rdtscp(d) \
    ((d)->arch.tsc_mode == TSC_MODE_DEFAULT && host_tsc_is_safe())
#define hvm_has_pvrdtscp(d) \
    ((d)->arch.tsc_mode == TSC_MODE_PVRDTSCP)

#define hvm_msr_tsc_aux(v) ({                                               \
    struct domain *__d = (v)->domain;                                       \
    (__d->arch.tsc_mode == TSC_MODE_PVRDTSCP)                               \
        ? (u32)__d->arch.incarnation : (u32)(v)->arch.hvm_vcpu.msr_tsc_aux; \
})

int hvm_x2apic_msr_read(struct vcpu *v, unsigned int msr, uint64_t *msr_content);
int hvm_x2apic_msr_write(struct vcpu *v, unsigned int msr, uint64_t msr_content);

void pt_maybe_sync_cpu(struct domain *d);
void pt_maybe_sync_cpu_enter(struct domain *d);
void pt_maybe_sync_cpu_leave(struct domain *d);
void pt_sync_domain(struct domain *d);

#ifdef __x86_64__
/* Called for current VCPU on crX changes by guest */
void hvm_memory_event_cr0(unsigned long value, unsigned long old);
void hvm_memory_event_cr3(unsigned long value, unsigned long old);
void hvm_memory_event_cr4(unsigned long value, unsigned long old);
/* Called for current VCPU on int3: returns -1 if no listener */
int hvm_memory_event_int3(unsigned long gla);

/* Called for current VCPU on single step: returns -1 if no listener */
int hvm_memory_event_single_step(unsigned long gla);

#else
static inline void hvm_memory_event_cr0(unsigned long value, unsigned long old)
{ }
static inline void hvm_memory_event_cr3(unsigned long value, unsigned long old)
{ }
static inline void hvm_memory_event_cr4(unsigned long value, unsigned long old)
{ }
static inline int hvm_memory_event_int3(unsigned long gla)
{ return 0; }
static inline int hvm_memory_event_single_step(unsigned long gla)
{ return 0; }
#endif

/*
 * Nested HVM
 */

/* Restores l1 guest state */
int nhvm_vcpu_hostrestore(struct vcpu *v, struct cpu_user_regs *regs);
/* Fill l1 guest's VMCB/VMCS with data provided by generic exit codes
 * (do conversion as needed), other misc SVM/VMX specific tweaks to make
 * it work */
int nhvm_vcpu_vmexit(struct vcpu *v, struct cpu_user_regs *regs,
                     uint64_t exitcode);
/* inject vmexit into l1 guest. l1 guest will see a VMEXIT due to
 * 'trapnr' exception.
 */ 
int nhvm_vcpu_vmexit_trap(struct vcpu *v,
    unsigned int trapnr, int errcode, unsigned long cr2);

/* returns l2 guest cr3 in l2 guest physical address space. */
uint64_t nhvm_vcpu_guestcr3(struct vcpu *v);
/* returns l1 guest's cr3 that points to the page table used to
 * translate l2 guest physical address to l1 guest physical address.
 */
uint64_t nhvm_vcpu_hostcr3(struct vcpu *v);
/* returns the asid number l1 guest wants to use to run the l2 guest */
uint32_t nhvm_vcpu_asid(struct vcpu *v);

/* returns true, when l1 guest intercepts the specified trap */
int nhvm_vmcx_guest_intercepts_trap(struct vcpu *v, 
                                    unsigned int trapnr, int errcode);

/* returns true when l1 guest wants to use hap to run l2 guest */
bool_t nhvm_vmcx_hap_enabled(struct vcpu *v);
/* interrupt */
enum hvm_intblk nhvm_interrupt_blocked(struct vcpu *v);

#endif /* __ASM_X86_HVM_HVM_H__ */
