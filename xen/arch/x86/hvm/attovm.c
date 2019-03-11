/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/v4v.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <asm/hvm/ax.h>
#include <asm/hvm/attovm.h>
#include <asm/hvm/rtc.h>
#include <public/sched.h>

static inline struct attovm_control *vmctrl(void)
{
    BUG_ON(this_cpu(current_vmcs_vmx)->vmcs->vmcs_revision_id !=
        PV_VMCS_ATTOVM_REV);

    return (struct attovm_control*)this_cpu(current_vmcs_vmx)->vmcs;
}

void
attovm_initialise(struct domain *d)
{
    if (ax_present)
        attovm_call_create(d->domain_id);
}

int
attovm_assign_token(struct domain *d, uint128_t *token)
{
    return ax_present ? attovm_call_assign_token(d->domain_id, token)
                      : -ENODEV;
}

void
attovm_destroy(struct domain *d)
{
    if (ax_present)
        attovm_call_destroy(d->domain_id);
}

void
attovm_vcpu_initialise(struct vcpu *v)
{
    if (ax_present)
        attovm_call_vcpu_init(v->domain->domain_id, v->vcpu_id);
}

void
attovm_vcpu_destroy(struct vcpu *v)
{
}

void
attovm_prepare_enter(struct vcpu *v)
{
    struct attovm_control *vmc = vmctrl();
    struct attovm_assist  *vma = &vmc->assist;

    /* domid + vcpu id */
    vmc->domain_id = v->domain->domain_id;
    vmc->vcpu_id = v->vcpu_id;
    vmc->tsc_offset = v->arch.hvm_vcpu.cache_tsc_offset;

    if (v->arch.hvm_vcpu.attovm.awaiting_stor_bitmap) {
        v->arch.hvm_vcpu.attovm.awaiting_stor_bitmap = 0;
        vma->x.query_stor_bitmap.bitmap = v->arch.user_regs.eax & 0xffff;
    }
}

enum hvm_intblk
attovm_intblk(void)
{
    /* block irq ack if another vector is still pending */
    return vmctrl()->is_irq_vector_pending ? hvm_intblk_arch : hvm_intblk_none;
}

void
attovm_inject_extint(uint8_t vector)
{
    struct attovm_control *vmc = vmctrl();

    vmc->pending_irq_vector = vector;
    vmc->is_irq_vector_pending = 1;
}

void
attovm_assist(struct vcpu *v)
{
    struct attovm_assist *vma = &vmctrl()->assist;

    switch (vma->op) {
    case ATTOVM_ASSIST_SIGNAL_DOMAIN: {
        uint64_t domid = vma->x.signal_domain.domain_id;
        v4v_signal_domid ((domid_t)domid);
        break;
    }
    case ATTOVM_ASSIST_READ_RTC: {
        struct RTCState *vrtc = vcpu_vrtc(current);
        uint64_t reg = vma->x.read_rtc.reg;
        uint32_t val;
        rtc_ioport_write(vrtc, 0x70, (int)reg);
        val = rtc_ioport_read(vrtc, 0x71);
        vma->x.read_rtc.value = val;
        break;
    }
    case ATTOVM_ASSIST_LAPIC_READ_MEM: {
        uint32_t reg = (uint32_t) vma->x.readwrite_lapic.reg;
        uint32_t val = 0;
        if (reg <= sizeof(struct hvm_hw_lapic_regs) - sizeof(uint32_t))
            val = vlapic_get_reg(vcpu_vlapic(current), reg);
        vma->x.readwrite_lapic.value = val;
        break;
    }
    case ATTOVM_ASSIST_LAPIC_WRITE_MEM: {
        uint32_t reg = (uint32_t) vma->x.readwrite_lapic.reg;
        uint32_t val = (uint32_t) vma->x.readwrite_lapic.value;
        if (reg <= sizeof(struct hvm_hw_lapic_regs) - sizeof(uint32_t))
            vlapic_reg_write(current, reg, val);
        break;
    }
    case ATTOVM_ASSIST_IOAPIC_READ_MEM: {
        uint32_t reg = (uint32_t) vma->x.readwrite_ioapic.reg;
        unsigned long val = 0;
        vioapic_read(current, reg, 4, &val);
        if (reg <= VIOAPIC_MEM_LENGTH - sizeof(uint32_t))
            vma->x.readwrite_ioapic.value = val;
        break;
    }
    case ATTOVM_ASSIST_IOAPIC_WRITE_MEM: {
        uint32_t reg = (uint32_t) vma->x.readwrite_ioapic.reg;
        unsigned long val = (unsigned long) vma->x.readwrite_ioapic.value;
        if (reg <= VIOAPIC_MEM_LENGTH - sizeof(uint32_t))
            vioapic_write(current, reg, 4, val);
        break;
    }
    case ATTOVM_ASSIST_TSC_DEADLINE_RDMSR: {
        vma->x.readwrite_tsc_deadline.value =
            vlapic_tdt_msr_get(vcpu_vlapic(current));
        break;
    }
    case ATTOVM_ASSIST_TSC_DEADLINE_WRMSR: {
        vlapic_tdt_msr_set(
            vcpu_vlapic(current),
            vma->x.readwrite_tsc_deadline.value);
        break;
    }
    case ATTOVM_ASSIST_QUERY_TSC_KHZ: {
        vma->x.query_tsc_khz.tsc_khz = current->domain->arch.tsc_khz;
        break;
    }
    case ATTOVM_ASSIST_SUSPEND: {
        domain_shutdown(current->domain, SHUTDOWN_suspend);
        break;
    }
    case ATTOVM_ASSIST_LOG: {
        hvm_print_char((char)vma->x.log.chr);
        break;
    }
    case ATTOVM_ASSIST_QUERY_STOR_BITMAP: {
        if (handle_pio(0x330, 2, IOREQ_READ))
            v->arch.hvm_vcpu.attovm.awaiting_stor_bitmap = 1;
        break;
    }
    default:
        break;
    }
}

static void
dump_hash(uint8_t *hash, size_t bytes)
{
    int i;

    for (i = 0; i < bytes; i++)
        printk(XENLOG_WARNING "%02x", hash[i]);
}

int
attovm_seal(struct domain *d, struct attovm_definition_v1 *def)
{
    int ret;

    printk(XENLOG_WARNING "seal vm%u\n", d->domain_id);
    printk(XENLOG_WARNING "memory hash: ");
    dump_hash(def->hash, sizeof(def->hash));
    printk(XENLOG_WARNING "\n");
    printk(XENLOG_WARNING "memory signature: ");
    dump_hash(def->hashsig, sizeof(def->hashsig));
    printk(XENLOG_WARNING "\n");

    ret = ax_present ? attovm_call_seal(d->domain_id, def) : -ENODEV;
    if (ret)
        printk(XENLOG_ERR "FAILED to seal vm%u, error %d\n", d->domain_id, ret);
    else
        printk(XENLOG_INFO "seal vm%u SUCCESS\n", d->domain_id);

    return ret;
}

int
attovm_get_guest_pages(struct domain *d, uint64_t pfn, uint64_t count,
                       XEN_GUEST_HANDLE(void) buffer)
{
    int ret =
      ax_present ? attovm_call_get_guest_pages(d->domain_id, pfn,
                                               count, buffer.p)
                 : -ENODEV;
    if (ret)
        printk(XENLOG_ERR "FAILED to get guest pages vm%u, error %d\n",
            d->domain_id, ret);

    return ret;
}

int
attovm_get_guest_cpu_state(struct domain *d, uint32_t vcpu,
                           XEN_GUEST_HANDLE(void) buffer, uint32_t buffer_size)
{
    int ret =
      ax_present ? attovm_call_get_guest_cpu_state(d->domain_id, vcpu,
                                                   buffer.p, buffer_size)
                 : -ENODEV;
    if (ret)
        printk(
            XENLOG_ERR "FAILED to get guest vcpu state vm%u.%u, error %d\n",
            d->domain_id, vcpu, ret);

    return ret;
}

int
attovm_kbd_focus(struct domain *d, uint32_t offer_focus)
{
    return ax_present ? attovm_call_kbd_focus(d->domain_id, offer_focus)
                      : -ENODEV;
}

int
attovm_do_cpuid(struct cpu_user_regs *regs)
{
    switch (regs->eax) {
    case ATTOCALL_QUERYOP:
        if (regs->ecx == ATTOCALL_QUERYOP_TSC_KHZ) {
            regs->eax = current->domain->arch.tsc_khz;

            return 1;
        }
        break;
    default:
        break;
    }

    return 0;
}
