/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/cpu.h>
#include <dm/whpx/apic.h>
#include <dm/vm.h>
#include <dm/control.h>
#include <dm/qemu/hw/isa.h>
#include <dm/shared-folders.h>
#include <dm/clipboard.h>
#include <public/hvm/hvm_info_table.h>
#include <public/hvm/e820.h>
#include <whpx-shared.h>
#include "whpx.h"
#include "winhvglue.h"
#include "winhvplatform.h"
#include "core.h"
#include "viridian.h"
#include "v4v-whpx.h"
#include "loader.h"
#include "emulate.h"
#include "util.h"
#include "dm-features.h"

/* acpi area */
#define ACPI_INFO_PHYSICAL_ADDRESS 0xFC000000
#define ACPI_INFO_SIZE 0x1000

/* memory for hvmloader allocations @ 0xfc001000+ */
#define HVMLOADER_ALLOC_ADDR 0xFC001000
#define HVMLOADER_ALLOC_MAX (1 * 1024 * 1024)

/* apic */
#define APIC_DEFAULT_PHYS_BASE 0xFEE00000

#define PERF_TIMER_PERIOD_MS 1000

static volatile uint32_t running_vcpus = 0;
static int shutdown_reason = 0;
static Timer *whpx_perf_timer;
static int vm_paused;
static uint64_t paused_tsc_value;

struct cpu_extra {
    HANDLE wake_ev;
    HANDLE stopped_ev;
};

#define extra(cpu) ((struct cpu_extra*)cpu->opaque)

struct qemu_work_item {
    struct qemu_work_item *next;
    void (*func)(CPUState *s, void *data);
    void *data;
    HANDLE ev_done;
};

enum xc_hvm_module_type {
    XC_HVM_MODULE_ACPI = 0,
    XC_HVM_MODULE_SMBIOS,
};

struct xc_hvm_mod_entry {
    int flags;
    size_t len;
    void *base;
};

struct xc_hvm_module {
    int type;
    size_t nent; /* Number of entries in the module */
    struct xc_hvm_mod_entry *entries;
};

CPUState cpu_state[32];
CPUState *first_cpu;
CPUInterruptHandler cpu_interrupt_handler;
static critical_section iothread_cs;
static DWORD current_cpu_tls;
static struct whpx_shared_info *shared_info_page;

/* struct domain for the single guest handled by this uxendm,
 * as required by v4v code */
struct domain guest;
extern int v4v_init(struct domain *);
extern int v4v_destroy(struct domain *);

/* represents host domain */
struct domain dom0;

static void tsc_pause(void);
static void tsc_resume(void);
static void tsc_resume_early(void);

void whpx_run_on_cpu(
    CPUState *env,
    int wait,
    void (*func)(CPUState *state, run_on_cpu_data data),
    run_on_cpu_data data)
{
    struct qemu_work_item wi;
    int ret;

    if (qemu_cpu_is_self(env)) {
        func(env, data);
        return;
    }

    wi.func = func;
    wi.data = data;
    /* FIXME: this doesn't seem thread safe but perhaps it is since its upstream code, verify */
    if (!env->queued_work_first)
        env->queued_work_first = &wi;
    else
        env->queued_work_last->next = &wi;
    env->queued_work_last = &wi;
    wi.next = NULL;
    if (wait) {
        wi.ev_done = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!wi.ev_done)
            whpx_panic("failed to create event\n");
    } else
        wi.ev_done = NULL;
    qemu_cpu_kick(env);

    if (wait) {
        ret = WaitForSingleObject(wi.ev_done, INFINITE);
        if (ret != WAIT_OBJECT_0)
            debug_printf("%s:%d: unexpected wait rval %d\n", __FUNCTION__, __LINE__, ret);
        CloseHandle(wi.ev_done);
    }
}

static void whpx_flush_queued_work(CPUState *env)
{
    struct qemu_work_item *wi;

    if (!env->queued_work_first)
        return;

    while ((wi = env->queued_work_first)) {
        env->queued_work_first = wi->next;
        wi->func(env, wi->data);
        if (wi->ev_done)
            SetEvent(wi->ev_done);
    }
    env->queued_work_last = NULL;
}

int whpx_cpu_is_stopped(CPUState *env)
{
    return (vm_get_run_mode() != RUNNING_VM) || env->stopped;
}

CPUState *whpx_get_cpu(int index)
{
    CPUState *env = first_cpu;

    while (env) {
        if (env->cpu_index == index)
            break;
        env = env->next_cpu;
    }

    return env;
}

CPUState *whpx_get_current_cpu(void)
{
    return (CPUState*)TlsGetValue(current_cpu_tls);
}

int whpx_cpu_is_self(void *env)
{
    CPUState *s = (CPUState*) env;

    return s->thread && (GetThreadId(s->thread) == GetCurrentThreadId());
}

void whpx_cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0)
{
    int pe_state;

#if defined(DEBUG_MMU)
    printf("CR0 update: CR0=0x%08x\n", new_cr0);
#endif
#ifndef QEMU_UXEN
    if ((new_cr0 & (CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK)) !=
        (env->cr[0] & (CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK))) {
        tlb_flush(env, 1);
    }
#endif

#ifdef TARGET_X86_64
    if (!(env->cr[0] & CR0_PG_MASK) && (new_cr0 & CR0_PG_MASK) &&
        (env->efer & MSR_EFER_LME)) {
        /* enter in long mode */
        /* XXX: generate an exception */
        if (!(env->cr[4] & CR4_PAE_MASK))
            return;
        env->efer |= MSR_EFER_LMA;
        env->hflags |= HF_LMA_MASK;
    } else if ((env->cr[0] & CR0_PG_MASK) && !(new_cr0 & CR0_PG_MASK) &&
               (env->efer & MSR_EFER_LMA)) {
        /* exit long mode */
        env->efer &= ~MSR_EFER_LMA;
        env->hflags &= ~(HF_LMA_MASK | HF_CS64_MASK);
        env->eip &= 0xffffffff;
    }
#endif
    env->cr[0] = new_cr0 | CR0_ET_MASK;

    /* update PE flag in hidden flags */
    pe_state = (env->cr[0] & CR0_PE_MASK);
    env->hflags = (env->hflags & ~HF_PE_MASK) | (pe_state << HF_PE_SHIFT);
    /* ensure that ADDSEG is always set in real mode */
    env->hflags |= ((pe_state ^ 1) << HF_ADDSEG_SHIFT);
    /* update FPU flags */
    env->hflags = (env->hflags & ~(HF_MP_MASK | HF_EM_MASK | HF_TS_MASK)) |
        ((new_cr0 << (HF_MP_SHIFT - 1)) & (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK));
}


void whpx_cpu_reset(CPUX86State *env)
{
    int i;

    debug_printf("CPU Reset (CPU %d)\n", env->cpu_index);

    memset(env, 0, offsetof(CPUX86State, breakpoints));

#ifndef QEMU_UXEN
    tlb_flush(env, 1);
#endif

    env->old_exception = -1;

    /* init to reset state */

#ifdef CONFIG_SOFTMMU
    env->hflags |= HF_SOFTMMU_MASK;
#endif
    env->hflags2 |= HF2_GIF_MASK;

    whpx_cpu_x86_update_cr0(env, 0x60000010);
    env->a20_mask = ~0x0;
    env->smbase = 0x30000;

    env->idt.limit = 0xffff;
    env->gdt.limit = 0xffff;
    env->ldt.limit = 0xffff;
    env->ldt.flags = DESC_P_MASK | (2 << DESC_TYPE_SHIFT);
    env->tr.limit = 0xffff;
    env->tr.flags = DESC_P_MASK | (11 << DESC_TYPE_SHIFT);

    /* unlike real hardware we'll start at 0 to make it simpler */
    cpu_x86_load_seg_cache(env, R_CS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_CS_MASK |
                           DESC_R_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_SS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);
    cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0xffff,
                           DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                           DESC_A_MASK);

    env->eip = 0;

    env->regs[R_EDX] = env->cpuid_version;

    env->eflags = 0x2;

    /* FPU init */
    for(i = 0;i < 8; i++)
        env->fptags[i] = 1;
    env->fpuc = 0x37f;

    env->mxcsr = 0x1f80;

    env->pat = 0x0007040600070406ULL;
    env->msr_ia32_misc_enable = MSR_IA32_MISC_ENABLE_DEFAULT;

    memset(env->dr, 0, sizeof(env->dr));
    env->dr[6] = DR6_FIXED_1;
    env->dr[7] = DR7_FIXED_1;
#ifndef QEMU_UXEN
    cpu_breakpoint_remove_all(env, BP_CPU);
    cpu_watchpoint_remove_all(env, BP_CPU);
#endif
}

void whpx_do_cpu_init(CPUState *env)
{
    int sipi = env->interrupt_request & CPU_INTERRUPT_SIPI;
    uint64_t pat = env->pat;

    whpx_cpu_reset(env);
    env->interrupt_request = sipi;
    env->pat = pat;
    //env->halted = !cpu_is_bsp(env);
    env->halted = false;
}

int whpx_register_pcidev(PCIDevice *dev)
{
    return 0;
}

void whpx_lock_iothread(void)
{
    critical_section_enter(&iothread_cs);
}

void whpx_unlock_iothread(void)
{
    critical_section_leave(&iothread_cs);
}

static int cpu_can_run(CPUState *cpu)
{
    return !cpu->halted;
}

void qemu_cpu_kick(CPUState *cpu)
{
    SetEvent(extra(cpu)->wake_ev);
    whpx_vcpu_kick(cpu);
}

int
whpx_v4v_signal(struct domain *domain)
{
    if (domain == &guest) {
        /* this can be called when vm is not yet initialized.. thanks guest-agent */
        if (vm_id) {
            qemu_set_irq(isa_get_irq(7), 1);
            qemu_set_irq(isa_get_irq(7), 0);
        } else
            debug_printf("v4v signal w/o initialized vm\n");
    } else {
        assert(domain == &dom0);
        whpx_v4v_handle_signal();
    }

    return 0;
}

static void
vcpu_stopped_cb(void *opaque)
{
    CPUState *cpu = opaque;

    debug_printf("vcpu%d stopped, running vcpus: %d\n", cpu->cpu_index, running_vcpus);
    if (!running_vcpus) {
        debug_printf("all vcpus stopped, reason: %d\n", shutdown_reason);
        if (shutdown_reason == WHPX_SHUTDOWN_PAUSE) {
            tsc_pause();
            vm_set_run_mode(PAUSE_VM);
        } else if (shutdown_reason == WHPX_SHUTDOWN_SUSPEND) {
            tsc_pause();
            v4v_destroy(&guest);
            vm_process_suspend(NULL);
        } else
            vm_set_run_mode(DESTROY_VM);
    }
}

void vcpu_create(CPUState *cpu)
{
    struct cpu_extra *ex;
    int err;

    cpu->env_ptr = cpu;
    cpu->stopped = 1;
    ex = calloc(1, sizeof(struct cpu_extra));
    if (!ex)
        whpx_panic("allocation failed\n");
    ex->wake_ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ex->wake_ev)
        whpx_panic("event creation failed\n");
    ex->stopped_ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ex->stopped_ev)
        whpx_panic("event creation failed\n");
    ioh_add_wait_object(&ex->stopped_ev, vcpu_stopped_cb, cpu, NULL);

    cpu->opaque = ex;
    /* initial vcpu register state */
    whpx_do_cpu_init(cpu);
    /* initial vcpu whpx state */
    err = whpx_init_vcpu(cpu);
    if (err)
        whpx_panic("failed to init whpx vcpu%d: %d\n", cpu->cpu_index, err);
}

void vcpu_destroy(CPUState *cpu)
{
    struct cpu_extra *ex = extra(cpu);

    ioh_del_wait_object(&ex->stopped_ev, NULL);
    CloseHandle(ex->wake_ev);
    CloseHandle(ex->stopped_ev);
    free(ex);
}

static void
run_vcpu(CPUState *s)
{
    uint32_t r, nr, or;

    debug_printf("execute vcpu%d, thread 0x%x\n", s->cpu_index, (int)GetCurrentThreadId());
    TlsSetValue(current_cpu_tls, s);

    while (!s->stopped) {
        int ret;

        whpx_flush_queued_work(s);

        if (cpu_can_run(s)) {
            ret = whpx_vcpu_exec(s);
            if (ret == EXCP_INTERRUPT) {
            } else if (ret == EXCP_HLT) {
            } else {
                debug_printf("vcpu%d EXCEPTION: %d\n", s->cpu_index, ret);
            }
        } else {
            // should not happen with apic virt, halt is handled in HV
            assert(false);
        }
    }

    r = running_vcpus;
    do {
        or = r;
        nr = or - 1;
    } while ((r = cmpxchg(&running_vcpus, or, nr)) != or);

    SetEvent(extra(s)->stopped_ev);

    debug_printf("vcpu%d exiting\n", s->cpu_index);
}

static DWORD WINAPI
whpx_vcpu_run_thread(PVOID opaque)
{
    CPUState *cpu = opaque;

    run_vcpu(cpu);

    return 0;
}

static void
whpx_vm_destroy(void)
{
    /* signal vcpus to exit */
    if (running_vcpus) {
        whpx_vm_shutdown(WHPX_SHUTDOWN_POWEROFF);
        /* wait for cpus to exit */
        whpx_unlock_iothread();
        whpx_vm_shutdown_wait();
        whpx_lock_iothread();
    }

    /* destroy cpus */
    CPUState *cpu = first_cpu;

    while (cpu) {
        whpx_destroy_vcpu(cpu);
        vcpu_destroy(cpu);
        cpu = cpu->next_cpu;
    }

    /* destroy v4v */
    whpx_v4v_shutdown();
    debug_printf("v4v destroy\n");
    v4v_destroy(&guest);
    debug_printf("v4v destroy done\n");

    /* destroy ram */
    whpx_ram_uninit();

    whpx_partition_destroy();

    VirtualFree(shared_info_page, 0, MEM_RELEASE);
    shared_info_page = NULL;

    memset(&guest, 0, sizeof(guest));
}

void
whpx_destroy(void)
{
    debug_printf("destroying whpx\n");
    whpx_vm_destroy();
}

void
whpx_vcpu_start(CPUState *s)
{
    HANDLE h;

    h = CreateThread(NULL, 0, whpx_vcpu_run_thread, s, CREATE_SUSPENDED, NULL);
    if (!h)
        whpx_panic("failed to create whpx vcpu thread: %d\n", (int)GetLastError());
    s->thread = h;
    s->stopped = 0;
    ResumeThread(h);
}

#define MAX_TSC_DESYNC 100000
#define MAX_TSC_PROPAGATE_ITERS 10000

static int
check_unreliable_tsc(void)
{
    WHV_REGISTER_NAME name = WHvX64RegisterTsc;
    WHV_REGISTER_VALUE v0;
    WHV_REGISTER_VALUE v1;

    if (FAILED(whpx_get_vp_registers(0, &name, 1, &v0)))
        whpx_panic("failed to get TSC value\n");
    Sleep(10);
    if (FAILED(whpx_get_vp_registers(0, &name, 1, &v1)))
        whpx_panic("failed to get TSC value\n");

    return !(v0.Reg64 == v1.Reg64);
}

static int
check_uniform_tsc(void)
{
    WHV_REGISTER_NAME name = WHvX64RegisterTsc;
    WHV_REGISTER_VALUE v0 = { };
    WHV_REGISTER_VALUE v1 = { };
    int i;

    for (i = 0; i < vm_vcpus; i++) {
        if (FAILED(whpx_get_vp_registers(i, &name, 1, &v0)))
            whpx_panic("failed to get TSC value\n");
        if (i >= 1) {
            if (v0.Reg64 != v1.Reg64)
                return 0;
        }
        v1 = v0;
    }

    return 1;
}

static uint64_t
read_max_tsc(void)
{
    WHV_REGISTER_NAME name;
    WHV_REGISTER_VALUE v;
    HRESULT hr;
    uint64_t tscval = 0;
    int i;

    name = WHvX64RegisterTsc;
    for (i = 0; i < vm_vcpus; i++) {
        hr = whpx_get_vp_registers(i, &name, 1, &v);
        if (FAILED(hr))
            whpx_panic("failed to get TSC value\n");
        if (v.Reg64 > tscval)
            tscval = v.Reg64;
    }

    return tscval;
}

static void
set_tsc_across_vcpus(uint64_t val)
{
    WHV_REGISTER_NAME name;
    WHV_REGISTER_VALUE v;
    HRESULT hr;
    int i;

    name = WHvX64RegisterTsc;
    for (i = 0; i < vm_vcpus; i++) {
        v.Reg64 = val;
        hr = whpx_set_vp_registers(i, &name, 1, &v);
        if (FAILED(hr))
            whpx_panic("failed to set TSC value: %08lx\n", hr);
    }
}

/* Sync TSC across vcpus by trying to propagate single value across all of them.
 * Only works perfectly if the partition has suspended time - older WHP does not have
 * explicit ability to suspend/resume partition time so this will leave some
 * undesirable desync */
static void
sync_vcpus_tsc(uint64_t tscval, int max_iters, int max_tsc_delta)
{
    uint64_t t0, dt = 0;
    int i;
    bool success = false;

    debug_printf("tsc value to propagate across vcpus: %"PRId64"\n", tscval);

    if (!max_iters)
        max_iters++;
    i = 0;
    while (i++ < max_iters) {
        t0 = _rdtsc();
        set_tsc_across_vcpus(tscval);
        dt = _rdtsc() - t0;
        if (!max_tsc_delta || dt <= max_tsc_delta) {
            success = true;
            break;
        }
    }

    if (success)
        debug_printf(
            "tsc value propagated (%d iterations), with delta: "
            "%"PRId64"\n", i, dt);
    else
        whpx_panic(
            "FAILED to propagate TSC with reasonably small delta, "
            "last delta=%"PRId64"\n", dt);
}

int
whpx_vm_start(void)
{
    int i;
    uint64_t start_tsc = read_max_tsc();

    debug_printf("vm start...\n");

    shutdown_reason = 0;
    vm_time_offset = 0;
    running_vcpus = vm_vcpus;

    if (check_unreliable_tsc()) {
        debug_printf("syncing unreliable TSC value\n");
        sync_vcpus_tsc(start_tsc, MAX_TSC_PROPAGATE_ITERS, MAX_TSC_DESYNC);
    } else {
        /* even with MS tsc bugfix which makes it possible to set consistent TSC value, still necessary to at least set initial uniform TSC
         * value rather than rely on per vcpu value in savefile. Value in
         * in savefile would typically be different per vcpu -> because it is queried at different time
         * points during save, and TSC is still progressing even with no vcpu running, and there's no API
         * to query TSC offset directly */
        debug_printf("syncing TSC value\n");
        sync_vcpus_tsc(start_tsc, 0, 0);

        if (!check_uniform_tsc())
            whpx_panic("TSC not uniform after sync");
    }

    tsc_resume_early();
    for (i = 0; i < vm_vcpus; i++)
        whpx_vcpu_start(&cpu_state[i]);
    tsc_resume();

    vm_set_run_mode(RUNNING_VM);

    return 0;
}

static void
tsc_pause(void)
{
    if (whpx_has_suspend_time)
        WHvSuspendPartitionTime(whpx_get_partition());
    else
        paused_tsc_value = read_max_tsc();
}

static void
tsc_resume(void)
{
    if (whpx_has_suspend_time)
        WHvResumePartitionTime(whpx_get_partition());
}

static void
tsc_resume_early(void)
{
    if (!whpx_has_suspend_time && paused_tsc_value) {
        debug_printf("propagating pause TSC value %"PRId64"\n", paused_tsc_value);
        sync_vcpus_tsc(paused_tsc_value, MAX_TSC_PROPAGATE_ITERS, MAX_TSC_DESYNC);
        paused_tsc_value = 0;
    }
}

int
whpx_vm_resume(void)
{
    /* init domain v4v. needs to be done early because
       some uxendm backends send v4v data before vm is properly initialized
       and rely on DLO */
    memset(&guest, 0, sizeof(guest));
    guest.domain_id = WHPX_DOMAIN_ID_SELF;
    critical_section_init(&guest.lock);
    v4v_init(&guest);

    return whpx_vm_start();
}

int
whpx_vm_is_paused(void)
{
    return vm_paused;
}

int
whpx_vm_pause(void)
{
    whpx_vm_shutdown(WHPX_SHUTDOWN_PAUSE);
    whpx_vm_shutdown_wait();
    viridian_timers_pause();
    vm_paused = 1;

    return 0;
}

int
whpx_vm_unpause(void)
{
    if (vm_paused) {
        viridian_timers_resume();
        whpx_vm_start();
        vm_paused = 0;
    }
    return 0;
}

// TODO: oem info (?)
static void
setup_hvm_info(void *base, uint64_t mem_size,
               uint32_t nr_vcpus, uint32_t modules_base)
//               struct xc_hvm_oem_info *oem_info)
{
    uint64_t lowmem_end = mem_size, highmem_end = 0;
    struct hvm_info_table *hvm_info = base + HVM_INFO_PADDR;
    uint8_t sum = 0;
    int i;

    memset(hvm_info, 0, sizeof(*hvm_info));

    if (lowmem_end > HVM_BELOW_4G_RAM_END) {
        highmem_end = lowmem_end + HVM_BELOW_4G_MMIO_LENGTH;
        lowmem_end = HVM_BELOW_4G_RAM_END;
    }

    /* Fill in the header. */
    strncpy(hvm_info->signature, "HVM INFO", 8);
    hvm_info->length = sizeof(struct hvm_info_table);

    /* Sensible defaults: these can be overridden by the caller. */
    hvm_info->apic_mode = 1;
    hvm_info->nr_vcpus = nr_vcpus;
    memset(hvm_info->vcpu_online, 0xff, sizeof(hvm_info->vcpu_online));

    /* Memory parameters. */
    hvm_info->low_mem_pgend = lowmem_end >> PAGE_SHIFT;
    hvm_info->high_mem_pgend = highmem_end >> PAGE_SHIFT;
    hvm_info->reserved_mem_pgstart = 0xFF000 - 32;

    /* Modules */
    hvm_info->mod_base = modules_base;

#if 0
    /* OEM info */
    if (oem_info && (oem_info->flags & XC_HVM_OEM_ID))
        memcpy(hvm_info->oem_info.oem_id, oem_info->oem_id, 6);
    else
        strncpy(hvm_info->oem_info.oem_id, "Xen", 6);

    if (oem_info && (oem_info->flags & XC_HVM_OEM_TABLE_ID))
        memcpy(hvm_info->oem_info.oem_table_id, oem_info->oem_table_id, 8);
    else
        strncpy(hvm_info->oem_info.oem_table_id, "HVM", 8);

    if (oem_info && (oem_info->flags & XC_HVM_OEM_REVISION))
        hvm_info->oem_info.oem_revision  = oem_info->oem_revision;
    else
        hvm_info->oem_info.oem_revision = 0;

    if (oem_info && (oem_info->flags & XC_HVM_CREATOR_ID))
        memcpy(hvm_info->oem_info.creator_id, oem_info->creator_id, 4);
    else
        strncpy(hvm_info->oem_info.creator_id, "HVML", 4);

    if (oem_info && (oem_info->flags & XC_HVM_CREATOR_REVISION))
        hvm_info->oem_info.creator_revision  = oem_info->creator_revision;
    else
        hvm_info->oem_info.creator_revision = 0;

    if (oem_info && (oem_info->flags & XC_HVM_SMBIOS_MAJOR))
        hvm_info->oem_info.smbios_version_major = oem_info->smbios_version_major;
    else
        hvm_info->oem_info.smbios_version_major = 2;

    if (oem_info && (oem_info->flags & XC_HVM_SMBIOS_MINOR))
        hvm_info->oem_info.smbios_version_minor = oem_info->smbios_version_minor;
    else
        hvm_info->oem_info.smbios_version_minor = 4;
#endif
    /* Finish with the checksum. */
    for ( i = 0, sum = 0; i < hvm_info->length; i++ )
        sum += ((uint8_t *)hvm_info)[i];
    hvm_info->checksum = -sum;
}

struct xc_hvm_module *vm_get_modules(int *mod_count);
void vm_cleanup_modules(struct xc_hvm_module *modules, size_t count);

static struct hvm_module_info *modules_init(struct xc_hvm_module *modules,
                                            size_t mod_count,
                                            size_t *out_len)
{
    struct hvm_module_info *hmi;
    struct xc_hvm_module *m;
    size_t len;
    int i, j;
    uint64_t *offsets;
    uint8_t sum;

    debug_printf("loading %d hvm modules\n", (int)mod_count);

    len = sizeof(*hmi);

    m = modules;
    for (i = 0; i < mod_count; i++) {
        len += sizeof(uint64_t); /* Offset */
        len += sizeof(struct hvm_module); /* Module Descriptor */
        for (j = 0; j < m->nent; j++) {
            len += sizeof (struct hvm_module_entry);
            len += m->entries[j].len;
        }
        m++;
    }

    hmi = calloc(1, (len + UXEN_PAGE_SIZE - 1) & ~(UXEN_PAGE_SIZE - 1));
    if (!hmi)
        return NULL;

    offsets = (uint64_t *)(hmi + 1);
    len = sizeof(*hmi) + mod_count * sizeof(uint64_t);

    for (i = 0; i < mod_count; i++) {
        struct hvm_module *mod = (void *)((uint8_t *)hmi + len);
        struct hvm_module_entry *entry = (void *)(mod + 1);

        offsets[i] = len;
        strncpy(mod->signature, "_HVMMOD_", 8);
        switch (modules[i].type) {
        case XC_HVM_MODULE_ACPI:
            mod->type = HVM_MODULE_ACPI;
            break;
        case XC_HVM_MODULE_SMBIOS:
            mod->type = HVM_MODULE_SMBIOS;
            break;
        default:
            goto out;
        }

        mod->length = sizeof(*mod);
        for (j = 0; j < modules[i].nent; j++) {
            entry->length = modules[i].entries[j].len;
            entry->flags = modules[i].entries[j].flags;

            memcpy(entry + 1, modules[i].entries[j].base, entry->length);
            mod->length += sizeof(*entry) + entry->length;

            entry = (void *)((uint8_t *)(entry + 1) + entry->length);
        }

        mod->count = j;
        mod->revision = 0;
        mod->checksum = 0;

        sum = 0;
        for (j = 0; j < mod->length; j++)
            sum += ((uint8_t *)mod)[j];
        mod->checksum = -sum;

        len += mod->length;
    }

    strncpy(hmi->signature, "_HVM_MI_", 8);
    hmi->length = sizeof(*hmi) + mod_count * sizeof(uint64_t);
    hmi->count = i;
    hmi->revision = 0;
    hmi->checksum = 0;

    sum = 0;
    for (j = 0; j < hmi->length; j++)
        sum += ((uint8_t *)hmi)[j];
    hmi->checksum = -sum;

    *out_len = (len + UXEN_PAGE_SIZE - 1) & ~(UXEN_PAGE_SIZE - 1);

    return hmi;
out:
    free(hmi);
    return NULL;
}

static int
load_modules(struct hvm_module_info *hmi,
             uint32_t mod_base, size_t mod_len)
{
    uint64_t maplen;
    void *dest;

    maplen = mod_len;
    dest = whpx_ram_map(mod_base, &maplen);
    if (!dest)
        whpx_panic("whpx_ram_map");
    if (maplen != mod_len)
        whpx_panic("short whpx_ram_map");
    debug_printf("copy hvm modules, target_addr=0x%x size = 0x%x\n", mod_base, (int)mod_len);
    memcpy(dest, hmi, mod_len);
    whpx_ram_unmap(dest);
    return 0;
}

void
add_hvm_modules(struct xc_hvm_module *modules, int count, uint64_t hvmloader_end)
{
    if (modules && count) {
        size_t modules_len = 0;
        struct hvm_module_info *hmi = NULL;
        /* Align to the next Megabyte */
        uint32_t base = (hvmloader_end + (1 << 20) - 1) & ~((1 << 20) - 1);

        hmi = modules_init(modules, count, &modules_len);
        if (!hmi)
            whpx_panic("failed to init hvm modules");
        if (load_modules(hmi, base, modules_len))
            whpx_panic("failed to load hvm modules");
    }
}

static void
whpx_shared_info_init(void)
{
    shared_info_page = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!shared_info_page)
        whpx_panic("no memory");

    shared_info_page->cpu_mhz = get_registry_cpu_mhz();

    if (whpx_ram_populate_with(WHP_SHARED_INFO_ADDR, PAGE_SIZE, shared_info_page, 0))
        whpx_panic("whpx_ram_populate");
}

static int
whpx_create_vm_memory(int memory_mb)
{
    uint64_t npages = memory_mb << 8;
    uint64_t npages_acpi = ACPI_INFO_SIZE >> PAGE_SHIFT;
    uint64_t npages_hvmloader = HVMLOADER_ALLOC_MAX >> PAGE_SHIFT;
    void *vm_mapped = 0;
    uint64_t mmap_len;

    /* main memory */
    if (whpx_ram_populate(0, npages * PAGE_SIZE, 0))
        whpx_panic("whpx_ram_populate");

    /* depopulate VGA hole */
    if (whpx_ram_depopulate(0xA0000, 0x20000, 0))
        whpx_panic("whpx_ram_depopulate");
    /* acpi info area */
    if (whpx_ram_populate(ACPI_INFO_PHYSICAL_ADDRESS, npages_acpi * PAGE_SIZE, 0))
        whpx_panic("whpx_ram_populate");

    /* hvmloader allocations */
    if (whpx_ram_populate(HVMLOADER_ALLOC_ADDR, npages_hvmloader * PAGE_SIZE, 0))
        whpx_panic("whpx_ram_populate");

    if (!vm_hpet) {
      /* no-op hpet area since some reads there are done to determine hpet presence */
      if (whpx_ram_populate(0xFED00000, PAGE_SIZE, 0))
          whpx_panic("whpx_ram_populate");
    }
    /* shared info page */
    whpx_shared_info_init();

    mmap_len = npages << PAGE_SHIFT;
    vm_mapped = whpx_ram_map(0, &mmap_len);
    if (!vm_mapped)
        whpx_panic("whpx_ram_map");

#ifdef DEBUG_SIMPLE_KERNEL
    load_simple_kernel("kernel.bin", vm_mapped);
#else
    uint64_t hvmloader_start = 0, hvmloader_end = 0;
    // hvmloader
    load_hvmloader(vm_mapped, &hvmloader_start, &hvmloader_end);
    // trampoline at 0x0000 to turn on protected mode and jmp to hvmloader
    load_pmode_trampoline(vm_mapped, hvmloader_start);

    struct xc_hvm_module *modules;
    int modules_count = 0;

    modules = vm_get_modules(&modules_count);
    debug_printf("hvm modules count: %d\n", modules_count);
    add_hvm_modules(modules, modules_count, hvmloader_end);
    vm_cleanup_modules(modules, modules_count);
#endif

    setup_hvm_info(vm_mapped, ((uint64_t)memory_mb) << 20, vm_vcpus, 0);

    return 0;
}

extern void pit_init(void);

void
whpx_debug_char(char data)
{
    static char line[2048];
    static int llen = 0;

    whpx_lock_iothread();
    if (llen < sizeof(line) - 1)
        line[llen++] = data;
    if (llen >= sizeof(line) - 1 || data == '\n') {
        line[llen] = 0;
        debug_printf("HVM DEBUG: %s", line);
        llen = 0;
    }
    whpx_unlock_iothread();
}

static void
ioport_debug_char(void *opaque, uint32_t addr, uint32_t data)
{
    whpx_debug_char((char)data);
}

int whpx_create_vm_vcpus(void)
{
    int i;

    assert(vm_vcpus < WHPX_MAX_VCPUS);

    for (i = 0; i < vm_vcpus; i++) {
      CPUState *s = &cpu_state[i];

      memset(s, 0, sizeof(*s));
      s->cpu_index = i;
      if (i < vm_vcpus-1)
        s->next_cpu = &cpu_state[i+1];
      vcpu_create(s);
    }

    first_cpu = &cpu_state[0];

    return 0;
}

static void
perf_timer_notify(void *opaque)
{
    whpx_dump_perf_stats();
    whpx_reset_perf_stats();
    mod_timer(whpx_perf_timer,
        get_clock_ms(vm_clock) + PERF_TIMER_PERIOD_MS);
}

int
whpx_early_init(void)
{
    critical_section_init(&iothread_cs);

    debug_printf("whpx early init\n");

    whpx_initialize_api();
    emu_init();
    viridian_init();
    whpx_v4v_init();

    /* init dom0 domain for v4v */
    memset(&dom0, 0, sizeof(dom0));
    dom0.is_host = 1;
    critical_section_init(&dom0.lock);
    v4v_init(&dom0);

    /* init domain v4v. needs to be done early because
       some uxendm backends send v4v data before vm is properly initialized
       and rely on DLO */
    memset(&guest, 0, sizeof(guest));
    guest.domain_id = WHPX_DOMAIN_ID_SELF;
    critical_section_init(&guest.lock);
    v4v_init(&guest);

    return 0;
}

int whpx_vm_init(const char *loadvm, int restore_mode)
{
    int ret;

#ifndef __x86_64__
    whpx_panic("whpx unsupported on 32bit\n");
#endif

    debug_printf("vm init, thread 0x%x, restore_mode=%d, file=%s\n", (int)GetCurrentThreadId(),
      restore_mode, loadvm ? loadvm : "");

    current_cpu_tls = TlsAlloc();
    if (current_cpu_tls == TLS_OUT_OF_INDEXES)
        whpx_panic("out of tls indexes\n");

    ret = whpx_partition_init();
    if (ret)
        return ret;
    ret = whpx_ram_init();
    if (ret)
        return ret;
    ret = whpx_create_vm_vcpus();
    if (ret)
      return ret;

    uint64_t rand_seed[2];
    generate_random_bytes(rand_seed, sizeof(rand_seed));
    whpx_set_random_seed(rand_seed[0], rand_seed[1]);

    union dm_features ftres;
    ftres.blob = 0;
    ftres.bits.run_patcher = (vm_run_patcher) ? 1 : 0;
    ftres.bits.seed_generation = (!!seed_generation) ? 1 : 0;
    ftres.bits.surf_copy_reduction = (!!surf_copy_reduction) ? 1 : 0;
    whpx_set_dm_features(ftres.blob);

    if (vm_restore_mode == VM_RESTORE_NONE) {
        ret = whpx_create_vm_memory(vm_mem_mb);
        if (ret)
            return ret;
    }

    if (restore_mode != VM_RESTORE_TEMPLATE &&
        restore_mode != VM_RESTORE_VALIDATE) {
        whpx_v4v_proxy_init();

#if defined(CONFIG_VBOXDRV)
        ret = sf_service_start();
        if (ret) {
            debug_printf("failed to start sf service\n");
            return ret;
        }
        ret = clip_service_start();
        if (ret) {
            debug_printf("failed to start clipboard service\n");
            return ret;
        }
    }
#endif

    // debug out
    register_ioport_write(DEBUG_PORT_NUMBER, 1, 1, ioport_debug_char, NULL);

    if (loadvm) {
        debug_printf("loading vm\n");
        ret = vm_load(loadvm, restore_mode);
        if (restore_mode == VM_RESTORE_VALIDATE)
            errx(ret ? 1 : 0, "vm_load(%s, validate) result: %d", loadvm, ret);
        if (ret)
	    errx(1, "vm_load(%s, %s) failed", loadvm,
		 restore_mode == VM_RESTORE_TEMPLATE ? "template" :
		 (restore_mode == VM_RESTORE_CLONE ? "clone" : "load"));
        if (restore_mode == VM_RESTORE_TEMPLATE) {
            control_send_status("template", "loaded", NULL);
            control_flush();
            errx(0, "template vm setup done");
        }
    }

    debug_printf("initialize pc\n");
    pc_init_xen();
    pit_init();

    if (loadvm) {
        debug_printf("finishing vm load\n");
        ret = vm_load_finish();
        if (ret)
            err(1, "vm_load_finish failed");
    }

    shutdown_reason = 0;

    /* dirty tracking unsupported */
    vm_vram_dirty_tracking = 0;

    if (whpx_perf_stats) {
        whpx_perf_timer = new_timer_ms(vm_clock, perf_timer_notify, NULL);
        mod_timer(whpx_perf_timer,
            get_clock_ms(vm_clock) + PERF_TIMER_PERIOD_MS);
    }
    return 0;
}

static void
kick_cpus(void)
{
    CPUState *cpu = first_cpu;

    while (cpu != NULL) {
        qemu_cpu_kick(cpu);
        cpu = cpu->next_cpu;
    }
}

int
whpx_vm_shutdown(int reason)
{
    CPUState *cpu = first_cpu;

    shutdown_reason = reason;

    while (cpu != NULL) {
        debug_printf("stopping vcpu%d...\n", cpu->cpu_index);
        cpu->stopped = 1;
        cpu = cpu->next_cpu;
    }

    kick_cpus();

    return 0;
}

int
whpx_vm_shutdown_wait(void)
{
    while (running_vcpus) {
        Sleep(25);
        kick_cpus();
    }

    return 0;
}

int
whpx_vm_get_context(void *buffer, size_t buffer_sz)
{
    size_t required = sizeof(struct whpx_vm_context) + vm_vcpus * sizeof(struct whpx_vcpu_context);
    struct whpx_vm_context *ctx = buffer;
    CPUState *cpu = first_cpu;
    int i;
    int r;

    if (!buffer)
        return required;

    if (buffer_sz < required)
        return -1;

    ctx->version = 1;
    ctx->vcpus = vm_vcpus;
    i = 0;
    while (cpu) {
        assert(cpu_is_stopped(cpu));
        r = whpx_vcpu_get_context(cpu, &ctx->vcpu[i]);
        if (r)
            return r;
        cpu = cpu->next_cpu;
        i++;
    }

    return required;
}

int
whpx_vm_set_context(void *buffer, size_t buffer_sz)
{
    size_t required = sizeof(struct whpx_vm_context) + vm_vcpus * sizeof(struct whpx_vcpu_context);
    struct whpx_vm_context *ctx = buffer;
    CPUState *cpu = first_cpu;
    int i;
    int r;

    if (buffer_sz < required)
        return -1;

    if (ctx->vcpus != vm_vcpus)
        whpx_panic("non-matching number of vcpus: %d != %d\n", ctx->vcpus, (int)vm_vcpus);

    i = 0;
    while (cpu) {
        r = whpx_vcpu_set_context(cpu, &ctx->vcpu[i]);
        if (r)
            return r;
        cpu = cpu->next_cpu;
        i++;
    }

    return 0;
}
