/*
 *  uxen.h
 *  uxen
 *
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#ifndef _UXEN_H_
#define _UXEN_H_

#include <stdarg.h>
#include <ntifs.h>
#include <ntddk.h>
#include <xen/types.h>
#include <rbtree/rbtree.h>

#include <uxen/uxen_info.h>

#define KERNEL 1

#include "uxen_debug.h"
#include "uxen_logging.h"

#include "version.h"

#define PAGE_MASK (~(PAGE_SIZE - 1))

#include "uxen_def.h"
#define UXEN_DEVICE_PATH_U		L"\\Device\\" UXEN_DEVICE_NAME_U
#define UXEN_DEVICE_PATH_DOS_U		L"\\DosDevices\\" UXEN_DEVICE_NAME_U

#define UXEN_POOL_TAG 'uxen'
#define UXEN_MAPPING_TAG 'nexu'

/* Windows timers are set in 100ns units, ie 10,000,000Hz. */
#define UXEN_HOST_TIMER_FREQUENCY 10000000

#define TIME_RELATIVE(x)         (-((int64_t)(x)))
#define TIME_NANO100_PER_MS      10000
#define TIME_NANO100_PER_NANO(x) ((x) / 100)
#define TIME_MS(x)               ((x) * TIME_NANO100_PER_MS)
#define TIME_NANO(x)             (TIME_NANO100_PER_NANO(x))

#define IN_RANGE(c, s, e)        ((s) <= (c) && (c) < (e))

#define LOW_VCPUTHREAD_PRI (-1)

typedef KIRQL preemption_t;
#define spinlock_acquire(lock, p) KeAcquireSpinLock(&(lock), &(p))
#define spinlock_release(lock, p) KeReleaseSpinLock(&(lock), p)
#define spinlock_initialize(lock) ( KeInitializeSpinLock(&(lock)), 0 )
#define spinlock_free(lock)     /* nothing */

#define start_execution(vmi) InterlockedIncrement(&(vmi)->vmi_running_vcpus)
#define end_execution(vmi) do {                                         \
        if (InterlockedDecrement(&(vmi)->vmi_running_vcpus) == 0)       \
            KeSetEvent(&(vmi)->vmi_notexecuting, 0, FALSE);             \
    } while (0)

#define uxen_pages_increase_reserve(i, p, increase)                     \
    _uxen_pages_increase_reserve(i, p, 0, increase, __FUNCTION__)
#define uxen_pages_increase_reserve_extra(i, p, e, increase)            \
    _uxen_pages_increase_reserve(i, p, e, increase, __FUNCTION__)

struct host_event_channel;

struct vm_info;
struct user_mapping_info { 
    rb_tree_t rbtree;
    KSPIN_LOCK lck;
    BOOLEAN initialized;
};

extern const rb_tree_ops_t user_mapping_rbtree_ops;

struct vm_vcpu_info {
    struct vm_vcpu_info_shared vci_shared;
    PKTHREAD vci_thread;
    KEVENT vci_runnable;
    KTIMER vci_timer;
    KDPC vci_timer_dpc;
    unsigned long vci_timer_cpu;
    unsigned long vci_host_cpu;
    KDPC vci_ipi_dpc;
    unsigned long vci_ipi_cpu;
    unsigned long vci_ipi_queued;
    KSPIN_LOCK vci_ipi_lck;
    volatile uint8_t vci_executing;
#ifdef DEBUG_POC_MAP_PAGE_RANGE_RETRY
    uint32_t vci_map_page_range_provided;
#endif  /* DEBUG_POC_MAP_PAGE_RANGE_RETRY */
};

struct vm_info {
    struct vm_info_shared vmi_shared;
    struct vm_vcpu_info vmi_vcpus[UXEN_MAX_VCPUS];
    uint32_t vmi_alive;
    uint32_t vmi_active_references;
    uint32_t vmi_running_vcpus;
    KEVENT vmi_notexecuting;
    KEVENT vmi_spinloop_wake_event;
    uint32_t vmi_marked_for_destroy;
    unsigned int vmi_maxpages;
    KEVENT *vmi_ioemu_exception_event;
    KEVENT *vmi_ioemu_vram_event;
    struct host_event_channel *vmi_host_event_channels;
    int vmi_host_preemption_masked;
    struct rb_node vmi_rbnode;

    /* dummy page mapped wherever we need to map a page without
     * defined content */
    uxen_pfn_t vmi_undefined_mfn;

    struct fd_assoc *vmi_mdm_fda;

    struct uxen_logging_buffer_desc vmi_logging_desc;
};

struct fd_assoc {
    struct vm_info *vmi;
    struct user_mapping_info user_mappings;
    KGUARDED_MUTEX user_malloc_mutex;
    struct uxen_logging_mapping_desc logging_mapping;
    BOOLEAN admin_access;
    BOOLEAN vmi_owner;
    BOOLEAN vmi_destroy_on_close;
};

struct device_extension {
    struct vm_info de_dom0_vm_info;
    rb_tree_t de_vm_info_rbtree;

    struct _CALLBACK_OBJECT *de_power_callback_object;
    void *de_power_callback;

    struct _CALLBACK_OBJECT *de_system_time_callback_object;
    void *de_system_time_callback;

    uint32_t de_initialised;
    KEVENT de_init_done;
    KEVENT de_shutdown_done;

    KEVENT de_vm_cleanup_event;

    LONG volatile de_executing;
    KEVENT de_resume_event;
    KEVENT de_suspend_event;
};

struct host_event_channel {
    KEVENT *request;
    KEVENT *completed;
    struct host_event_channel *next;
};

#ifdef DEBUG_PAGE_ALLOC
struct pinfo {
    int allocated;
};
extern struct pinfo *pinfotable;
#endif  /* DEBUG_PAGE_ALLOC */

#define is_vci_runnable(vci) (MemoryBarrier(), (vci)->vci_shared.vci_runnable)

/* uxen.c */
extern struct device_extension *uxen_devext;
extern DRIVER_OBJECT *uxen_drvobj;
extern uint8_t *uxen_hv;
extern size_t uxen_size;
void uxen_lock(void);
void uxen_unlock(void);
void uxen_exec_dom0_start(void);
void uxen_exec_dom0_end(void);

/* uxen_call.c */
intptr_t uxen_hypercall(struct uxen_hypercall_desc *, int,
                        struct vm_info_shared *, void *, uint32_t);
intptr_t uxen_dom0_hypercall(struct vm_info_shared *, void *,
                             uint32_t, uint64_t, ...);
#define SNOOP_USER 0
#define SNOOP_KERNEL 1
int32_t _uxen_snoop_hypercall(void *udata, int mode);
#define uxen_snoop_hypercall(udata) _uxen_snoop_hypercall(udata, SNOOP_USER)
#define try_call(r, exception_retval, fn, ...) do {                 \
        try {                                                       \
            r fn(__VA_ARGS__);                                      \
        } except (UXEN_EXCEPTION_EXECUTE_HANDLER) {                 \
            fail_msg("try_call: " #fn " exception: 0x%08X",         \
                     GetExceptionCode());                           \
            r exception_retval;                                     \
        }                                                           \
    } while (0)
#define uxen_call(r, exception_retval, _pages, fn, ...) do {            \
        LONG x;                                                         \
        preemption_t i;                                                 \
        uint32_t pages = _pages;                                        \
        uint32_t increase = 0;                                          \
        if (_pages < 0) {                                               \
            r _pages;                                                   \
            break;                                                      \
        }                                                               \
        if (uxen_pages_increase_reserve(&i, pages, &increase)) {        \
            r -ENOMEM;                                                  \
            break;                                                      \
        }                                                               \
        while ((x = uxen_devext->de_executing) == 0 ||                  \
               InterlockedCompareExchange(                              \
                   &uxen_devext->de_executing, x + 1, x) != x)          \
            if (suspend_block(i, pages, &increase)) {                   \
                x = 0;                                                  \
                r -ENOMEM;                                              \
                break;                                                  \
            }                                                           \
        if (x == 0)                                                     \
            break;                                                      \
        try_call(r, exception_retval, fn, __VA_ARGS__);                 \
        if (!InterlockedDecrement(&uxen_devext->de_executing))          \
            KeSetEvent(&uxen_devext->de_suspend_event, 0, FALSE);       \
        uxen_pages_decrease_reserve(i, increase);                       \
    } while (0)

/* uxen_cpu.c */
#define cpu_number() KeGetCurrentProcessorNumber()
extern unsigned long uxen_cpu_vm;
extern unsigned long uxen_cpu_first(void);
extern void uxen_cpu_pin(unsigned long);
extern void uxen_cpu_pin_current(void);
extern void uxen_cpu_pin_first(void);
#define uxen_cpu_pin_dom0() uxen_cpu_pin_current()
extern void uxen_cpu_unpin(void);
extern void uxen_cpu_pin_vcpu(struct vm_vcpu_info *, int);
extern void uxen_cpu_unpin_vcpu(struct vm_vcpu_info *);
extern void uxen_cpu_set_active_mask(void *, int);
extern void __cdecl uxen_cpu_on_selected(const void *,
                                         uintptr_t (*)(uintptr_t));
extern void __cdecl uxen_cpu_interrupt(uintptr_t);
extern int pv_vmware(void);
#define UXEN_CPU_VENDOR_UNKNOWN 0
#define UXEN_CPU_VENDOR_INTEL 1
#define UXEN_CPU_VENDOR_AMD 2
extern int uxen_cpu_vendor(void);

/* uxen_hiber.c */
#ifdef __i386__
extern PIRP wait_for_s4_irp;
extern PIRP wait_for_resume_from_s4_irp;
extern LONG s4_in_progress;
KEVENT continue_power_transition_event;
extern BOOLEAN uxen_hibernation_enabled;
int uxen_hibernation_init(void);
void uxen_hibernation_cleanup(void);
void hiber_cancel_routine(__inout PDEVICE_OBJECT devobj,
                          __in __drv_useCancelIRQL PIRP irp);
NTSTATUS uxen_shutdown(__inout DEVICE_OBJECT *devobj, __inout IRP *irp);
#endif /* __i386__ */

/* uxen_ioctl.c */
NTSTATUS uxen_ioctl(__inout DEVICE_OBJECT *DeviceObject, __inout IRP *pIRP);
struct fd_assoc *associate_fd_assoc(void *p);
void release_fd_assoc(void *p);
void final_release_fd_assoc(void *p);
int copyin(const void *uaddr, void *kaddr, size_t size);
int copyout(const void *kaddr, void *uaddr, size_t size);
int copyin_kernel(const void *uaddr, void *kaddr, size_t size);

/* uxen_load.c */
#if !defined(__UXEN_EMBEDDED__)
int uxen_load(struct uxen_load_desc *);
#else
int uxen_load_symbols(void);
#endif
int uxen_unload(void);

/* uxen_mem.c */
extern int map_page_range_max_nr;
void set_map_mfn_pte_flags(void);
uint64_t __cdecl map_mfn(uintptr_t va, xen_pfn_t mfn);
int mem_init(void);
void mem_exit(void);
void *_kernel_malloc(size_t, int);
#define kernel_malloc(size) _kernel_malloc(size, __LINE__)
void *_kernel_malloc_unchecked(size_t, int);
#define kernel_malloc_unchecked(size) _kernel_malloc_unchecked(size, __LINE__)
void kernel_free(void *, size_t);
int kernel_query_mfns(void *va, uint32_t nr_pages,
                      uxen_pfn_t *mfn_list, uint32_t max_mfn);
void *kernel_alloc_contiguous(uint32_t size);
void kernel_free_contiguous(void *va, uint32_t size);
void *kernel_alloc_va(uint32_t num);
int kernel_free_va(void *va, uint32_t num);
int _uxen_pages_increase_reserve(preemption_t *i, uint32_t pages,
                                 uint32_t extra_pages, uint32_t *increase,
                                 const char *fn);
void uxen_pages_decrease_reserve(preemption_t i, uint32_t decrease);
#define NO_RESERVE 0
#define MIN_RESERVE 64
#define EXTRA_RESERVE 128
#define HYPERCALL_RESERVE 326
#define SETUPVM_RESERVE (HYPERCALL_RESERVE + 16)
#define STARTXEN_RESERVE 1024
#define IDLE_RESERVE 326
#define UXEN_SYS_V4V_MAX_RING_SIZE (2097152ULL)
#define V4V_VCPU_RUN_RESERVE ((UXEN_SYS_V4V_MAX_RING_SIZE >> PAGE_SHIFT) + 32)
#define VCPU_RUN_RESERVE (64 + V4V_VCPU_RUN_RESERVE)
#define VCPU_RUN_EXTRA_RESERVE 448
#define MAX_RESERVE (1<<18)
#define MAX_PAGES_RESERVE_CPU (4 << 18)
void uxen_pages_clear(void);
extern KSPIN_LOCK idle_free_lock;
extern uint32_t idle_free_list;
int idle_free_free_list(void);
extern KSPIN_LOCK populate_frametable_lock;
int _populate_frametable(uxen_pfn_t, uxen_pfn_t);
extern int frametable_check_populate;
#ifdef __i386__
extern uxen_pfn_t os_max_pfn;
#define populate_frametable(mfn, pmfn)                                  \
    ((!frametable_check_populate || (mfn) >= os_max_pfn) ? 0 :          \
     _populate_frametable((mfn), (pmfn)))
#else  /* __i386__ */
#define populate_frametable(mfn, pmfn) (!frametable_check_populate ? 0 : \
                                        _populate_frametable((mfn), (pmfn)))
#endif  /* __i386__ */
int populate_frametable_physical_memory(void);
void depopulate_frametable(unsigned int);
int kernel_alloc_mfn(uxen_pfn_t *);
int kernel_malloc_mfns(uint32_t, uxen_pfn_t *, uint32_t);
void kernel_free_mfn(uxen_pfn_t);
#define MAP_PAGE_RANGE_KERNEL_MODE 0x0
#define MAP_PAGE_RANGE_USER_MODE   0x1
/* permissions not honored (yet) */
#define MAP_PAGE_RANGE_RW          0x0
#define MAP_PAGE_RANGE_RO          0x2
void *kernel_mmap_pages(int, uxen_pfn_t *);
int kernel_munmap_pages(const void *, int, uxen_pfn_t *);
void *user_mmap_pages(int, uxen_pfn_t *, int, struct fd_assoc *);
int user_munmap_pages(const void *, int, uxen_pfn_t *, struct fd_assoc *);
void *uxen_mem_user_va_with_page(uint32_t, uint32_t, struct fd_assoc *);
void uxen_mem_user_va_remove(uint32_t, void *, struct fd_assoc *);
enum user_mapping_type {
    USER_MAPPING_MEMORY_MAP,
    USER_MAPPING_BUFFER,
    USER_MAPPING_USER_MALLOC,
    USER_MAPPING_HOST_MFNS,
};
void *user_malloc(size_t, enum user_mapping_type, struct fd_assoc *);
void user_free(void *va, struct fd_assoc *);
void user_free_all_user_mappings(struct fd_assoc *);
int uxen_mem_malloc(struct uxen_malloc_desc *, struct fd_assoc *);
int uxen_mem_free(struct uxen_free_desc *, struct fd_assoc *);
uint64_t __cdecl uxen_mem_user_access_ok(void *, void *, uint64_t);
int uxen_mem_mmapbatch(struct uxen_mmapbatch_desc *, struct fd_assoc *);
int uxen_mem_munmap(struct uxen_munmap_desc *, struct fd_assoc *);
void * __cdecl uxen_mem_map_page(xen_pfn_t);
uint64_t __cdecl uxen_mem_unmap_page_va(const void *);
void * __cdecl uxen_mem_map_page_range(struct vm_vcpu_info_shared *, uint64_t,
                                       uxen_pfn_t *);
uint64_t __cdecl uxen_mem_unmap_page_range(
    struct vm_vcpu_info_shared *, const void *, uint64_t, uxen_pfn_t *);
uxen_pfn_t __cdecl uxen_mem_mapped_va_pfn(const void *);
void __cdecl uxen_mem_fill_free_pages(void);
void __cdecl uxen_mem_clear_free_pages(void);
void uxen_mem_tlb_flush(void);
uxen_pfn_t get_max_pfn(int use_hidden);
#ifdef __i386__
void add_hidden_memory(void);
#endif
uint64_t get_highest_user_address(void);
int map_host_pages(void *, size_t, uint64_t, struct fd_assoc *);
int unmap_host_pages(void *, size_t, struct fd_assoc *);

/* uxen_sys.asm */
ULONG_PTR __stdcall uxen_mem_tlb_flush_fn(ULONG_PTR arg);
ULONG_PTR __stdcall uxen_mem_tlb_flush_fn_global(ULONG_PTR arg);

/* uxen_ops.c */
extern MDL *map_page_range_mdl;
extern uint8_t *frametable;
extern unsigned int frametable_size;
extern uint8_t *frametable_populated;
extern struct vm_info *dom0_vmi;
extern uxen_pfn_t uxen_zero_mfn;
extern const rb_tree_ops_t vm_info_rbtree_ops;
int uxen_except_handler(unsigned int, struct _EXCEPTION_POINTERS *);
#define UXEN_EXCEPTION_EXECUTE_HANDLER					\
    uxen_except_handler(GetExceptionCode(), GetExceptionInformation())
int hostdrv_except_handler(char *, ...);
#define HOSTDRV_EXCEPTION_EXECUTE_HANDLER(fmt, ...)                     \
    hostdrv_except_handler("uxen: %s:%d: exception %08X: " fmt "\n",    \
                           __FUNCTION__, __LINE__, GetExceptionCode(),  \
                           __VA_ARGS__)
#define disable_preemption(pi) KeRaiseIrql(DISPATCH_LEVEL, pi)
#define enable_preemption(i) KeLowerIrql(i)
#define preemption_enabled() (KeGetCurrentIrql() < DISPATCH_LEVEL)
#define uxen_smap_state(smap) struct smap
#define uxen_smap_preempt_disable(smap) do { } while(0, 0)
#define uxen_smap_preempt_restore(smap) do { } while(0, 0)
void set_host_preemption(uint64_t disable);
void uxen_update_unixtime_generation(void);
extern PETHREAD uxen_idle_thread[];
extern KEVENT uxen_idle_thread_event[];
#define uxen_signal_idle_thread(cpu) do {                       \
        if (uxen_idle_thread[cpu])                              \
            KeSetEvent(&uxen_idle_thread_event[cpu], 0, FALSE); \
    } while (0)
int suspend_block(preemption_t i, uint32_t pages, uint32_t *reserve_increase);
void uxen_op_init_free_allocs(void);
int uxen_op_init(struct fd_assoc *, struct uxen_init_desc *, uint32_t,
                 DEVICE_OBJECT *);
int uxen_op_shutdown(void);
void uxen_complete_shutdown(void);
int uxen_op_wait_vm_exit(void);
int uxen_op_version(struct uxen_version_desc *);
int uxen_op_keyhandler(char *, unsigned int);
int uxen_op_create_vm(struct uxen_createvm_desc *, struct fd_assoc *);
int uxen_op_target_vm(struct uxen_targetvm_desc *, struct fd_assoc *);
void uxen_vmi_free(struct vm_info *);
void uxen_vmi_cleanup_vm(struct vm_info *);
int uxen_op_destroy_vm(struct uxen_destroyvm_desc *, struct fd_assoc *);
int uxen_op_execute(struct uxen_execute_desc *ued, struct vm_info *);
int uxen_op_set_event(struct uxen_event_desc *, struct vm_info *);
int uxen_op_set_event_channel(struct uxen_event_channel_desc *,
                              struct vm_info *, struct fd_assoc *);
int uxen_op_query_vm(struct uxen_queryvm_desc *);
void uxen_power_state(uint32_t);
int uxen_op_map_host_pages(struct uxen_map_host_pages_desc *,
                           struct fd_assoc *);
int uxen_op_unmap_host_pages(struct uxen_map_host_pages_desc *,
                             struct fd_assoc *);

/* memcache-dm.c */
int mdm_init(struct uxen_memcacheinit_desc *, struct fd_assoc *);
int mdm_map(struct uxen_memcachemap_desc *, struct fd_assoc *);
void mdm_clear_all(struct vm_info *);

#if defined(__x86_64__) && defined(__UXEN_EMBEDDED__)
/* uxen_xpdata.obj */
extern uint8_t uxen_xdata_start;
extern uint8_t uxen_xdata_end;
extern uint8_t uxen_pdata_start;
extern uint8_t uxen_pdata_end;
#endif

/* uxen_xmm.asm */
extern void uxen_cpu_xmm_save_host(void *);
extern void uxen_cpu_xmm_restore_host(void *);
extern void uxen_cpu_xmm_save_guest(void *);
extern void uxen_cpu_xmm_restore_guest(void *);

/* v4v.c */
void uxen_sys_start_v4v(void);
void uxen_sys_stop_v4v(void);
void __cdecl uxen_sys_signal_v4v(void);

/* uxen_stackwalk.c */
extern void uxen_stacktrace(PCONTEXT);

static __inline int
ffs(uint32_t i)
{
    int m = 16;
    int b = 1;

    if (i == 0)
	return 0;
    while (m > 0) {
	if ((i & ((1 << m) - 1)) == 0) {
	    i >>= m;
	    b += m;
	}
	m >>= 1;
    }
    return b;
}

#define cmpxchg(ptr, cmp, new)                  \
    InterlockedCompareExchange(ptr, new, cmp)
#define cmpxchg16b(ptr, cmp, new)               \
    InterlockedCompareExchange16(ptr, new, cmp)

#if defined(__x86_64__)
#define affinity_mask(x) ((ULONGLONG)1 << (x))
#else
#define affinity_mask(x) (1 << (x))
#endif

#define PAGE_MASK (~(PAGE_SIZE - 1))
#define ALIGN_PAGE_DOWN(x) ((x) & PAGE_MASK)
#define ALIGN_PAGE_UP(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int:-!!(condition); }))

#define ASSERT_IRQL(irql) (ASSERT(KeGetCurrentIrql() <= (irql)))

#endif  /* _UXEN_H_ */
