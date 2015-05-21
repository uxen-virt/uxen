/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

/*
 *  uxen.h
 *  uxen
 *
 *  COPYRIGHT
 * 
 */

#ifndef _UXEN_H_
#define _UXEN_H_

#ifdef __cplusplus
extern "C" {
#endif

#define _CLOCK_T

#include <kern/kern_types.h>
#define MACH_ASSERT 1
#include <kern/assert.h>
#include <errno.h>

#include <i386/eflags.h>

#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>

#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <kern/locks.h>
#include <kern/queue.h>
#include <libkern/OSMalloc.h>
#include <libkern/version.h>
#include <sys/kauth.h>

#include <queue.h>
#include <rbtree/rbtree.h>

#include <uxen/uxen_info.h>

#include <uxen_def.h>
#include <uxen_ioctl.h>

#undef EAGAIN
#undef ENOSYS
#undef EMSGSIZE
#undef ECONNREFUSED
#include <xen/errno.h>

#include "events.h"
#include "uxen_debug.h"
#include "xnu_symbols.h"

#include "version.h"

#define ASSERT(a) assert(a)
#undef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))

/* osfmk/kern/timer.h TIMER_RATE */ /* XXX really? */
#define UXEN_HOST_TIMER_FREQUENCY 1000000000

#define UXEN_MAP_PAGE_RANGE_MAX 16

typedef uint32_t preemption_t;
void disable_preemption(preemption_t *i);
void enable_preemption(preemption_t i);
struct smap_state {
    uint64_t flags;
    preemption_t i;
};
#define uxen_smap_state(smap) struct smap_state smap

static inline void uxen_smap_preempt_disable(struct smap_state *s)
{
    if (!xnu_pmap_smap_enabled())
        return;

    disable_preemption(&s->i);
    asm ("pushfq; popq %0\n\t" : "=r"(s->flags));
    if (!(s->flags & EFL_AC))
        asm volatile("stac\n\t");
}

static inline void uxen_smap_preempt_restore(struct smap_state *s)
{
    if (!xnu_pmap_smap_enabled())
        return;

    if (!(s->flags & EFL_AC))
        asm volatile("clac\n\t");
    enable_preemption(s->i);
}

#define spinlock_acquire(lock, p) (({ (void)(p); lck_spin_lock(lock); }))
#define spinlock_release(lock, p) (({ (void)(p); lck_spin_unlock(lock); }))
#define spinlock_initialize(lock) (({                                   \
                (lock) = lck_spin_alloc_init(uxen_lck_grp, LCK_ATTR_NULL); \
                !(lock) ? ENOMEM : 0;                                   \
            }))
#define spinlock_free(lock) do {                \
        if (lock)                               \
            lck_spin_free(lock, uxen_lck_grp);  \
    } while (0)

#define start_execution(vmi) OSIncrementAtomic(&(vmi)->vmi_running_vcpus)
#define end_execution(vmi) do {                                 \
        if (OSDecrementAtomic(&(vmi)->vmi_running_vcpus) == 1)  \
            fast_event_signal(&(vmi)->vmi_notexecuting);        \
    } while (0)

#define uxen_pages_increase_reserve(i, p, increase)                     \
    _uxen_pages_increase_reserve(i, p, 0, increase, __FUNCTION__)
#define uxen_pages_increase_reserve_extra(i, p, e, increase)            \
    _uxen_pages_increase_reserve(i, p, e, increase, __FUNCTION__)

struct map_pfn_array_pool_entry {
    LIST_ENTRY(map_pfn_array_pool_entry) list_entry;
    void *va;
    uint32_t num;
    uint32_t n_mapped;
};

#include "uxen_logging.h"

struct vm_info;
struct user_mapping_info { 
    rb_tree_t rbtree;
    lck_spin_t *lck;
    struct vm_info *vmi;
};

extern const rb_tree_ops_t user_mapping_rbtree_ops;

struct vm_vcpu_info {
    struct vm_vcpu_info_shared vci_shared;
    struct event_object vci_runnable;
    struct timer_call vci_timer;
    uint32_t vci_timer_created;
    unsigned long vci_host_cpu;
};

struct vm_info {
    struct vm_info_shared vmi_shared;
    struct vm_vcpu_info vmi_vcpus[UXEN_MAX_VCPUS];
    uint32_t vmi_alive;
    uint32_t vmi_active_references;
    uint32_t vmi_running_vcpus;
    struct fast_event_object vmi_notexecuting;
    uint32_t vmi_marked_for_destroy;
    unsigned int vmi_maxpages;
    struct notification_event vmi_ioemu_exception_event;
    struct notification_event vmi_ioemu_vram_event;
    struct host_event_channel *vmi_host_event_channels;
    int vmi_host_preemption_masked;
    struct rb_node vmi_rbnode;

    /* dummy page mapped wherever we need to map a page without
     * defined content */
    uint32_t vmi_undefined_mfn;

    struct fd_assoc *vmi_mdm_fda;

    struct uxen_logging_buffer_desc vmi_logging_desc;
};

struct fd_assoc {
    task_t task;
    struct vm_info *vmi;
    struct rb_node rbnode;
    mach_port_t notification_port;
    struct notification_event_queue events;
    struct user_notification_event_queue user_events;
    struct user_mapping_info user_mappings;
    struct uxen_logging_mapping_desc logging_mapping;
    bool admin_access;
    bool vmi_owner;
    bool vmi_destroy_on_close;
};

struct device_extension {
    struct vm_info de_dom0_vm_info;
    rb_tree_t de_vm_info_rbtree;

    /* struct _CALLBACK_OBJECT *de_power_callback_object; */
    void *de_power_callback;

    uint32_t de_initialised;
    struct fast_event_object de_init_done;
    struct fast_event_object de_shutdown_done;

    struct fast_event_object de_vm_cleanup_event;

    uint32_t volatile de_executing;
    struct fast_event_object de_resume_event;
    struct fast_event_object de_suspend_event;
};

/* uxen.c */
extern struct device_extension *uxen_devext;
extern uint8_t *uxen_hv;
extern uint32_t uxen_size;
extern OSMallocTag uxen_malloc_tag;
extern lck_grp_t *uxen_lck_grp;
int uxen_driver_load(void);
void uxen_driver_unload(void);
int uxen_open(struct fd_assoc *fda, task_t task);
int uxen_ioctl(u_long cmd, struct fd_assoc *fda, struct vm_info *vmi,
               void *in_buf, size_t in_len, void *out_buf, size_t out_len);
void uxen_close(struct fd_assoc *fda);
void uxen_lock(void);
void uxen_unlock(void);
void uxen_exec_dom0_start(void);
void uxen_exec_dom0_end(void);
intptr_t uxen_hypercall(struct uxen_hypercall_desc *, int,
                        struct vm_info_shared *, void *, uint32_t);
intptr_t uxen_dom0_hypercall(struct vm_info_shared *, void *,
                             uint32_t, uint64_t, ...);
#define SNOOP_USER 0
#define SNOOP_KERNEL 1
int32_t _uxen_snoop_hypercall(void *udata, int mode);
#define uxen_snoop_hypercall(udata) _uxen_snoop_hypercall(udata, SNOOP_USER)

#define try_call(r, exception_retval, fn, ...) do {                 \
        r fn(__VA_ARGS__);                                          \
    } while (0)

#define uxen_call(r, exception_retval, _pages, fn, ...) do {            \
        uint32_t x;                                                     \
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
               !OSCompareAndSwap(x, x + 1, &uxen_devext->de_executing)) \
            if (suspend_block(i, pages, &increase)) {                   \
                x = 0;                                                  \
                r -ENOMEM;                                              \
                break;                                                  \
            }                                                           \
        if (x == 0)                                                     \
            break;                                                      \
        try_call(r, exception_retval, fn, __VA_ARGS__);                 \
        if (OSDecrementAtomic(&uxen_devext->de_executing) == 1)         \
            fast_event_signal(&uxen_devext->de_suspend_event);          \
        uxen_pages_decrease_reserve(i, increase);                       \
    } while (0)
int copyin_user(const user_addr_t uaddr, void *kaddr, size_t size);
int copyin_kernel(const user_addr_t uaddr, void *kaddr, size_t size);

typedef void *pointer_map_key;
typedef void *pointer_map_val;

struct pointer_map {
    pointer_map_key key;
    pointer_map_val val;
    struct rb_node rbnode;
};

extern const rb_tree_ops_t pointer_map_rbtree_ops;

/* uxen_ops.c */
extern uint8_t *frametable;
extern unsigned int frametable_size;
extern uint8_t *frametable_populated;
extern uint32_t uxen_zero_mfn;
void set_host_preemption(uint64_t disable);
void __cdecl signal_idle_thread(void);
int suspend_block(preemption_t i, uint32_t pages, uint32_t *reserve_increase);
void uxen_op_init_free_allocs(void);
int uxen_op_init(struct fd_assoc *fda);
int uxen_op_shutdown(void);
void uxen_complete_shutdown(void);
int uxen_op_wait_vm_exit(void);
int uxen_op_version(struct uxen_version_desc *uvd);
int uxen_op_keyhandler(char *keys, unsigned int num);
int uxen_op_create_vm(struct uxen_createvm_desc *utd, struct fd_assoc *fda);
int uxen_op_target_vm(struct uxen_targetvm_desc *utd, struct fd_assoc *fda);
void uxen_vmi_cleanup_vm(struct vm_info *vmi);
int uxen_op_destroy_vm(struct uxen_destroyvm_desc *, struct fd_assoc *fda);
int uxen_op_query_vm(struct uxen_queryvm_desc *);
int uxen_op_execute(struct uxen_execute_desc *ued, struct vm_info *vmi);
int uxen_op_set_event(struct uxen_event_desc *ued, struct vm_info *vmi,
                      struct notification_event_queue *queue);
int uxen_op_set_event_channel(
    struct uxen_event_channel_desc *uecd,
    struct vm_info *vmi, struct fd_assoc *fda,
    struct notification_event_queue *queue,
    struct user_notification_event_queue *user_events);
int uxen_op_signal_event(void *addr,
                         struct user_notification_event_queue *user_events);
int uxen_op_poll_event(struct uxen_event_poll_desc *,
                       struct notification_event_queue *);
void uxen_power_state(uint32_t);
int uxen_op_map_host_pages(struct uxen_map_host_pages_desc *,
                           struct fd_assoc *);
int uxen_op_unmap_host_pages(struct uxen_map_host_pages_desc *,
                             struct fd_assoc *);

/* uxen_load.c */
#if !defined(__UXEN_EMBEDDED__)
int uxen_load(struct uxen_load_desc *);
#else
int uxen_load_symbols(void);
#endif
int uxen_unload(void);

/* uxen_mem.c */
#define set_map_mfn_pte_flags() do { } while (0)
uint64_t __cdecl map_mfn(uintptr_t va, xen_pfn_t mfn);
int map_pfn_array_pool_fill(void);
void map_pfn_array_pool_clear(void);
void *map_pfn_array_from_pool(uint32_t *pfn_array, uint32_t num_pages);
void unmap_pfn_array_from_pool(const void *va, uxen_pfn_t *mfns);
void *map_pfn_array(uint32_t *pfn_array, uint32_t num_pages,
                    struct map_pfn_array_pool_entry *e);
void *map_pfn(uint32_t pfn, struct map_pfn_array_pool_entry *e);
void unmap(struct map_pfn_array_pool_entry *e);
int uxen_mem_malloc(struct uxen_malloc_desc *, struct fd_assoc *);
int uxen_mem_free(struct uxen_free_desc *, struct fd_assoc *);
uint64_t uxen_mem_user_access_ok(void *, void *, uint64_t);
int uxen_mem_mmapbatch(struct uxen_mmapbatch_desc *ummapbd,
                       struct fd_assoc *fda);
int uxen_mem_munmap(struct uxen_munmap_desc *umd, struct fd_assoc *fda);
void *user_mmap_pages(uint32_t num, uint32_t *pfn_array,
                      struct fd_assoc *fda);
int user_munmap_pages(unsigned int num, const void *addr,
                      struct fd_assoc *fda);
void *kernel_malloc(uint32_t size);
void kernel_free(void *addr, uint32_t size);
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
#define IDLE_RESERVE 326
#define VCPU_RUN_RESERVE 64
#define VCPU_RUN_EXTRA_RESERVE 448
void uxen_pages_clear(void);
extern lck_spin_t *idle_free_lock;
extern uint32_t idle_free_list;
int idle_free_free_list(void);
extern lck_spin_t *populate_frametable_lock;
int _populate_frametable(uxen_pfn_t);
extern int frametable_check_populate;
#define populate_frametable(mfn) (!frametable_check_populate ? 0 :      \
                                  _populate_frametable((mfn)))
int populate_frametable_physical_memory(void);
void depopulate_frametable(unsigned int);
int kernel_alloc_mfn(uxen_pfn_t *, int zeroed);
int kernel_malloc_mfns(uint32_t nr_pages, uint32_t *mfn_list, int zeroed);
void kernel_free_mfn(uint32_t);
#ifdef DEBUG
void debug_check_malloc(void);
#endif
void uxen_mem_tlb_flush(void);
uxen_pfn_t get_max_pfn(void);
int uxen_mem_init(void);
void uxen_mem_exit(void);
void *uxen_mem_user_va_with_page(uint32_t nr_pages, uint32_t mfn,
                                 struct fd_assoc *fda);
void uxen_mem_user_va_remove(uint32_t num, void *va,
                             struct fd_assoc *fda);
enum user_mapping_type {
    USER_MAPPING_MEMORY_MAP,
    USER_MAPPING_BUFFER,
    USER_MAPPING_USER_MALLOC,
    USER_MAPPING_HOST_MFNS,
};
void *user_malloc(size_t size, enum user_mapping_type type,
                  struct fd_assoc *fda);
void user_free(void *va, struct fd_assoc *fda);
void user_free_all_user_mappings(struct fd_assoc *fda);
int map_host_pages(void *, size_t, uint64_t, struct fd_assoc *);
int unmap_host_pages(void *, size_t, struct fd_assoc *);

/* memcache-dm.c */
int mdm_init(struct uxen_memcacheinit_desc *, struct fd_assoc *);
int mdm_map(struct uxen_memcachemap_desc *, struct fd_assoc *);
void mdm_clear_all(struct vm_info *);

/* uxen_physmap.c */
int physmap_init(void);
void *physmap_pfn_to_va(uint32_t pfn);
uint32_t physmap_va_to_pfn(const void *va);

/* uxen_cpu.c */
extern int uxen_nr_cpus;
void uxen_cpu_set_active_mask(uint64_t *mask);
void uxen_cpu_pin(int cpu);
void uxen_cpu_pin_current(void);
void uxen_cpu_pin_first(void);
void uxen_cpu_unpin(void);
void uxen_cpu_pin_vcpu(struct vm_vcpu_info *vci, int cpu);
void uxen_cpu_unpin_vcpu(struct vm_vcpu_info *);
void uxen_cpu_call(int cpu, void (*fn)(void *), void *arg);
void uxen_cpu_on_selected(const void *mask, uintptr_t (*fn)(uintptr_t));
void uxen_cpu_on_selected_async(uintptr_t mask, uintptr_t (*fn)(uintptr_t));
void uxen_cpu_interrupt(uintptr_t mask);
int uxen_ipi_init(void (*dispatch)(unsigned int));
void uxen_ipi_cleanup(void);
void uxen_cpu_ipi(int cpu, unsigned int vector);

/* From osfmk/i386/mp.h */
#define MAX_CPUS 32

/* uxen_time.c */
uint64_t uxen_get_counter_freq(void);

/* uxen_pm.c */
int uxen_pm_init(void);
void uxen_pm_cleanup(void);

/* uxen_sys.S */
uintptr_t uxen_mem_tlb_flush_fn_global(uintptr_t);

/* uxen custom kauth actions */
enum {
    UXEN_KAUTH_OP_OPEN,
};

#define MemoryBarrier() __sync_synchronize()

#define cmpxchg(ptr, cmp, new)                          \
    (OSCompareAndSwap(cmp, new, ptr) ? (cmp) : *(ptr))

#if defined(__x86_64__)
#define affinity_mask(x) (1ULL << (x))
#else
#define affinity_mask(x) (1 << (x))
#endif

#define PAGE_MASK (~(PAGE_SIZE - 1))
#define ALIGN_PAGE_DOWN(x) ((x) & PAGE_MASK)
#define ALIGN_PAGE_UP(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int:-!!(condition); }))

#define uxen_translate_xen_errno(xen_e) (({             \
                int os_e;                               \
                switch (xen_e) {                        \
                case -11: os_e = EAGAIN; break;         \
                case -40: os_e = ENOSYS; break;         \
                case -90: os_e = EMSGSIZE; break;       \
                case -111: os_e = ECONNREFUSED; break;  \
                default: os_e = -(xen_e); break;        \
                }                                       \
                os_e;                                   \
            }))

#ifdef __cplusplus
}

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

class uxen_driver : public IOService
{
    OSDeclareDefaultStructors(uxen_driver)

public:
    virtual bool init(OSDictionary *d = NULL);
    virtual void free(void);
    virtual IOService *probe(IOService *, SInt32 *);

    virtual bool start(IOService *);
    virtual void stop(IOService *);
};

class uxen_user_client : public IOUserClient
{
    OSDeclareDefaultStructors(uxen_user_client)

public:
    virtual bool initWithTask(task_t, void *, UInt32, OSDictionary *);
    virtual bool start(IOService *);
    virtual IOReturn clientClose(void);
    virtual void stop(IOService *);
    virtual void free(void);
    virtual IOReturn externalMethod(uint32_t, IOExternalMethodArguments *,
                                    IOExternalMethodDispatch *, OSObject *,
                                    void *);
    virtual IOReturn registerNotificationPort(mach_port_t, UInt32, UInt32);

private:
    task_t task;
    uxen_driver *owner;
    struct fd_assoc fd_assoc;
};


#endif

#endif /* _UXEN_H_ */
