/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _XNU_SYMBOLS_H_
#define _XNU_SYMBOLS_H_

#include <kern/locks.h>
#include <kern/clock.h>

/* osfmk/i386/mp_events.h */
enum {
    SYNC,
    ASYNC,
    NOSYNC,
};

/* From osfmk/i386/pmap.h */
struct pmap;
typedef struct pmap *pmap_t;
extern pmap_t kernel_pmap;

typedef struct pmap_memory_regions_10_8 {
        ppnum_t base;
        ppnum_t end;
        ppnum_t alloc;
        uint32_t type;
        uint64_t attribute;
} pmap_memory_regions_v10_8_t;

typedef struct pmap_memory_regions_10_9 {
        ppnum_t base;
        ppnum_t end;
        ppnum_t unknown;
        ppnum_t alloc;
        uint32_t type;
        uint64_t attribute;
} pmap_memory_regions_v10_9_t;

#define pmap_memory_regions_get(_i, _fld)                               \
  ((version_major <= 12) ?                                              \
   ((pmap_memory_regions_v10_8_t *)xnu_pmap_memory_regions())[i]._fld : \
   ((pmap_memory_regions_v10_9_t *)xnu_pmap_memory_regions())[i]._fld )


/* From osfm/i386/locks.h */
struct __lck_mtx_t__ {
        unsigned long   opaque[2];
};

/* From osfmk/vm/vm_page.h */
typedef struct vm_page {
        queue_chain_t   pageq;
        /* Rest we don't care */
} *vm_page_t;


#define VM_PAGE_PHYS_OFFSET_10_9  60
#define VM_PAGE_PHYS_OFFSET_10_10 56

#define vm_page_get_phys(_page)                          \
    *(ppnum_t *)((uint8_t *)(_page) +                    \
                 ((version_major <= 13) ?                \
                  VM_PAGE_PHYS_OFFSET_10_9 :             \
                  VM_PAGE_PHYS_OFFSET_10_10))

/* From i386/cpu_data.h */
typedef struct cpu_data cpu_data_t;

/* From osfmk/kern/thread.h */
#define TH_SUSP 0x2

/* From kern/timer_call.h */
/* XXX actual size from 2050.18.24 is 0x50 -- extract from mach_kernel? */
typedef struct timer_call {
    uint8_t data[0x100];
} *timer_call_t;
typedef void *timer_call_param_t;
typedef void (*timer_call_func_t)(timer_call_param_t param0,
                                  timer_call_param_t param1);

#define TIMER_CALL_SYS_CRITICAL  0x01
#define TIMER_CALL_USER_CRITICAL 0x11
#define TIMER_CALL_LOCAL         0x40

#define TIMER_CALL_VCPU TIMER_CALL_LOCAL|TIMER_CALL_USER_CRITICAL

/* From kern/ast.h */
typedef uint32_t ast_t;


/*
 * Hardwired offsets.
 */

#define CPU_DATA_CPUNUMBER_10_8 0x14
#define CPU_DATA_CPUNUMBER_10_9 0x1c

#define CPU_DATA_CPUNUMBER() \
    (version_major <= 12 ? CPU_DATA_CPUNUMBER_10_8 : CPU_DATA_CPUNUMBER_10_9)

#define CPU_DATA_CURRENT_10_8 0xf0
#define CPU_DATA_CURRENT_10_9 0xf8

#define CPU_DATA_CURRENT() \
    (version_major <= 12 ? CPU_DATA_CURRENT_10_8 : CPU_DATA_CURRENT_10_9)

#define THREAD_STATUS_10_8 0x80
#define THREAD_STATUS_10_9 0x78
#define THREAD_STATE() \
    (version_major <= 12 ? THREAD_STATUS_10_8 : THREAD_STATUS_10_9)


/*
 * Symbols not defined in Kernel.framework
 * headers but still linkable.
 */

extern pmap_t kernel_pmap;
extern int cpu_number(void);
extern ppnum_t pmap_find_phys(pmap_t map, addr64_t va);

/*
 * Functions found through _find_xnu_symbols().
 */

typedef vm_page_t (*vm_page_grab_t)(void);
typedef boolean_t (*vm_page_wait_t)(int interruptible);
typedef void (*vm_page_release_t)(vm_page_t mem);
typedef void (*vm_page_free_list_t)(vm_page_t freeq, boolean_t prepare);
typedef void (*pmap_enter_t)(pmap_t pmap, vm_map_offset_t v, ppnum_t pn,
                             vm_prot_t prot, vm_prot_t fault_type,
                             unsigned int flags, boolean_t wired);
typedef void (*pmap_remove_t)(pmap_t pmap, addr64_t s, addr64_t e);
typedef kern_return_t (*vm_map_wire_t)(register vm_map_t map,
                                       register vm_map_offset_t start,
                                       register vm_map_offset_t end,
                                       register vm_prot_t access_type,
                                       boolean_t user_wire);
typedef kern_return_t (*vm_map_unwire_t)(vm_map_t map,
                                         vm_map_offset_t start,
                                         vm_map_offset_t end,
                                         boolean_t user_wire);
typedef void (*vm_map_deallocate_t)(vm_map_t map);
typedef vm_map_t (*get_task_map_reference_t)(task_t task);
typedef pmap_t (*get_map_pmap_t)(vm_map_t map);
typedef void (*_disable_preemption_t)(void);
typedef void (*_enable_preemption_t)(void);
typedef processor_t (*current_processor_t)(void);
typedef processor_t (*cpu_to_processor_t)(int cpu);
typedef processor_t (*thread_bind_t)(processor_t processor);
typedef uint32_t (*mp_cpus_call_t)(uint32_t cpu_mask, int sync,
                                   void (*action_func)(void *), void *arg);

typedef boolean_t (*timer_call_enter_t)(timer_call_t, uint64_t, uint32_t);
typedef void (*timer_call_setup_t)(timer_call_t, timer_call_func_t, timer_call_param_t);
typedef boolean_t (*timer_call_cancel_t)(timer_call_t);
typedef ast_t *(*ast_pending_t)(void);
typedef wait_result_t (*thread_block_reason_t)(thread_continue_t, void *, ast_t);
typedef void (*clock_gettimeofday_t)(clock_sec_t *, clock_usec_t *);

extern vm_page_grab_t xnu_vm_page_grab;
extern vm_page_release_t xnu_vm_page_release;
extern vm_page_free_list_t xnu_vm_page_free_list;
extern vm_page_wait_t xnu_vm_page_wait;
extern pmap_enter_t xnu_pmap_enter;
extern pmap_remove_t xnu_pmap_remove;
extern vm_map_wire_t xnu_vm_map_wire;
extern vm_map_unwire_t xnu_vm_map_unwire;
extern vm_map_deallocate_t xnu_vm_map_deallocate;
extern get_task_map_reference_t xnu_get_task_map_reference;
extern get_map_pmap_t xnu_get_map_pmap;

extern _disable_preemption_t xnu_disable_preemption;
extern _enable_preemption_t xnu_enable_preemption;

extern current_processor_t xnu_current_processor;
extern cpu_to_processor_t xnu_cpu_to_processor;
extern thread_bind_t xnu_thread_bind;
extern mp_cpus_call_t xnu_mp_cpus_call;

extern timer_call_enter_t xnu_timer_call_enter;
extern timer_call_setup_t xnu_timer_call_setup;
extern timer_call_cancel_t xnu_timer_call_cancel;

extern ast_pending_t xnu_ast_pending;
extern thread_block_reason_t xnu_thread_block_reason;
extern clock_gettimeofday_t xnu_clock_gettimeofday;


/*
 * Access functions for unexported variables.
 */

vm_map_t xnu_kernel_map(void);
unsigned xnu_pmap_memory_region_count(void);
boolean_t xnu_pmap_smap_enabled(void);
void *xnu_pmap_memory_regions(void);
uint64_t xnu_physmap_base(void);
uint64_t xnu_physmap_max(void);
cpu_data_t **xnu_cpu_data_ptr(void);


/*
 *These belong to uxen.h! 
 */


#define init_timer(timer, func, param0)         \
    xnu_timer_call_setup(timer, func, param0)
#define set_timer(timer, expire)                \
    xnu_timer_call_enter(timer, expire, TIMER_CALL_VCPU)
#define cancel_timer(timer) do {                                \
        set_timer(timer, mach_absolute_time() + NSEC_PER_SEC);  \
        while (!xnu_timer_call_cancel(timer)) {                 \
            dprintk("cancel_timer block\n");                    \
            thread_block(THREAD_CONTINUE_NULL);                 \
        }                                                       \
    } while (0)


extern int xnu_symbols_present;
int uxen_load_xnu_symbols(struct uxen_syms_desc *usd);
int init_xnu_symbols(void);

#endif  /* _XNU_SYMBOLS_H_ */
