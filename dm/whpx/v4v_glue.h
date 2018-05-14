/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef V4V_GLUE_H_
#define V4V_GLUE_H_

#include "v4v_err.h"

#define WHPX_V4V

typedef uint16_t domid_t;
typedef uint64_t mfn_t;

typedef CPUState pcpu_t;


struct v4v_domain;
struct domain;

extern struct domain guest, dom0;

#define ASSERT assert

/* domain glue */
static inline struct domain *vmptr(CPUState *cpu) {
    return cpu ? &guest : &dom0;
}

static inline struct domain *vm_get_by_id(domid_t id) {
    if (id == 0)
        return &dom0;
    else if (id == guest.domain_id)
        return &guest;
    return NULL;
}

static inline int vm_get(struct domain *d) {
    return 1;
}

static inline void vm_put(struct domain *d) {
}

static inline void vm_lock(struct domain *d) {
    critical_section_enter(&d->lock);
}

static inline void vm_unlock(struct domain *d) {
    critical_section_leave(&d->lock);
}

/* lock glue */

#define DEFINE_RWLOCK(x) rwlock_t x
typedef critical_section spinlock_t;
typedef SRWLOCK rwlock_t;

static inline void rwlock_init(rwlock_t *l) {
    InitializeSRWLock(l);
}

static inline void read_lock(rwlock_t *l) {
    AcquireSRWLockShared(l);
}

static inline void read_unlock(rwlock_t *l) {
    ReleaseSRWLockShared(l);
}

static inline void write_lock(rwlock_t *l) {
    AcquireSRWLockExclusive(l);
}

static inline void write_unlock(rwlock_t *l) {
    ReleaseSRWLockExclusive(l);
}

#define spin_lock_init critical_section_init
#define spin_lock critical_section_enter
#define spin_unlock critical_section_leave

/* other glue */

#define DEFINE_V4V_GUEST_HANDLE(x)
#define V4V_GUEST_HANDLE(t) t*
#define V4V_GUEST_HANDLE_NULL(t) NULL

#define IS_HOST(d) ((d)->is_host)
#define IS_PRIV_SYS(d) ((d)->is_host)

static inline void* map_domain_page_global(mfn_t mfn)
{
    void *p;
    uint64_t len = PAGE_SIZE;

    p = whpx_ram_map(mfn << PAGE_SHIFT, &len);
    assert(len == PAGE_SIZE);

    return p;
}

static inline void unmap_domain_page_global(void *p)
{
    whpx_ram_unmap(p);
}

#define guest_handle_add_offset(p,nr) (p += nr)
#define guest_handle_from_ptr(ptr,type) ((type*)ptr)
#define guest_handle_okay(a, b) 1
#define guest_handle_cast(p, t) ((t*)p)
#define guest_handle_is_aligned(p, mask) (!((uintptr_t)(p) & (mask)))
#define guest_handle_is_null(x) (x == NULL)
#define unlikely(x) x
#define prefetch(x)
#define rcu_lock_domain_by_uuid(a,b) NULL
#define rcu_lock_remote_target_domain_by_id(a, b) 0
#define rcu_unlock_domain(p)
#define get_domain_by_id(x) vm_get_by_id(x)
#define get_domain(x) vm_get(x)
#define put_domain(x) vm_put(x)
#define domain_lock(x) vm_lock(x)
#define domain_unlock(x) vm_unlock(x)
#define mfn_valid(x) 1
#define mfn_retry(x) 0
#define put_page(x)
#define mfn_x(x) x
#define _mfn(pfn) pfn
#define check_free_pages_needed(x) 0
#define hypercall_create_retry_continuation() (-ENOSYS)

#define printk debug_printf

#define XENLOG_G_ERR ""
#define XENLOG_G_WARNING ""
typedef unsigned short *printk_symbol;

#define PRI_xen_pfn PRIx64
#define PRI_mfn PRIx64

#define mb()                    \
    __sync_synchronize(); \
    asm volatile("":::"memory");

#define BUG_ON(x) if (x) { bug(NULL,__FILE__,__LINE__,0); }

static inline int
v4v_raw_copy_from_guest(pcpu_t *cpu, volatile void *dst, uint64_t src, uint64_t off, size_t sz)
{
    // assume 'guest' is ourselves (host/uxendm) if cpu == NULL
    if (!cpu)
        memcpy((void*)dst, (void*)(uintptr_t)(src + off), sz);
    else
        whpx_copy_from_guest_va(cpu, (void*)dst, src+off, sz);

    return 0;
}

static inline int
v4v_raw_copy_to_guest(pcpu_t *cpu, uint64_t dst, volatile void *src, size_t sz)
{
    // assume 'guest' is ourselves (host/uxendm) if cpu == NULL
    if (!cpu)
        memcpy((void*)(uintptr_t)dst, (void*)src, sz);
    else
        whpx_copy_to_guest_va(cpu, dst, (void*)src, sz);

    return 0;
}

#define v4v_copy_from_guest_errno(cpu, dst, src, nr) \
    v4v_raw_copy_from_guest(cpu, dst, (uint64_t)(uintptr_t)(src), 0, sizeof(*(src))*nr)
#define v4v_copy_from_guest_offset_errno(cpu, dst, src, off, nr) \
    v4v_raw_copy_from_guest(cpu, dst, (uint64_t)(uintptr_t)(src), sizeof(*(src))*off, sizeof(*(src))*nr)

#define v4v_copy_field_to_guest_errno(cpu, dst, src, field) \
    v4v_raw_copy_to_guest(cpu, (uint64_t)(uintptr_t)(&(dst)->field), &(src)->field, sizeof((src)->field))
#define v4v_copy_field_from_guest_errno(cpu, dst, src, field) \
    v4v_raw_copy_from_guest(cpu, (&(dst)->field), (uint64_t)(uintptr_t)(&(src)->field), 0, sizeof((src)->field))

#endif
