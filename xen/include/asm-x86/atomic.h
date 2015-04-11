#ifndef __ARCH_X86_ATOMIC__
#define __ARCH_X86_ATOMIC__

#include <xen/config.h>
#include <asm/system.h>

#define build_atomic_read(name, size, type, reg, barrier) \
static inline type name(const volatile type *addr) \
{ type ret; asm volatile("mov" size " %1,%0":reg (ret) \
:"m" (*(volatile type *)addr) barrier); return ret; }

#define build_atomic_write(name, size, type, reg, barrier) \
static inline void name(volatile type *addr, type val) \
{ asm volatile("mov" size " %1,%0": "=m" (*(volatile type *)addr) \
:reg (val) barrier); }

build_atomic_read(atomic_read8, "b", uint8_t, "=q", )
build_atomic_read(atomic_read16, "w", uint16_t, "=r", )
build_atomic_read(atomic_read32, "l", uint32_t, "=r", )
build_atomic_read(atomic_read_int, "l", int, "=r", )

build_atomic_write(atomic_write8, "b", uint8_t, "q", )
build_atomic_write(atomic_write16, "w", uint16_t, "r", )
build_atomic_write(atomic_write32, "l", uint32_t, "r", )
build_atomic_write(atomic_write_int, "l", int, "r", )

#ifdef __x86_64__
build_atomic_read(atomic_read64, "q", uint64_t, "=r", )
build_atomic_write(atomic_write64, "q", uint64_t, "r", )
#else
static inline uint64_t atomic_read64(const volatile uint64_t *addr)
{
    uint64_t *__addr = (uint64_t *)addr;
    return __cmpxchg8b(__addr, 0, 0);
}
static inline void atomic_write64(volatile uint64_t *addr, uint64_t val)
{
    uint64_t old = *addr, new, *__addr = (uint64_t *)addr;
    while ( (new = __cmpxchg8b(__addr, old, val)) != old )
        old = new;
}
#endif

#undef build_atomic_read
#undef build_atomic_write

#ifdef __x86_64__
#define atomic_readptr(p) atomic_read64((uint64_t *)(p))
#define atomic_writeptr(p, v) atomic_write64((uint64_t *)(p), (uint64_t)(v))
#else
#define atomic_readptr(p) atomic_read32((uint32_t *)(p))
#define atomic_writeptr(p, v) atomic_write32((uint32_t *)(p), (uint32_t)(v))
#endif

/*
 * NB. I've pushed the volatile qualifier into the operations. This allows
 * fast accessors such as _atomic_read() and _atomic_set() which don't give
 * the compiler a fit.
 */
typedef struct { int counter; } atomic_t;

#define ATOMIC_INIT(i) { (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically reads the value of @v.
 */
#define _atomic_read(v)  ((v).counter)
#define atomic_read(v)   atomic_read_int(&((v)->counter))

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 * 
 * Atomically sets the value of @v to @i.
 */ 
#define _atomic_set(v,i) (((v).counter) = (i))
#define atomic_set(v,i)  atomic_write_int(&((v)->counter), (i))

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 * 
 * Atomically adds @i to @v.
 */
static inline void atomic_add(int i, atomic_t *v)
{
    asm volatile (
        "lock; addl %1,%0"
        : "=m" (*(volatile int *)&v->counter)
        : "ir" (i), "m" (*(volatile int *)&v->counter) );
}

/**
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub(int i, atomic_t *v)
{
    asm volatile (
        "lock; subl %1,%0"
        : "=m" (*(volatile int *)&v->counter)
        : "ir" (i), "m" (*(volatile int *)&v->counter) );
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static inline int atomic_sub_and_test(int i, atomic_t *v)
{
    unsigned char c;

    asm volatile (
        "lock; subl %2,%0; sete %1"
        : "=m" (*(volatile int *)&v->counter), "=qm" (c)
        : "ir" (i), "m" (*(volatile int *)&v->counter) : "memory" );
    return c;
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1.
 */ 
static inline void atomic_inc(atomic_t *v)
{
    asm volatile (
        "lock; incl %0"
        : "=m" (*(volatile int *)&v->counter)
        : "m" (*(volatile int *)&v->counter) );
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.
 */ 
static inline void atomic_dec(atomic_t *v)
{
    asm volatile (
        "lock; decl %0"
        : "=m" (*(volatile int *)&v->counter)
        : "m" (*(volatile int *)&v->counter) );
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */ 
static inline int atomic_dec_and_test(atomic_t *v)
{
    unsigned char c;

    asm volatile (
        "lock; decl %0; sete %1"
        : "=m" (*(volatile int *)&v->counter), "=qm" (c)
        : "m" (*(volatile int *)&v->counter) : "memory" );
    return c != 0;
}

/**
 * atomic_inc_and_test - increment and test 
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */ 
static inline int atomic_inc_and_test(atomic_t *v)
{
    unsigned char c;

    asm volatile (
        "lock; incl %0; sete %1"
        : "=m" (*(volatile int *)&v->counter), "=qm" (c)
        : "m" (*(volatile int *)&v->counter) : "memory" );
    return c != 0;
}

/**
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 * 
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.
 */ 
static inline int atomic_add_negative(int i, atomic_t *v)
{
    unsigned char c;

    asm volatile (
        "lock; addl %2,%0; sets %1"
        : "=m" (*(volatile int *)&v->counter), "=qm" (c)
        : "ir" (i), "m" (*(volatile int *)&v->counter) : "memory" );
    return c;
}

static inline atomic_t atomic_compareandswap(
    atomic_t old, atomic_t new, atomic_t *v)
{
    atomic_t rc;
    rc.counter = __cmpxchg(&v->counter, old.counter, new.counter, sizeof(int));
    return rc;
}

typedef union {
#ifdef __x86_64__
    unsigned __int128 value;
#endif
    struct {
        uint64_t val_lo;
        uint64_t val_hi;
    };
} uint128_t;
#ifdef __x86_64__
typedef __int128 int128_t;
#endif

typedef uint128_t __attribute__ ((aligned (16))) atomic_domain_handle_t;

#ifdef __x86_64__
#define uint128_t_equal(a, b) ((a)->value == (b)->value)
#else
#define uint128_t_equal(a, b) ((a)->val_lo == (b)->val_lo &&    \
                               (a)->val_hi == (b)->val_hi)
#endif

#ifdef __x86_64__
static inline void
atomic_read_domain_handle(const atomic_domain_handle_t *src, uint128_t *dst)
{

    asm volatile ("xor %%rax, %%rax;"
                  "xor %%rbx, %%rbx;"
                  "xor %%rcx, %%rcx;"
                  "xor %%rdx, %%rdx;"
                  "lock cmpxchg16b %0" : "+m"(*(atomic_domain_handle_t *)src),
                  "=a"(dst->val_lo), "=d"(dst->val_hi)
                  : : "rbx", "rcx");
}

static inline void
atomic_write_domain_handle(atomic_domain_handle_t *dst, const uint128_t *val)
{
    uint128_t cur;
    int result;

    atomic_read_domain_handle(dst, &cur);
    do {
        asm volatile ("lock cmpxchg16b %0; setz %b1" : "+m"(*dst), "=q"(result),
                      "+a"(cur.val_lo), "+d"(cur.val_hi)
                      : "b"(val->val_lo), "c"(val->val_hi) : "cc");
    } while (!result);
}
#else
static inline void
atomic_read_domain_handle(const atomic_domain_handle_t *src, uint128_t *dst)
{

    /* sufficiently atomic_read_domain_handle -- uuid is being written to if
     * val_lo==0 -- v4 uuid's always have both val_lo!=0 and
     * val_hi!=0 -- special uuid's have val_hi==0 and we don't care
     * about val_hi atomicity */
    do {
        dst->val_lo = atomic_read64(&src->val_lo);
        dst->val_hi = atomic_read64(&src->val_hi);
    } while (dst->val_lo != atomic_read64(&src->val_lo) ||
             (!dst->val_lo && dst->val_hi));
}

static inline void
atomic_write_domain_handle(atomic_domain_handle_t *dst, const uint128_t *val)
{

    atomic_write64(&dst->val_lo, 0);
    atomic_write64(&dst->val_hi, val->val_hi);
    atomic_write64(&dst->val_lo, val->val_lo);
}
#endif

#endif /* __ARCH_X86_ATOMIC__ */
