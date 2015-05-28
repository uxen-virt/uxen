/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _LIB_H_
#define _LIB_H_

#include <stdbool.h>
#include <stdint.h>
#include "config.h"

/* muldiv64: COPYRIGHT xen */
/* Compute with 96 bit intermediate result: (a*b)/c */
static inline uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
#ifdef __x86_64__
    asm ( "mul %%rdx; div %%rcx" : "=a" (a) : "0" (a), "d" (b), "c" (c) );
    return a;
#else
    union {
        uint64_t ll;
        struct {
#ifdef WORDS_BIGENDIAN
            uint32_t high, low;
#else
            uint32_t low, high;
#endif
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t)u.l.low * (uint64_t)b;
    rh = (uint64_t)u.l.high * (uint64_t)b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (rl & 0xffffffff)) / c;
    return res.ll;
#endif
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

struct __xchg_dummy { uintptr_t a[100]; };
#define __xg(x) ((volatile struct __xchg_dummy *)(x))

static inline uintptr_t __cmpxchg(
    volatile void *ptr, uintptr_t old, uintptr_t new, int size)
{
    uintptr_t prev;
    switch ( size )
    {
    case 1:
        asm volatile ( "lock; cmpxchgb %b1,%2"
                       : "=a" (prev)
                       : "q" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
    case 2:
        asm volatile ( "lock; cmpxchgw %w1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
#if defined(__i386__)
    case 4:
        asm volatile ( "lock; cmpxchgl %1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
#elif defined(__x86_64__)
    case 4:
        asm volatile ( "lock; cmpxchgl %k1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
    case 8:
        asm volatile ( "lock; cmpxchgq %1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
#endif
    }
    return old;
}

#define cmpxchg(ptr,o,n)                                            \
    ((__typeof__(*(ptr)))__cmpxchg((ptr),(uintptr_t)(o),	    \
                                   (uintptr_t)(n),sizeof(*(ptr))))

static inline void atomic_inc(uint32_t *v)
{
   asm volatile("lock; incl %0" : "+m" (*v));
}

static inline void atomic_dec(uint32_t *v)
{
   asm volatile("lock; decl %0" : "+m" (*v));
}

static inline int atomic_dec_and_test(uint32_t *v)
{
    unsigned char c;

    asm volatile("lock; decl %0; sete %1"
         : "+m" (*v), "=qm" (c)
         : : "memory");
    return c != 0;
}

static inline void atomic_add(uint32_t *v, uint32_t n)
{
    asm volatile("lock; addl %1, %0"
                  :"=m" (*v)
                  :"ir" (n), "m" (*v));
}

int strstart(const char *str, const char *val, const char **ptr);
int stristart(const char *str, const char *val, const char **ptr);

void strip_filename(char *path);
size_t urldecode(const char *str, char *output, size_t len);

#endif	/* _LIB_H_ */
