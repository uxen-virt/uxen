/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _COMPILER_H_
#define _COMPILER_H_

#ifdef _WIN32

#define PRId8 "d"
#define PRIu8 "u"
#define PRIx8 "x"
#define PRId16 "d"
#define PRIu16 "u"
#define PRIx16 "x"
#define PRId32 "d"
#define PRIu32 "u"
#define PRIx32 "x"
#define PRId64 "I64d"
#define PRIu64 "I64u"
#define PRIx64 "I64x"
#define PRIdS "Id"
#define PRIuS "Iu"
#define PRIxS "Ix"
#ifdef __x86_64__
#define PRIdPTR PRId64
#define PRIuPTR PRIu64
#define PRIxPTR PRIx64
#else
#define PRIdPTR PRId32
#define PRIuPTR PRIu32
#define PRIxPTR PRIx32
#endif

#endif /* _WIN32 */

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/*----------------------------------------------------------------------------
| The macro QEMU_GNUC_PREREQ tests for minimum version of the GNU C compiler.
| The code is a copy of SOFTFLOAT_GNUC_PREREQ, see softfloat-macros.h.
*----------------------------------------------------------------------------*/
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
# define QEMU_GNUC_PREREQ(maj, min) \
         ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
# define QEMU_GNUC_PREREQ(maj, min) 0
#endif

#define QEMU_NORETURN __attribute__ ((__noreturn__))

#if QEMU_GNUC_PREREQ(3, 4)
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define QEMU_WARN_UNUSED_RESULT
#endif

#if defined(_WIN32)
# define PACKED __attribute__((gcc_struct, packed))
#else
# define PACKED __attribute__((packed))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#endif

/* Convert from a base type to a parent type, with compile time checking.  */
#ifdef __GNUC__
#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
#else
#define DO_UPCAST(type, field, dev) container_of(dev, type, field)
#endif

#define typeof_field(type, field) typeof(((type *)0)->field)
#define type_check(t1,t2) ((t1*)0 - (t2*)0)

#if defined(DEBUG)
#define debug_break() asm("int $3\n")
#else
#define debug_break() do { /**/ } while (0)
#endif

#define warn_once(fmt, ...) do {                \
        static int warned = 0;                  \
        if (!warned) {                          \
            warned++;                           \
            debug_printf(fmt, ## __VA_ARGS__);  \
            debug_break();                      \
        }                                       \
    } while (0)

#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)
#define stringify(s)	tostring(s)
#define tostring(s)	#s

#if defined _WIN32
#  define GCC_ATTR __attribute__((__unused__, format(printf, 1, 2)))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
#elif defined __GNUC__
# if !QEMU_GNUC_PREREQ(4, 4)
   /* gcc versions before 4.4.x don't support gnu_printf, so use printf. */
#  define GCC_ATTR __attribute__((__unused__, format(printf, 1, 2)))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))
# else
   /* Use gnu_printf when supported (qemu uses standard format strings). */
#  define GCC_ATTR __attribute__((__unused__, format(gnu_printf, 1, 2)))
#  define GCC_FMT_ATTR(n, m) __attribute__((format(gnu_printf, n, m)))
# endif
#else
#define GCC_ATTR /**/
#define GCC_FMT_ATTR(n, m)
#endif

#define inline        __inline__
#define noinline      __attribute__((noinline))

#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int:-!!(condition); }))

static inline int test_bit(uint8_t *map, int bit)
{
    return ( map[bit / 8] & (1 << (bit % 8)) );
}

static inline void set_bit(uint8_t *map, int bit)
{
    map[bit / 8] |= (1 << (bit % 8));
}

static inline void clear_bit(uint8_t *map, int bit)
{
    map[bit / 8] &= ~(1 << (bit % 8));
}

#endif	/* _COMPILER_H_ */
