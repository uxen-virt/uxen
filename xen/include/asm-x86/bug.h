#ifndef __X86_BUG_H__
#define __X86_BUG_H__

#ifdef __x86_64__
#include <asm/x86_64/bug.h>
#else
#include <asm/x86_32/bug.h>
#endif

struct bug_frame {
    unsigned char ud2[2];
    unsigned char ret;
    unsigned short id; /* BUGFRAME_??? */
} __attribute__((packed));

#define BUGFRAME_run_fn 0
#define BUGFRAME_warn   1
#define BUGFRAME_bug    2
#define BUGFRAME_assert 3
#define BUGFRAME_abort  4

#if !defined(__UXEN__) || defined(UXEN_HOST_WINDOWS)
#define run_in_exception_handler(fn)               \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_run_fn),                 \
            "i" (&(fn)) )
#endif  /* __UXEN__ */

#ifndef UXEN_HOST_OSX
#define WARN()                                     \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_warn | (__LINE__<<3)),   \
            "i" (__FILE__) )
#else
#define WARN()                                     \
    UI_HOST_CALL(ui_printf, NULL, "Xen WARN at %.50s:%d\n", __FILE__, __LINE__);
#endif

#define WARN_ONCE() do {                        \
        static int warned = 0;                  \
        if (!warned) {                          \
            warned++;                           \
            WARN();                             \
        }                                       \
    } while (0)

#define BUG()                                      \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_bug | (__LINE__<<3)),    \
            "i" (__FILE__) )

/* like BUG but don't print regs/stacktraces or do other ud2 processing */
#define ABORT()                                    \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1)                  \
        : : "i" (BUGFRAME_abort | (__LINE__<<3)),  \
            "i" (__FILE__) )

#define assert_failed(p)                           \
    asm volatile (                                 \
        "ud2 ; ret %0" BUG_STR(1) BUG_STR(2)       \
        : : "i" (BUGFRAME_assert | (__LINE__<<3)), \
            "i" (__FILE__), "i" (p) )

#define DEBUG()					\
    asm volatile ( "int $3\n" )
#define DEBUG_IF(p)                             \
    if (p) DEBUG()
#define DEBUGLOG()                                            \
    printk("%s:%d %s %p\n", __FILE__, __LINE__, __FUNCTION__, \
           __builtin_return_address(0));

#endif /* __X86_BUG_H__ */
