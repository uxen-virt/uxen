#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <xen/config.h>
#include <xen/types.h>
#include <asm/init.h>
#include <uxen/uxen_desc.h>

/*
 * Mark functions and data as being only used at initialization
 * or exit time.
 */
#ifdef __UXEN_todo__
#define __init       \
    __attribute__ ((__section__ (".init.text")))
#define __exit       \
    __attribute_used__ __attribute__ ((__section__(".exit.text")))
#else  /* __UXEN_todo__ */
#define __init
#define __exit
#endif  /* __UXEN_todo__ */
#define __initdata   \
    __attribute__ ((__section__ (".init.data")))
#ifdef __UXEN_todo__
#define __exitdata   \
    __attribute_used__ __attribute__ ((__section__ (".exit.data")))
#else  /* __UXEN_todo__ */
#define __exitdata
#endif  /* __UXEN_todo__ */
#define __initsetup  \
    __attribute_used__ __attribute__ ((__section__ (".init.setup")))
#define __init_call(lvl)  \
    __attribute_used__ __attribute__ ((__section__ (".initcall" lvl ".init")))
#define __exit_call  \
    __attribute_used__ __attribute__ ((__section__ (".exitcall.exit")))

/* These macros are used to mark some functions or 
 * initialized data (doesn't apply to uninitialized data)
 * as `initialization' functions. The kernel can take this
 * as hint that the function is used only during the initialization
 * phase and free up used memory resources after
 *
 * Usage:
 * For functions:
 * 
 * You should add __init immediately before the function name, like:
 *
 * static void __init initme(int x, int y)
 * {
 *    extern int z; z = x * y;
 * }
 *
 * If the function has a prototype somewhere, you can also add
 * __init between closing brace of the prototype and semicolon:
 *
 * extern int initialize_foobar_device(int, int, int) __init;
 *
 * For initialized data:
 * You should insert __initdata between the variable name and equal
 * sign followed by value, e.g.:
 *
 * static int init_variable __initdata = 0;
 * static char linux_logo[] __initdata = { 0x32, 0x36, ... };
 *
 * Don't forget to initialize data not at file scope, i.e. within a function,
 * as gcc otherwise puts the data into the bss section and not into the init
 * section.
 * 
 * Also note, that this data cannot be "const".
 */

#ifndef __ASSEMBLY__

/*
 * Used for initialization calls..
 */
typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);

#define presmp_initcall(fn) \
    static initcall_t __initcall_##fn __init_call("presmp") = fn
#define __initcall(fn) \
    static initcall_t __initcall_##fn __init_call("1") = fn
#define __exitcall(fn) \
    static exitcall_t __exitcall_##fn __exit_call = fn

void do_presmp_initcalls(void);
void do_initcalls(void);

/*
 * Used for kernel command line parameter setup
 */
struct kernel_param {
    const char *name;
    enum {
        OPT_STR,
        OPT_UINT,
        OPT_BOOL,
        OPT_INVBOOL,
        OPT_SIZE,
        OPT_CUSTOM
    } type;
    void *var;
    uint32_t len;
    uint32_t mask_offset;
    uint64_t opt_mask;
    uint32_t value_offset;
    uint32_t value_size;
    uint32_t _align[0] __attribute__((__aligned__(32)));
} __attribute__((__aligned__(32)));

extern struct kernel_param __setup_start, __setup_end;

#define __setup_str static __initdata __attribute__((__aligned__(1))) char
#define __kparam static __attribute_used__ __initsetup struct kernel_param

#define custom_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = { __setup_str_##_var, OPT_CUSTOM, _var, 0 }
#define boolean_param(_name, _var)                                      \
    __setup_str __setup_str_##_var[] = _name;                           \
    __kparam __setup_##_var =                                           \
    { __setup_str_##_var, OPT_BOOL, &_var, sizeof(_var),                \
      offsetof(struct uxen_init_desc, UXEN_INIT_##_var##_MASK),         \
      UXEN_INIT_##_var, offsetof(struct uxen_init_desc, _var),          \
      sizeof(((struct uxen_init_desc *)NULL)->_var) }
#define invbool_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name;                           \
    __kparam __setup_##_var =                                           \
    { __setup_str_##_var, OPT_INVBOOL, &_var, sizeof(_var),             \
      offsetof(struct uxen_init_desc, UXEN_INIT_##_var##_MASK),         \
      UXEN_INIT_##_var, offsetof(struct uxen_init_desc, _var),          \
      sizeof(((struct uxen_init_desc *)NULL)->_var) }
#define integer_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name;                           \
    __kparam __setup_##_var =                                           \
    { __setup_str_##_var, OPT_UINT, &_var, sizeof(_var),                \
      offsetof(struct uxen_init_desc, UXEN_INIT_##_var##_MASK),         \
      UXEN_INIT_##_var, offsetof(struct uxen_init_desc, _var),          \
      sizeof(((struct uxen_init_desc *)NULL)->_var) }
#define size_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { __setup_str_##_var, OPT_SIZE, &_var, sizeof(_var) }
#define string_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name;                           \
    __kparam __setup_##_var =                                           \
    { __setup_str_##_var, OPT_STR, &_var, sizeof(_var),                 \
      offsetof(struct uxen_init_desc, UXEN_INIT_##_var##_MASK),         \
      UXEN_INIT_##_var, offsetof(struct uxen_init_desc, _var),          \
      sizeof(((struct uxen_init_desc *)NULL)->_var) }

/* Make sure obsolete cmdline params don't break the build. */
#define __setup(_name, _fn) static void * __attribute_used__ _dummy_##_fn = _fn
    
#endif /* __ASSEMBLY__ */

#ifdef CONFIG_HOTPLUG
#define __devinit
#define __devinitdata
#define __devexit
#define __devexitdata
#else
#define __devinit __init
#define __devinitdata __initdata
#define __devexit __exit
#define __devexitdata __exitdata
#endif

#endif /* _LINUX_INIT_H */
