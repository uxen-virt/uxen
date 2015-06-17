
#ifndef __X86_ASM_DEFNS_H__
#define __X86_ASM_DEFNS_H__

#ifndef COMPILE_OFFSETS
/* NB. Auto-generated from arch/.../asm-offsets.c */
#include <asm/asm-offsets.h>
#endif
#include <asm/processor.h>
#include <xen/compiler.h>

#ifdef __x86_64__
#include <asm/x86_64/asm_defns.h>
#else
#include <asm/x86_32/asm_defns.h>
#endif

/* Exception table entry */
#ifdef __ASSEMBLY__
# define _ASM__EXTABLE(sfx, from, to)             \
    .section .ex_table##sfx, "a" ;                \
    .balign 4 ;                                   \
    .long _ASM_EX(from), _ASM_EX(to) ;            \
    _ASM_PREVIOUS
#else
# define _ASM__EXTABLE(sfx, from, to)             \
    " .section .ex_table" #sfx ",\"a\"\n"         \
    " .balign 4\n"                                \
    " .long " _ASM_EX(from) ", " _ASM_EX(to) "\n" \
    " " _ASM_PREVIOUS "\n"
#endif

#define _ASM_EXTABLE(from, to)     _ASM__EXTABLE(, from, to)
#define _ASM_PRE_EXTABLE(from, to) _ASM__EXTABLE(.pre, from, to)

#ifdef __ASSEMBLY__

#define UNLIKELY_START(cond, tag) \
        j##cond .Lunlikely.tag;   \
        _ASM_SUBSECTION 1;	  \
        .Lunlikely.tag:

#define UNLIKELY_END(tag)         \
        jmp .Llikely.tag;         \
        _ASM_SUBSECTION 0;	  \
        .Llikely.tag:

#endif

#define _ASM_CLAC      ".byte 0x0f,0x01,0xca"
#define _ASM_STAC      ".byte 0x0f,0x01,0xcb"

#endif /* __X86_ASM_DEFNS_H__ */
