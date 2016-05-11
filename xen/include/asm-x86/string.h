#ifndef __X86_STRING_H__
#define __X86_STRING_H__

#include <xen/config.h>

#define __HAVE_ARCH_MEMCPY
#define memcpy(t,f,n) (__builtin_memcpy((t),(f),(n)))

#define __HAVE_ARCH_MEMMOVE
#define memmove(t,f,n) (__builtin_memmove((t),(f),(n)))

#define __HAVE_ARCH_MEMSET
#define memset(s,c,n) (__builtin_memset((s),(c),(n)))

#endif /* __X86_STRING_H__ */
