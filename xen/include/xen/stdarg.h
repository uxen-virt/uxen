#ifndef __XEN_STDARG_H__
#define __XEN_STDARG_H__

#if defined(__OpenBSD__)
#  include "/usr/include/stdarg.h"
#elif defined (__NetBSD__)
   typedef __builtin_va_list va_list;
#  define va_start(ap, last)    __builtin_stdarg_start((ap), (last))
#  define va_end(ap)            __builtin_va_end(ap)
#  define va_arg                __builtin_va_arg
#elif defined (WINNT)
   typedef __builtin_va_list va_list;
#  define va_start(v, l)        __builtin_va_start(v, l)
#  define va_end(v)             __builtin_va_end(v)
#  define va_arg(v, l)          __builtin_va_arg(v, l)
#else
#  include <stdarg.h>
#endif

#endif /* __XEN_STDARG_H__ */
