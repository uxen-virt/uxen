/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIBELF_PRIVATE_H__
#define __LIBELF_PRIVATE_H__

#if defined(__XEN__) && !defined(__UXEN_SYS__)

#include <xen/config.h>
#include <xen/types.h>
#include <xen/string.h>
#include <xen/lib.h>
#include <libelf/libelf.h>
#include <asm/byteorder.h>
#include <public/elfnote.h>

/* we would like to use elf->log_callback but we can't because
 * there is no vprintk in Xen */
#define elf_msg(elf, fmt, args ... ) \
   if (elf->verbose) printk(fmt, ## args )
#define elf_err(elf, fmt, args ... ) \
   printk(fmt, ## args )

#define strtoull(str, end, base) simple_strtoull(str, end, base)
#define bswap_16(x) swab16(x)
#define bswap_32(x) swab32(x)
#define bswap_64(x) swab64(x)

#else /* !__XEN__ || __UXEN_SYS__ */

#if !defined(__UXEN_SYS__)
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <inttypes.h>
#else  /* __UXEN_SYS__ */
#if defined(WINNT)
#include <stdarg.h>
#include <ntifs.h>
#include <ntddk.h>
#include <xen/types.h>
#include <xen/inttypes.h>
#elif defined(__APPLE__)
#include <libkern/libkern.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <mach/mach_types.h>
#define PRIx32 "lx"
#define PRId32 "ld"
#define PRIx64 "llx"
#define PRId64 "lld"
#define PRIu64 "llu"
#else
#error Unsupported OS
#endif
#endif /* __UXEN_SYS__ */

#ifdef __sun__
#include <sys/byteorder.h>
#define bswap_16(x) BSWAP_16(x)
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)
#elif defined(__NetBSD__)
#include <sys/bswap.h>
#define bswap_16(x) bswap16(x)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#elif defined(__OpenBSD__)
#include <machine/endian.h>
#define bswap_16(x) swap16(x)
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)
#elif defined(__linux__) || defined(__Linux__) || defined(__MINIOS__)
#include <byteswap.h>
#elif defined(__APPLE__)
#include <machine/endian.h>
#define bswap_16(x) __DARWIN_OSSwapInt16(x)
#define bswap_32(x) __DARWIN_OSSwapInt32(x)
#define bswap_64(x) __DARWIN_OSSwapInt64(x)
#elif defined(WINNT)
#ifndef _MSVCRT_
  unsigned long __cdecl _byteswap_ulong (unsigned long _Long);
#endif
#define bswap_16(x) _byteswap_ushort(x)
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)
#else
#error Unsupported OS
#endif

#ifndef NO_XEN_ELF_NOTE
#include <xen/elfnote.h>
#endif
#include <libelf/libelf.h>

#ifdef __XEN_TOOLS__
#include "xenctrl.h"
#include "xc_private.h"
#endif

#define elf_msg(elf, fmt, ... )                         \
    elf_call_log_callback(elf, 0, fmt , __VA_ARGS__ );
#define elf_err(elf, fmt, ... )                         \
    elf_call_log_callback(elf, 1, fmt , __VA_ARGS__ );

void elf_call_log_callback(struct elf_binary*, int iserr, const char *fmt,...);

#define safe_strcpy(d,s)                        \
do { strncpy((d),(s),sizeof((d))-1);            \
     (d)[sizeof((d))-1] = '\0';                 \
} while (0)

#endif

#endif /* __LIBELF_PRIVATE_H_ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
