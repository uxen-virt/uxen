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

#ifndef XG_PRIVATE_H
#define XG_PRIVATE_H

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>

#include "xenctrl.h"
#include "xenguest.h"
#include "xc_private.h"

#include <xen/memory.h>
#include <xen/elfnote.h>

#ifndef ELFSIZE
#include <limits.h>
#if UINT_MAX == ULONG_MAX
#define ELFSIZE 32
#else
#define ELFSIZE 64
#endif
#endif

char *xc_read_image(xc_interface *xch,
                    const char *filename, unsigned long *size);

#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE       0x080
#define _PAGE_GLOBAL    0x100

#define ROUNDUP(_x,_w) (((unsigned long)(_x)+(1UL<<(_w))-1) & ~((1UL<<(_w))-1))
#define NRPAGES(x) (ROUNDUP(x, PAGE_SHIFT) >> PAGE_SHIFT)


#endif /* XG_PRIVATE_H */
