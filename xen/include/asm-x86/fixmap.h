/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 * Modifications for Xen are copyright (c) 2002-2004, K A Fraser
 */

#ifndef _ASM_FIXMAP_H
#define _ASM_FIXMAP_H

#include <xen/config.h>
#include <xen/pfn.h>
#include <xen/kexec.h>
#include <xen/iommu.h>
#include <asm/apicdef.h>
#include <asm/acpi.h>
#include <asm/page.h>
#include <asm/amd-iommu.h>
#include <asm/msi.h>
#include <acpi/apei.h>

#define __fix_to_virt(x)   (({ BUG(); 0UL; }))
#define fix_to_virt(x)   (__fix_to_virt(x))

#endif
