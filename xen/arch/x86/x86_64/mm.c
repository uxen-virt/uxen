/******************************************************************************
 * arch/x86/x86_64/mm.c
 * 
 * Modifications to Linux original are copyright (c) 2004, K A Fraser tr This 
 * program is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 59 
 * Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/numa.h>
#include <xen/nodemask.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/asm_defns.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/fixmap.h>
#include <asm/hypercall.h>
#include <asm/msr.h>
#include <asm/setup.h>
#include <asm/numa.h>
#include <public/memory.h>

/* Parameters for PFN/MADDR compression. */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
