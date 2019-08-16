/*  Generic MTRR (Memory Type Range Register) driver.

    Copyright (C) 1997-2000  Richard Gooch
    Copyright (c) 2002	     Patrick Mochel

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free
    Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    Richard Gooch may be reached by email at  rgooch@atnf.csiro.au
    The postal address is:
      Richard Gooch, c/o ATNF, P. O. Box 76, Epping, N.S.W., 2121, Australia.

    Source: "Pentium Pro Family Developer's Manual, Volume 3:
    Operating System Writer's Guide" (Intel document number 242692),
    section 11.11.7

    This was cleaned and made readable by Patrick Mochel <mochel@osdl.org> 
    on 6-7 March 2002. 
    Source: Intel Architecture Software Developers Manual, Volume 3: 
    System Programming Guide; Section 9.11. (1997 edition - PPro).
*/

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <asm/mtrr.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include "mtrr.h"

unsigned int paddr_bits __read_mostly = 36;

