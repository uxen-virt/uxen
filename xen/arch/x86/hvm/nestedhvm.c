/*
 * Nested HVM
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <asm/msr.h>
#include <asm/hvm/support.h>	/* for HVM_DELIVER_NO_ERROR_CODE */
#include <asm/hvm/hvm.h>
#include <asm/p2m.h>    /* for struct p2m_domain */
#include <asm/hvm/nestedhvm.h>
#include <asm/event.h>  /* for local_event_delivery_(en|dis)able */
#include <asm/paging.h> /* for paging_mode_hap() */

/* Nested HVM on/off per domain */
bool_t
nestedhvm_enabled(struct domain *d)
{
    bool_t enabled;

    enabled = 0;
    
    return enabled;
}

/* Nested VCPU */
bool_t
nestedhvm_vcpu_in_guestmode(struct vcpu *v)
{
    return 0;
}

