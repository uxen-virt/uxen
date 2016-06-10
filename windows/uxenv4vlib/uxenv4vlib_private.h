/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define UNICODE

#include "gh_stdint.h"

#include <ntifs.h>
#include <csq.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <sddl.h>
#include <stdarg.h>
#include <uxen/platform_interface.h>

#define XENV4V_MAX_RING_LENGTH (4*1024*1024UL)


#define XENV4V_DRIVER

#define V4V_DLL_EXPORT

#include "uxenv4vlib.h"
#include "log.h"

#include "gh_xenv4v.h"


#define UXEN_V4VLIB_MAX_RESUME_DPCS 16

#define UXEN_V4V_TAG 'uv4v'

//Aparently this does exist in win7 but is only defined in win8
typedef volatile LONG EX_SPIN_LOCK, *PEX_SPIN_LOCK;

#include "prototypes.h"
#include "alloc.h"

static __inline void check_resume(void)
{
    if (!state_bar_ptr) return;
    if (!*state_bar_ptr) return;
    if ((*state_bar_ptr)->v4v_running) return;
    uxen_v4v_resume();
}

#define UXEN_V4VLIB_MAX_RESUME_DPCS 16

#define FISH do { DbgPrint("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__); } while(0)
