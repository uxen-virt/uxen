/*
 * Copyright 2015-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define UNICODE

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <sddl.h>
#include <stdarg.h>

#define XENV4V_DRIVER
#include <xen/types.h>
#include <uxen/platform_interface.h>

#define XENV4V_MAX_RING_LENGTH (4*1024*1024UL)

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

#define check_resume()                                                  \
    if (state_bar_ptr && *state_bar_ptr && !((*state_bar_ptr)->v4v_running)) { \
        uxen_v4v_warn("resuming v4v");                                  \
        uxen_v4v_resume();                                              \
    }

#define UXEN_V4VLIB_MAX_RESUME_DPCS 16

#define FISH do { DbgPrint("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__); } while(0)

#undef ASSERT
#define ASSERT(expr) do {                                               \
        if (!(expr)) {                                                  \
            uxen_v4v_err("ASSERT(%s) failed", # expr);                  \
        }                                                               \
    } while (0, 0)

