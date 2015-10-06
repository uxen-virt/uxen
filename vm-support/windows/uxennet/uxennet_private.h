/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <ndis.h>

#undef DBG

#pragma warning(disable:4127)  //conditional expression is a constant
#pragma warning(disable:4201)  //standard extension used : nameless struct/union

#include <uxenv4vlib.h>

#undef DBG

#define V4V_RING_LEN 131072
//#define V4V_RING_LEN 524288
//#define V4V_RING_LEN 1048576

struct _MP_ADAPTER;

typedef struct uxen_net {
    LIST_ENTRY      list;
    struct _MP_ADAPTER *parent;
    int anum;
    uxen_v4v_ring_handle_t *recv_ring;
    v4v_addr_t  dest_addr;
    KDPC    resume_dpc;
    int ready;
} Uxennet;

typedef struct uxen_net_globals {
    LIST_ENTRY      adapter_list;
    NDIS_SPIN_LOCK  lock;
} Uxennet_globals;


#include "miniport.h"
#include "public.h"

#include "prototypes.h"

