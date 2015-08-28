/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    Msvad.h

Abstract:

    Header file for common stuff.

--*/
/*
 * uXen changes:
 *
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _UXENAUDIO_H_
#define _UXENAUDIO_H_

#include <portcls.h>
#include <stdunk.h>
#include <ksdebug.h>
#include "kshelper.h"
#include "debug.h"

//=============================================================================
// Defines
//=============================================================================

// Version number. Revision numbers are specified for each sample.
#define UXENAUDIO_VERSION               1

// Revision number.
#define UXENAUDIO_REVISION              0

// Product Id
// {5B722BF8-F0AB-47ee-B9C8-8D61D31375A1}
#define STATIC_PID_UXENAUDIO\
    0x5b722bf8, 0xf0ab, 0x47ee, 0xb9, 0xc8, 0x8d, 0x61, 0xd3, 0x13, 0x75, 0xa1
DEFINE_GUIDSTRUCT("5B722BF8-F0AB-47ee-B9C8-8D61D31375A1", PID_UXENAUDIO);
#define PID_UXENAUDIO DEFINE_GUIDNAMED(PID_UXENAUDIO)

// Pool tag used for UXENAUDIO allocations
#define UXENAUDIO_POOLTAG               'UXAU'  

#define DPF_ENTER DOUT(DBG_PRINT, "===> enter")

// Channel orientation
#define CHAN_LEFT                   0
#define CHAN_RIGHT                  1
#define CHAN_MASTER                 (-1)

// Dma Settings.
#define DMA_BUFFER_SIZE             0x16000

#define KSPROPERTY_TYPE_ALL         KSPROPERTY_TYPE_BASICSUPPORT | \
                                    KSPROPERTY_TYPE_GET | \
                                    KSPROPERTY_TYPE_SET
                                    
// Specific node numbers for vadsampl.sys
#define DEV_SPECIFIC_VT_BOOL 9
#define DEV_SPECIFIC_VT_I4   10
#define DEV_SPECIFIC_VT_UI4  11

//=============================================================================
// Typedefs
//=============================================================================

// Connection table for registering topology/wave bridge connection
typedef struct _PHYSICALCONNECTIONTABLE
{
    ULONG       ulTopologyIn;
    ULONG       ulTopologyOut;
    ULONG       ulWaveIn;
    ULONG       ulWaveOut;
} PHYSICALCONNECTIONTABLE, *PPHYSICALCONNECTIONTABLE;

//=============================================================================
// Externs
//=============================================================================

// Physical connection table. Defined in mintopo.cpp for each sample
extern PHYSICALCONNECTIONTABLE TopologyPhysicalConnections;

// Generic topology handler
extern NTSTATUS PropertyHandler_Topology
( 
    IN  PPCPROPERTY_REQUEST     PropertyRequest 
);

// Generic wave port handler
extern NTSTATUS PropertyHandler_Wave
(
    IN  PPCPROPERTY_REQUEST     PropertyRequest
);

// Default WaveFilter automation table.
// Handles the GeneralComponentId request.
extern NTSTATUS PropertyHandler_WaveFilter
(
    IN PPCPROPERTY_REQUEST PropertyRequest
);

#endif
