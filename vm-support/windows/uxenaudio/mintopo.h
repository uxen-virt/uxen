
/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    minitopo.h

Abstract:

    Declaration of topology miniport.

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

#ifndef _UXENAUDIO_MINTOPO_H_
#define _UXENAUDIO_MINTOPO_H_

#include "basetopo.h"

//=============================================================================
// Classes
//=============================================================================

///////////////////////////////////////////////////////////////////////////////
// CMiniportTopology 
//   

class CMiniportTopology : 
    public CMiniportTopologyUXenAudio,
    public IMiniportTopology,
    public CUnknown
{
  public:
    DECLARE_STD_UNKNOWN();
    DEFINE_STD_CONSTRUCTOR(CMiniportTopology);
    ~CMiniportTopology();

    IMP_IMiniportTopology;

    NTSTATUS                    PropertyHandlerJackDescription
    (
        IN PPCPROPERTY_REQUEST  PropertyRequest
    );
};
typedef CMiniportTopology *PCMiniportTopology;

extern NTSTATUS PropertyHandler_TopoFilter(IN PPCPROPERTY_REQUEST PropertyRequest);

#endif

