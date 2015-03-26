/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    hw.h

Abstract:

    Declaration of UXENAUDIO HW class. 
    UXENAUDIO HW has an array for storing mixer and volume settings
    for the topology.

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

#ifndef _UXENAUDIO_HW_H_
#define _UXENAUDIO_HW_H_

//=============================================================================
// Defines
//=============================================================================
// BUGBUG we should dynamically allocate this...
#define MAX_TOPOLOGY_NODES      20

//=============================================================================
// Classes
//=============================================================================
///////////////////////////////////////////////////////////////////////////////
// CUXENAUDIOHW
// This class represents virtual UXENAUDIO HW. An array representing volume
// registers and mute registers.

class CUXENAUDIOHW
{
public:
protected:
    BOOL                        m_MuteControls[MAX_TOPOLOGY_NODES];
    LONG                        m_VolumeControls[MAX_TOPOLOGY_NODES];
    ULONG                       m_ulMux;            // Mux selection
    BOOL                        m_bDevSpecific;
    INT                         m_iDevSpecific;
    UINT                        m_uiDevSpecific;

private:

public:
    CUXENAUDIOHW();
    
    void                        MixerReset();
    BOOL                        bGetDevSpecific();
    void                        bSetDevSpecific
    (
        IN  BOOL                bDevSpecific
    );
    INT                         iGetDevSpecific();
    void                        iSetDevSpecific
    (
        IN  INT                 iDevSpecific
    );
    UINT                        uiGetDevSpecific();
    void                        uiSetDevSpecific
    (
        IN  UINT                uiDevSpecific
    );
    BOOL                        GetMixerMute
    (
        IN  ULONG               ulNode
    );
    void                        SetMixerMute
    (
        IN  ULONG               ulNode,
        IN  BOOL                fMute
    );
    ULONG                       GetMixerMux();
    void                        SetMixerMux
    (
        IN  ULONG               ulNode
    );
    LONG                        GetMixerVolume
    (   
        IN  ULONG               ulNode,
        IN  LONG                lChannel
    );
    void                        SetMixerVolume
    (   
        IN  ULONG               ulNode,
        IN  LONG                lChannel,
        IN  LONG                lVolume
    );

protected:
private:
};
typedef CUXENAUDIOHW                *PCUXENAUDIOHW;

#endif
