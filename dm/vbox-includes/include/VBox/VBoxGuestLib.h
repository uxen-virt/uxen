/** @file
 * VBoxGuestLib - VirtualBox Guest Additions Library.
 */

/*
 * Copyright (C) 2006-2012 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, as it comes in the "COPYING.CDDL" file of the
 * VirtualBox OSE distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */

#ifndef ___VBox_VBoxGuestLib_h
#define ___VBox_VBoxGuestLib_h

#include <VBox/types.h>
#include <VBox/VMMDev2.h>
#include <VBox/VMMDev.h>     /* grumble */
#ifdef IN_RING0
#include <VBox/VBoxGuest.h>
#endif
#include <VBox/VBoxGuest2.h>


# define DECLR0VBGL(type) type VBOXCALL
# define DECLVBGL(type) DECLR0VBGL(type)
struct VBGLHGCMHANDLEDATA;
typedef struct VBGLHGCMHANDLEDATA *VBGLHGCMHANDLE;

DECLVBGL(int) VbglHGCMConnect (VBGLHGCMHANDLE *pHandle, 
    VBoxGuestHGCMConnectInfo *pData);
DECLVBGL(int) VbglHGCMDisconnect (VBGLHGCMHANDLE handle, 
    VBoxGuestHGCMDisconnectInfo *pData);
DECLVBGL(int) VbglHGCMCall (VBGLHGCMHANDLE handle, 
    VBoxGuestHGCMCallInfo *pData, uint32_t cbData);
DECLVBGL(int) VbglInit (void);
DECLVBGL(void) VbglTerminate (void);

#ifndef IN_RING0
# define VBGLR3DECL(type) type VBOXCALL
//VBGLR3DECL(int)     VbglR3Init(void);
//VBGLR3DECL(void)    VbglR3Term(void);
int     VbglR3Init(void);
void    VbglR3Term(void);

/* Clipboard functions. Not sure this is the proper place, that is the way
   in case of the original vbox anyway. */
VBGLR3DECL(int)     VbglR3ClipboardConnect(uint32_t *pu32ClientId);
VBGLR3DECL(int)     VbglR3ClipboardDisconnect(uint32_t u32ClientId);
VBGLR3DECL(int)     VbglR3ClipboardGetHostMsg(uint32_t u32ClientId,
    uint32_t *pMsg, uint32_t *pfFormats);
VBGLR3DECL(int)     VbglR3ClipboardReadData(uint32_t u32ClientId,
    uint32_t fFormat, void *pv, uint32_t cb, uint32_t *pcb);
VBGLR3DECL(int)     VbglR3ClipboardReportFormats(uint32_t u32ClientId,
    uint32_t fFormats);
VBGLR3DECL(int)     VbglR3ClipboardReportFormatsV2(uint32_t u32ClientId,
    void *pv, uint32_t cb);
VBGLR3DECL(int)     VbglR3ClipboardWriteData(uint32_t u32ClientId,
    uint32_t fFormat, void *pv, uint32_t cb);
#endif

#endif

