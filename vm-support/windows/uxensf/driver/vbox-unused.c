/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include <VBox/VBoxGuestLib.h>
#include <ntstrsafe.h>

void VBOXCALL VbglTerminate (void)
{
}

void VBOXCALL RTMemTmpFree(void *pv)
{
}

void* VBOXCALL RTMemTmpAllocTag(size_t cb, const char *pszTag)
{
    return NULL;
}

DECLVBGL(int) VbglHGCMConnect (VBGLHGCMHANDLE *pHandle, VBoxGuestHGCMConnectInfo *pData) {
    return 0;
}

DECLVBGL(int) VbglInit (void)
{
    return 0;
}

DECLVBGL(int) VbglHGCMDisconnect (VBGLHGCMHANDLE handle, VBoxGuestHGCMDisconnectInfo *pData)
{
    return 0;
}

RTDECL(size_t) RTLogBackdoorPrintf(const char *pszFormat, ...)
{
    va_list args;
#if 0 /* disabled for now - kills performance */
    static char logMsg[2048];

    va_start(args, pszFormat);
    RtlStringCchVPrintfA(logMsg, sizeof(logMsg), pszFormat, args);
    va_end(args);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", logMsg);
#endif
    return 0;
}


