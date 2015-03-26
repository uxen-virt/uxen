/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include <wsk.h>
/* These functions are responsible for initialization of kernel winsock, plus
   implement synchronous send/receive by providing relevant callbacks to
   asynchronous kernel winsock functions. */
NTSTATUS WskGlueRegister(PWSK_PROVIDER_NPI providernpi,
    PWSK_REGISTRATION registration);

VOID WskGlueUnregister(PWSK_REGISTRATION clireg);

NTSTATUS WskGlueSend(PWSK_SOCKET socket, PVOID buffer, ULONG count);

NTSTATUS WskGlueReceive(PWSK_SOCKET sock, PVOID data, ULONG datal, ULONG flags,
		PULONG_PTR recvd);

NTSTATUS WskGlueConnect(PWSK_PROVIDER_NPI providernpi, PSOCKADDR address,
    PWSK_SOCKET *psocket);

NTSTATUS WskGlueDisconnect(PWSK_SOCKET socket);


