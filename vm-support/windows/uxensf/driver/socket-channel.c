/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "wskglue.h"

WSK_REGISTRATION wsk_registration;
PWSK_SOCKET socket;

enum {
    STATUS_DISCONNECTED,
    STATUS_CONNECTED,
    STATUS_ERROR
};
int channel_status = STATUS_DISCONNECTED;

#define CHANNEL_CONNECT_ID 0x01020304
extern PDRIVER_OBJECT  uxensfDriverObject;
extern unsigned int uxensfServerAddr;
NTSTATUS SendToEventLog(ULONG id, NTSTATUS error, unsigned int data)
{
    PIO_ERROR_LOG_PACKET packet;
    packet = IoAllocateErrorLogEntry(uxensfDriverObject,
        sizeof(IO_ERROR_LOG_PACKET) + 3 * sizeof(ULONG));
    RtlZeroMemory(packet, sizeof(IO_ERROR_LOG_PACKET));
    packet->ErrorCode = 0;
    packet->DumpData[0] = id;
    packet->DumpData[1] = error;
    packet->DumpData[2] = data;
    packet->DumpDataSize = 3 * sizeof(ULONG);
    IoWriteErrorLogEntry(packet);
    return STATUS_SUCCESS;
}

NTSTATUS ChannelConnect(void)
{
    SOCKADDR_IN address;
	WSK_PROVIDER_NPI provider_npi;
    NTSTATUS Status;

	Status = WskGlueRegister(&provider_npi, &wsk_registration);
	if (!NT_SUCCESS(Status)) {
        SendToEventLog(CHANNEL_CONNECT_ID, Status, uxensfServerAddr);
        return Status;
    }

	address.sin_family = AF_INET;
	address.sin_port = RtlUshortByteSwap(44444);
	address.sin_addr.S_un.S_addr = uxensfServerAddr;

    Status = WskGlueConnect(&provider_npi, (PSOCKADDR)&address, &socket);
	if (Status != STATUS_SUCCESS || !socket) {
		WskGlueUnregister(&wsk_registration);
		SendToEventLog(CHANNEL_CONNECT_ID, Status, uxensfServerAddr);
        return Status;
	}
    channel_status = STATUS_CONNECTED;
    SendToEventLog(CHANNEL_CONNECT_ID, Status, uxensfServerAddr);
    return Status;
}

static NTSTATUS CheckChannelStatus()
{
    NTSTATUS Status;
    if (channel_status == STATUS_ERROR)
        return STATUS_FILE_FORCED_CLOSED;
    if (channel_status == STATUS_DISCONNECTED) {
        Status = ChannelConnect();
        if (!NT_SUCCESS(Status)) {
            channel_status = STATUS_ERROR;
            return Status;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS ChannelSend(char* buffer, int count)
{
    NTSTATUS Status = CheckChannelStatus();
    if (!NT_SUCCESS(Status))
        return Status;
	Status = WskGlueSend(socket, buffer, count);
	if (!NT_SUCCESS(Status))
        channel_status = STATUS_ERROR;
    return Status;
}

NTSTATUS ChannelRecv(char* buffer, int count)
{
    ULONG transferred = 0;
    NTSTATUS Status = CheckChannelStatus();
    if (!NT_SUCCESS(Status))
        return Status;

    Status = WskGlueReceive(socket, buffer, count, 0, (PULONG_PTR)&transferred);
    if (NT_SUCCESS(Status) && transferred == 0)
        Status = STATUS_END_OF_FILE;
     
	if (!NT_SUCCESS(Status))
        channel_status = STATUS_ERROR;
    return Status;
}

void ChannelDisconnect()
{
    if (channel_status == STATUS_CONNECTED) {
    	WskGlueDisconnect(socket);
	    WskGlueUnregister(&wsk_registration);
        channel_status = STATUS_DISCONNECTED;
    }
}


