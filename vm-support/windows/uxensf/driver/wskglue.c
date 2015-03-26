/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "wskglue.h"

#define PRIORITY_INCREMENT 4


static NTSTATUS WskConnectCallback(PDEVICE_OBJECT devobj, PIRP irp, 
    PVOID context)
{
	UNREFERENCED_PARAMETER(devobj);
	UNREFERENCED_PARAMETER(irp);
	KeSetEvent((PKEVENT)context, PRIORITY_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS WskGlueConnect(PWSK_PROVIDER_NPI providernpi, PSOCKADDR address, 
    PWSK_SOCKET *psocket)
{
	NTSTATUS Status;
	PIRP irp;
	KEVENT event;
	SOCKADDR localaddress = {0};

	irp = IoAllocateIrp(1, FALSE);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IoSetCompletionRoutine(irp, WskConnectCallback, &event, TRUE, TRUE, TRUE);
	localaddress.sa_family = address->sa_family;
	
	Status = providernpi->Dispatch->WskSocketConnect(
			providernpi->Client, SOCK_STREAM, IPPROTO_TCP, &localaddress,
			address, 0, NULL, NULL, NULL, NULL, NULL, irp);
	if (!NT_SUCCESS(Status)) {
		IoFreeIrp(irp);
		return Status;
	}

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		Status = irp->IoStatus.Status;
		if (!NT_SUCCESS(Status)) {
			IoFreeIrp(irp);
			return Status;
		}
	}

	*psocket = (PWSK_SOCKET)irp->IoStatus.Information;
	IoFreeIrp(irp);
	return Status;
}

static NTSTATUS WskRecvCallback(PDEVICE_OBJECT devobj, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(devobj);
	UNREFERENCED_PARAMETER(irp);
	KeSetEvent((PKEVENT)context, PRIORITY_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS WskGlueReceiveInternal(PWSK_SOCKET socket, PVOID buffer, 
    ULONG count, ULONG flags, PULONG_PTR transferred)
{
	WSK_BUF wskbuf;
	KEVENT event;
	PIRP irp;
    NTSTATUS Status;

	irp = IoAllocateIrp(1, FALSE);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IoSetCompletionRoutine(irp, WskRecvCallback, &event, TRUE, TRUE,
			TRUE);

	wskbuf.Mdl = IoAllocateMdl(buffer, count, FALSE, FALSE, NULL);
	if (!wskbuf.Mdl)
		return STATUS_MORE_PROCESSING_REQUIRED;

	MmBuildMdlForNonPagedPool(wskbuf.Mdl);
	wskbuf.Offset = 0;
	wskbuf.Length = count;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)(socket->Dispatch))->
		WskReceive(socket, &wskbuf, flags, irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		Status = irp->IoStatus.Status;
	}

	*transferred = irp->IoStatus.Information;
	IoFreeIrp(irp);
    IoFreeMdl(wskbuf.Mdl);
	return Status;
}

NTSTATUS WskGlueReceive(PWSK_SOCKET socket, PVOID buffer, ULONG count, 
    ULONG flags, PULONG_PTR transferred)
{
    NTSTATUS Status;
    ULONG left = count;
    char * buf = (char*)buffer;
    while (left > 0) {
        Status = WskGlueReceiveInternal(socket, buf + count - left, left, flags,
            transferred);
        if (Status)
            return Status;
        if (!(*transferred))
            return Status;
        left -= *transferred;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WskSendCallback(PDEVICE_OBJECT devobj, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(devobj);
	UNREFERENCED_PARAMETER(irp);
	KeSetEvent((PKEVENT)context, PRIORITY_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS WskGlueSend(PWSK_SOCKET socket, PVOID buffer, ULONG count)
{
	WSK_BUF wskbuf;
	KEVENT event;
	PIRP irp;
    NTSTATUS Status;

	irp = IoAllocateIrp(1, FALSE);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IoSetCompletionRoutine(irp, WskSendCallback, &event, TRUE, TRUE, TRUE);

	wskbuf.Mdl = IoAllocateMdl(buffer, count, FALSE, FALSE, NULL);
	if (!wskbuf.Mdl)
		return STATUS_MORE_PROCESSING_REQUIRED;
	MmBuildMdlForNonPagedPool(wskbuf.Mdl);
	wskbuf.Offset = 0;
	wskbuf.Length = count;

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)(socket->Dispatch))->
		WskSend(socket, &wskbuf, 0, irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		Status = irp->IoStatus.Status;
	}

	IoFreeIrp(irp);
    IoFreeMdl(wskbuf.Mdl);
	return Status;
}

static NTSTATUS WskCloseSocketCallback(PDEVICE_OBJECT devobj, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(devobj);
	UNREFERENCED_PARAMETER(irp);
	KeSetEvent((PKEVENT)context, PRIORITY_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS WskGlueDisconnect(PWSK_SOCKET socket)
{
	KEVENT event;
	PIRP irp;
    NTSTATUS Status;

	irp = IoAllocateIrp(1, FALSE);
	if (!irp) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IoSetCompletionRoutine(irp, WskCloseSocketCallback, &event, TRUE, TRUE,	TRUE);

	Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)(socket->Dispatch))->
		WskCloseSocket(socket, irp);
	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		Status = irp->IoStatus.Status;
	}

	IoFreeIrp(irp);
	return Status;
}

NTSTATUS WskGlueRegister(PWSK_PROVIDER_NPI providernpi, 
    PWSK_REGISTRATION registration)
{
	WSK_CLIENT_NPI wskClientNpi;
	WSK_CLIENT_DISPATCH wskDispatch = {MAKE_WSK_VERSION(1, 0), 0, NULL};
    NTSTATUS Status;

	wskClientNpi.ClientContext = NULL;
	wskClientNpi.Dispatch = &wskDispatch;

	Status = WskRegister(&wskClientNpi, registration);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = WskCaptureProviderNPI(registration, WSK_INFINITE_WAIT, 
        providernpi);
	if (!NT_SUCCESS(Status)) {
		WskDeregister(registration);
		return Status;
	}

	return STATUS_SUCCESS;
}

VOID WskGlueUnregister(PWSK_REGISTRATION registration)
{
	WskReleaseProviderNPI(registration);
	WskDeregister(registration);
}

