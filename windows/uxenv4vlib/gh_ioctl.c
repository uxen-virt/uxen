/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * uXen changes:
 *
 * Copyright 2015, Bromium, Inc.
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

#include "uxenv4vlib_private.h"

static NTSTATUS gh_v4v_ctrl_initialize_file(xenv4v_context_t *ctx, v4v_init_values_t *invs, PIRP irp);

static NTSTATUS
gh_v4v_ctrl_dump_ring(xenv4v_context_t *ctx)
{
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    LONG               val;
    KLOCK_QUEUE_HANDLE lqh;

    val = InterlockedExchangeAdd(&ctx->state, 0);

    if (val & (XENV4V_STATE_BOUND)) {
        KeAcquireInStackQueuedSpinLock(&ctx->ring_object->lock, &lqh);
        gh_v4v_dump_ring(ctx->ring_object->ring);
        KeReleaseInStackQueuedSpinLock(&lqh);
        status = STATUS_SUCCESS;
    }

    return status;
}

static NTSTATUS
gh_v4v_ctrl_get_info(xenv4v_context_t *ctx, v4v_getinfo_values_t *gi)
{
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    LONG               val;
    KLOCK_QUEUE_HANDLE lqh;

    val = InterlockedExchangeAdd(&ctx->state, 0);

    if (gi->type == V4V_GET_LOCAL_INFO) {
        if (val & (XENV4V_STATE_BOUND)) {
            KeAcquireInStackQueuedSpinLock(&ctx->ring_object->lock, &lqh);
            RtlMoveMemory(&gi->ring_info, &ctx->ring_object->ring->id, sizeof(v4v_ring_id_t));
            KeReleaseInStackQueuedSpinLock(&lqh);
            status = STATUS_SUCCESS;
        }
    }

    return status;
}

static NTSTATUS
gh_v4v_ctrl_bind(xenv4v_extension_t *pde, xenv4v_context_t *ctx, v4v_bind_values_t *bvs)
{
    NTSTATUS            status = STATUS_SUCCESS;
    LONG                val;
    KLOCK_QUEUE_HANDLE  lqh;
    xenv4v_ring_t        *robj;
    uint32_t            port;

    // Use a simple guard variable to enforce the state transition order
    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_IDLE) {
        TraceWarning(("state not IDLE, cannot complete bind request\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    ASSERT(ctx->ring_object == NULL);

    do {
        if ((bvs->ringId.addr.domain != V4V_DOMID_NONE) &&
            (bvs->ringId.addr.domain != DOMID_INVALID_COMPAT)) {
            TraceWarning(("failure - ring ID domain must be V4V_DOMID_NONE - value: 0x%x\n",
                          bvs->ringId.addr.domain));
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        robj = gh_v4v_allocate_ring(ctx->ring_length);
        if (robj == NULL) {
            TraceError(("failed to allocate the ring\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        robj->ring->id = bvs->ringId;

        // Have to grab this outside of lock at IRQL PASSIVE
        port = gh_v4v_random_port(pde);

        // Lock this section since we access the list
        KeAcquireInStackQueuedSpinLock(&pde->ring_lock, &lqh);

        if (robj->ring->id.addr.port == V4V_PORT_NONE) {
            robj->ring->id.addr.port = gh_v4v_spare_port_number(pde, port);
        } else if (gh_v4v_ring_id_in_use(pde, &robj->ring->id)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            TraceWarning(("ring ID already in use, cannot bind\n"));
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

        // Now register the ring.
        status = gh_v4v_register_ring(robj);
        if (!NT_SUCCESS(status)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            TraceError(("failed in register ring hypercall - error: 0x%x\n", status));
            break;
        }
        robj->registered = TRUE;

        // Link it to the main list and set our pointer to it
        gh_v4v_link_to_ring_list(pde, robj);
        ctx->ring_object = robj;

        KeReleaseInStackQueuedSpinLock(&lqh);

        check_resume();

        InterlockedExchange(&ctx->state, XENV4V_STATE_BOUND);
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        // If it failed, undo everything - this will remove it from the list
        if (ctx->ring_object != NULL) {
            gh_v4v_release_ring(pde, ctx->ring_object);
        }
    }

    return status;
}

static NTSTATUS
gh_v4v_ctrl_initialize_file(xenv4v_context_t *ctx, v4v_init_values_t *invs, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (ctx == NULL) {
        TraceError(("no file context!\n"));
        return STATUS_INVALID_HANDLE;
    }

    if (invs->rx_event == NULL) {
        TraceError(("no event handle!\n"));
        return STATUS_INVALID_HANDLE;
    }

    do {
        // Reference the event objects
        status = ObReferenceObjectByHandle(invs->rx_event,
                                           EVENT_MODIFY_STATE,
                                           *ExEventObjectType,
                                           irp->RequestorMode,
                                           (void **)&ctx->receive_event,
                                           NULL);

        if (!NT_SUCCESS(status)) {
            TraceError(("failed to get a reference to the receive event - error: 0x%x\n", status));
            break;
        }

        ctx->ring_length = invs->ring_length;

        // Straighten out the ring
        if (ctx->ring_length > PAGE_SIZE) {
            ctx->ring_length = (ctx->ring_length + xenv4v_ring_t_MULT - 1) & ~(xenv4v_ring_t_MULT - 1);
        } else {
            ctx->ring_length = PAGE_SIZE; // minimum to guarantee page alignment
        }

        InterlockedExchange(&ctx->state, XENV4V_STATE_IDLE);
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        // If it failed, undo everything
        if (ctx->receive_event != NULL) {
            ObDereferenceObject(ctx->receive_event);
            ctx->receive_event = NULL;
        }
    }

    return status;
}

NTSTATUS NTAPI
gh_v4v_dispatch_device_control(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  isl;
    ULONG               io_control_code;
    PVOID               io_buffer;
    ULONG               io_in_len;
    ULONG               io_out_len;
    xenv4v_extension_t   *pde = v4v_get_device_extension(fdo);
    xenv4v_context_t     *ctx;
    LONG                ds;

    // TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    isl           = IoGetCurrentIrpStackLocation(irp);
    io_control_code = isl->Parameters.DeviceIoControl.IoControlCode;
    io_buffer      = irp->AssociatedIrp.SystemBuffer;
    io_in_len       = isl->Parameters.DeviceIoControl.InputBufferLength;
    io_out_len      = isl->Parameters.DeviceIoControl.OutputBufferLength;
    ctx           = (xenv4v_context_t *)isl->FileObject->FsContext;

    // TraceVerbose((" =IOCTL= 0x%x\n", io_control_code));

    irp->IoStatus.Information = 0;

    ds = InterlockedExchangeAdd(&pde->state, 0);
    if (ds & XENV4V_DEV_STOPPED) {
        TraceVerbose(("aborting IOCTL IRP, device is in the stopped state.\n"));
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_STATE;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
        return STATUS_INVALID_DEVICE_STATE;
    }

    switch (io_control_code) {
#if defined(_WIN64)
        case V4V_IOCTL_INITIALIZE_32: {
                v4v_init_values_32_t *invs32 = (v4v_init_values_32_t *)io_buffer;
                if (io_in_len == sizeof(v4v_init_values_32_t)) {
                    v4v_init_values_t init;
                    init.rx_event = invs32->rx_event;
                    init.ring_length = invs32->ring_length;
                    status = gh_v4v_ctrl_initialize_file(ctx, &init, irp);
                } else {
                    TraceError(("invalid initialization values.\n"));
                    status = STATUS_INVALID_PARAMETER;
                }

                break;
            }
#endif
        case V4V_IOCTL_INITIALIZE: {
                v4v_init_values_t *invs = (v4v_init_values_t *)io_buffer;
                if (io_in_len == sizeof(v4v_init_values_t)) {
                    status = gh_v4v_ctrl_initialize_file(ctx, invs, irp);
                } else {
                    TraceError(("invalid initialization values.\n"));
                    status = STATUS_INVALID_PARAMETER;
                }

                break;
            }
        case V4V_IOCTL_BIND: {
                v4v_bind_values_t *bvs = (v4v_bind_values_t *)io_buffer;
                if (io_in_len == sizeof(v4v_bind_values_t)) {
                    status = gh_v4v_ctrl_bind(pde, ctx, bvs);
                } else {
                    TraceError(("invalid bind values.\n"));
                    status = STATUS_INVALID_PARAMETER;
                }

                break;
            }
        case V4V_IOCTL_GETINFO: {
                v4v_getinfo_values_t *gi = (v4v_getinfo_values_t *)io_buffer;
                if (io_in_len == sizeof(v4v_getinfo_values_t)) {
                    status = gh_v4v_ctrl_get_info(ctx, gi);
                } else {
                    TraceError(("invalid get info values.\n"));
                    status = STATUS_INVALID_PARAMETER;
                }

                if (NT_SUCCESS(status))
                    irp->IoStatus.Information = sizeof(v4v_getinfo_values_t);

                break;
            }
        case V4V_IOCTL_DUMPRING: {
                status = gh_v4v_ctrl_dump_ring(ctx);
                break;
            }
        case V4V_IOCTL_NOTIFY: {
                gh_v4v_process_notify(pde);
                status = STATUS_SUCCESS;
                break;
            }
        case V4V_IOCTL_MAPRING: { //XXX: fix WoW thunking
                v4v_mapring_values_t *mr = (v4v_mapring_values_t *)io_buffer;
                if (io_in_len == sizeof(v4v_mapring_values_t)) {
                    status = uxen_v4v_mapring(ctx->ring_object, mr);
                } else {
                    TraceError(("invalid mapring struct.\n"));
                    status = STATUS_INVALID_PARAMETER;
                }
                if (NT_SUCCESS(status))
                    irp->IoStatus.Information = sizeof(v4v_mapring_values_t);
                break;
            }
#if 0
        case V4V_IOCTL_POKE: {
                v4v_poke_values_t *p = (v4v_poke_values_t *)io_buffer;
                if (io_in_len == sizeof(v4v_poke_values_t)) {
                    status = uxen_v4v_poke(&p->dst);
                } else {
                    TraceError(("invalid poke struct.\n"));
                    status = STATUS_INVALID_PARAMETER;
                }
                if (NT_SUCCESS(status))
                    irp->IoStatus.Information = sizeof(v4v_poke_values_t);

                break;
            }
        case V4V_IOCTL_DEBUG: //XXX: fix WoW thunking
            gh_v4v_debug();
            status = STATUS_SUCCESS;
            break;
#endif

        default:
            status = STATUS_INVALID_PARAMETER;
    }

    if (status != STATUS_PENDING) {
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    // TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}
