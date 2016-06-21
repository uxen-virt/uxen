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
 * Copyright 2015-2016, Bromium, Inc.
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

#include <xen/errno.h>

static __declspec(inline) int
gh_v4v_hypercall(unsigned int cmd, void *arg2, void *arg3, void *arg4,
                 ULONG32 arg5, ULONG32 arg6)
{

    return (int)(uintptr_t)uxen_v4v_hypercall6(
        (void *)(uintptr_t)cmd, arg2, arg3, arg4,
        (void *)(uintptr_t)arg5, (void *)(uintptr_t)arg6);
}

static NTSTATUS
gh_v4v_filter_send_errno(int err, unsigned int cmd,
                         v4v_addr_t *src, v4v_addr_t *dest)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (err < 0) {
        switch (err) {
            case -EAGAIN:
                status = STATUS_RETRY;
                break;
            case -EINVAL:
                status = STATUS_INVALID_PARAMETER;
                break;
            case -ENOMEM:
                status = STATUS_NO_MEMORY;
                break;
            case -ENOSPC:
            case -EMSGSIZE:
                status = STATUS_BUFFER_OVERFLOW;
                break;
            case -ENOSYS:
                status = STATUS_NOT_IMPLEMENTED;
                break;
            case -ECONNREFUSED:
                status = STATUS_VIRTUAL_CIRCUIT_CLOSED;
                break;
            case -EFAULT:
            default:
                uxen_v4v_err(
                    "%s data fault (vm%u:%x vm%u:x) err %d",
                    cmd == V4VOP_send ? "V4VOP_send" : "V4VOP_sendv",
                    src->domain, src->port, dest->domain, dest->port, err);
                status = STATUS_UNSUCCESSFUL;
        };
    }

    return status;
}

NTSTATUS
gh_v4v_register_ring(xenv4v_ring_t *robj)
{
    int err;

    if (v4v_call_page_notify(robj->pfn_list->pages, robj->pfn_list->npage, 1)) {
        uxen_v4v_err("v4v_call_page_notify (vm%u:%x vm%u) failed",
                     robj->ring->id.addr.domain, robj->ring->id.addr.port,
                     robj->ring->id.partner);
        return STATUS_UNSUCCESSFUL;
    }

    err = gh_v4v_hypercall(V4VOP_register_ring, robj->ring, robj->pfn_list, 0, 0, 0);

    if (err == -ENOSYS) {
        /* Special case - say it all worked and we'll sort it out later when the platform device actually loads and the resume notify fires */
        return STATUS_SUCCESS;
    }
    if (err != 0) {
        uxen_v4v_err("V4VOP_register_ring (vm%u:%x vm%u) failed err %d",
                     robj->ring->id.addr.domain, robj->ring->id.addr.port,
                     robj->ring->id.partner, err);
        return STATUS_UNSUCCESSFUL;
    }


    return STATUS_SUCCESS;
}

NTSTATUS
gh_v4v_unregister_ring(xenv4v_ring_t *robj)
{
    int err;


    err = gh_v4v_hypercall(V4VOP_unregister_ring, robj->ring, 0, 0, 0, 0);
    if (err != 0) {
        uxen_v4v_err("V4VOP_unregister_ring (vm%u:%x vm%u) failed err %d",
                     robj->ring->id.addr.domain, robj->ring->id.addr.port,
                     robj->ring->id.partner, err);
        return STATUS_UNSUCCESSFUL;
    }

    (void)v4v_call_page_notify(robj->pfn_list->pages, robj->pfn_list->npage, 0);

    return STATUS_SUCCESS;
}

NTSTATUS
gh_v4v_create_ring(v4v_addr_t *dst, domid_t partner)
{
    int err;

    struct v4v_ring_id id;

    id.addr.port = dst->port;
    id.addr.domain = dst->domain;
    id.partner = partner;

    err = gh_v4v_hypercall(V4VOP_create_ring, &id, 0, 0, 0, 0);
    if (err != 0) {
        uxen_v4v_err("V4VOP_create_ring (vm%u:%x vm%u) failed err %d",
                     id.addr.domain, id.addr.port, id.partner, err);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
gh_v4v_notify(v4v_ring_data_t *ringData)
{
    int err;

    err = gh_v4v_hypercall(V4VOP_notify, ringData, 0, 0, 0, 0);
    if (err != 0) {
        uxen_v4v_err("V4VOP_notify (nent %d) failed err %d",
                     ringData->nent, err);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
gh_v4v_debug(void)
{
    int err;

    err = gh_v4v_hypercall(V4VOP_debug, 0, 0, 0, 0, 0);
    if (err != 0) {
        uxen_v4v_err("V4VOP_debug failed err %d", err);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
gh_v4v_send(v4v_addr_t *src, v4v_addr_t *dest, ULONG32 protocol, VOID *buf, ULONG32 length, ULONG32 *writtenOut)
{
    int err;

    check_resume();

    *writtenOut = 0;

    err = gh_v4v_hypercall(V4VOP_send, src, dest, buf, length, protocol);
    if (err >= 0) {
        *writtenOut = (ULONG32)err;
    }

    return gh_v4v_filter_send_errno(err, V4VOP_send, src, dest);
}

NTSTATUS
gh_v4v_send_vec(v4v_addr_t *src, v4v_addr_t *dest, v4v_iov_t *iovec, ULONG32 nent, ULONG32 protocol, ULONG32 *writtenOut)
{
    int err;

    check_resume();

    *writtenOut = 0;

    err = gh_v4v_hypercall(V4VOP_sendv, src, dest, iovec, nent, protocol);
    if (err >= 0) {
        *writtenOut = (ULONG32)err;
    }

    return gh_v4v_filter_send_errno(err, V4VOP_sendv, src, dest);
}
