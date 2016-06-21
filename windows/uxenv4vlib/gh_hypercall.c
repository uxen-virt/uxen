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

#define EPERM        1  /* Operation not permitted */
#define ENOENT       2  /* No such file or directory */
#define ESRCH        3  /* No such process */
#define EINTR        4  /* Interrupted system call */
#define EIO          5  /* I/O error */
#define ENXIO        6  /* No such device or address */
#define E2BIG        7  /* Arg list too long */
#define ENOEXEC      8  /* Exec format error */
#define EBADF        9  /* Bad file number */
#define ECHILD      10  /* No child processes */
#define EAGAIN      11  /* Try again */
#define ENOMEM      12  /* Out of memory */
#define EACCES      13  /* Permission denied */
#define EFAULT      14  /* Bad address */
#define ENOTBLK     15  /* Block device required */
#define EBUSY       16  /* Device or resource busy */
#define EEXIST      17  /* File exists */
#define EXDEV       18  /* Cross-device link */
#define ENODEV      19  /* No such device */
#define ENOTDIR     20  /* Not a directory */
#define EISDIR      21  /* Is a directory */
#define EINVAL      22  /* Invalid argument */
#define ENFILE      23  /* File table overflow */
#define EMFILE      24  /* Too many open files */
#define ENOTTY      25  /* Not a typewriter */
#define ETXTBSY     26  /* Text file busy */
#define EFBIG       27  /* File too large */
#define ENOSPC      28  /* No space left on device */
#define ESPIPE      29  /* Illegal seek */
#define EROFS       30  /* Read-only file system */
#define EMLINK      31  /* Too many links */
#define EPIPE       32  /* Broken pipe */
#define EDOM        33  /* Math argument out of domain of func */
#define ERANGE      34  /* Math result not representable */
#define EDEADLK     35  /* Resource deadlock would occur */
#define ENAMETOOLONG    36  /* File name too long */
#define ENOLCK      37  /* No record locks available */
#define ENOSYS      38  /* Function not implemented */
#define ENOTEMPTY   39  /* Directory not empty */
#define ELOOP       40  /* Too many symbolic links encountered */
#define EWOULDBLOCK EAGAIN  /* Operation would block */
#define ENOMSG      42  /* No message of desired type */
#define EIDRM       43  /* Identifier removed */
#define ECHRNG      44  /* Channel number out of range */
#define EL2NSYNC    45  /* Level 2 not synchronized */
#define EL3HLT      46  /* Level 3 halted */
#define EL3RST      47  /* Level 3 reset */
#define ELNRNG      48  /* Link number out of range */
#define EUNATCH     49  /* Protocol driver not attached */
#define ENOCSI      50  /* No CSI structure available */
#define EL2HLT      51  /* Level 2 halted */
#define EBADE       52  /* Invalid exchange */
#define EBADR       53  /* Invalid request descriptor */
#define EXFULL      54  /* Exchange full */
#define ENOANO      55  /* No anode */
#define EBADRQC     56  /* Invalid request code */
#define EBADSLT     57  /* Invalid slot */

#define EDEADLOCK   EDEADLK

#define EBFONT      59  /* Bad font file format */
#define ENOSTR      60  /* Device not a stream */
#define ENODATA     61  /* No data available */
#define ETIME       62  /* Timer expired */
#define ENOSR       63  /* Out of streams resources */
#define ENONET      64  /* Machine is not on the network */
#define ENOPKG      65  /* Package not installed */
#define EREMOTE     66  /* Object is remote */
#define ENOLINK     67  /* Link has been severed */
#define EADV        68  /* Advertise error */
#define ESRMNT      69  /* Srmount error */
#define ECOMM       70  /* Communication error on send */
#define EPROTO      71  /* Protocol error */
#define EMULTIHOP   72  /* Multihop attempted */
#define EDOTDOT     73  /* RFS specific error */
#define EBADMSG     74  /* Not a data message */
#define EOVERFLOW   75  /* Value too large for defined data type */
#define ENOTUNIQ    76  /* Name not unique on network */
#define EBADFD      77  /* File descriptor in bad state */
#define EREMCHG     78  /* Remote address changed */
#define ELIBACC     79  /* Can not access a needed shared library */
#define ELIBBAD     80  /* Accessing a corrupted shared library */
#define ELIBSCN     81  /* .lib section in a.out corrupted */
#define ELIBMAX     82  /* Attempting to link in too many shared libraries */
#define ELIBEXEC    83  /* Cannot exec a shared library directly */
#define EILSEQ      84  /* Illegal byte sequence */
#define ERESTART    85  /* Interrupted system call should be restarted */
#define ESTRPIPE    86  /* Streams pipe error */
#define EUSERS      87  /* Too many users */
#define ENOTSOCK    88  /* Socket operation on non-socket */
#define EDESTADDRREQ    89  /* Destination address required */
#define EMSGSIZE    90  /* Message too long */
#define EPROTOTYPE  91  /* Protocol wrong type for socket */
#define ENOPROTOOPT 92  /* Protocol not available */
#define EPROTONOSUPPORT 93  /* Protocol not supported */
#define ESOCKTNOSUPPORT 94  /* Socket type not supported */
#define EOPNOTSUPP  95  /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT    96  /* Protocol family not supported */
#define EAFNOSUPPORT    97  /* Address family not supported by protocol */
#define EADDRINUSE  98  /* Address already in use */
#define EADDRNOTAVAIL   99  /* Cannot assign requested address */
#define ENETDOWN    100 /* Network is down */
#define ENETUNREACH 101 /* Network is unreachable */
#define ENETRESET   102 /* Network dropped connection because of reset */
#define ECONNABORTED    103 /* Software caused connection abort */
#define ECONNRESET  104 /* Connection reset by peer */
#define ENOBUFS     105 /* No buffer space available */
#define EISCONN     106 /* Transport endpoint is already connected */
#define ENOTCONN    107 /* Transport endpoint is not connected */
#define ESHUTDOWN   108 /* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS    109 /* Too many references: cannot splice */
#define ETIMEDOUT   110 /* Connection timed out */
#define ECONNREFUSED    111 /* Connection refused */
#define EHOSTDOWN   112 /* Host is down */
#define EHOSTUNREACH    113 /* No route to host */
#define EALREADY    114 /* Operation already in progress */
#define EINPROGRESS 115 /* Operation now in progress */
#define ESTALE      116 /* Stale NFS file handle */
#define EUCLEAN     117 /* Structure needs cleaning */
#define ENOTNAM     118 /* Not a XENIX named type file */
#define ENAVAIL     119 /* No XENIX semaphores available */
#define EISNAM      120 /* Is a named type file */
#define EREMOTEIO   121 /* Remote I/O error */
#define EDQUOT      122 /* Quota exceeded */

#define ENOMEDIUM   123 /* No medium found */
#define EMEDIUMTYPE 124 /* Wrong medium type */


static __declspec(inline) int
gh_v4v_hypercall(
    unsigned int cmd, void *arg2, void *arg3, void *arg4, ULONG32 arg5, ULONG32 arg6)
{
    void *uxen_v4v_hypercall6 (void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6);
    uintptr_t ret;
    ret = (uintptr_t) uxen_v4v_hypercall6((void *) (uintptr_t)  cmd, arg2, arg3, arg4, (void *)  (uintptr_t) arg5, (void *) (uintptr_t) arg6);

    return (int) ret;
}


static NTSTATUS
gh_v4v_filter_errno(int err)
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
            case -ENOTCONN:
            case -ECONNREFUSED:
                status = STATUS_VIRTUAL_CIRCUIT_CLOSED;
                break;
            case -EFAULT:
            default:
                uxen_v4v_err("send data fault - hypercall err: %d\n", err);
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
        uxen_v4v_err("register ring populate frametable failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    err = gh_v4v_hypercall(V4VOP_register_ring, robj->ring, robj->pfn_list, 0, 0, 0);

    if (err == -ENOSYS) {
        /* Special case - say it all worked and we'll sort it out later when the platform device actually loads and the resume notify fires */
        return STATUS_SUCCESS;
    }
    if (err != 0) {
        uxen_v4v_err("register ring failed - hypercall err: %d\n", err);
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
        uxen_v4v_err("unregister ring failed - hypercall err: %d\n", err);
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
        uxen_v4v_err("create destinatino ring failed - hypercall err: %d\n", err);
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
        uxen_v4v_err("notify ring data failed - hypercall err: %d\n", err);
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
        uxen_v4v_err("debug failed - hypercall err: %d\n", err);
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

    return gh_v4v_filter_errno(err);
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

    return gh_v4v_filter_errno(err);
}
