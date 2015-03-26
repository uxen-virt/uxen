/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

#define EAGAIN      11  /* Try again */

#define EAGAIN      11  /* Try again */

V4V_DLL_EXPORT int uxen_v4v_ring_create(v4v_addr_t *dst, domid_t partner)
{
    int ret;
    struct v4v_ring_id id;

    check_resume();

    id.addr.port = dst->port;
    id.addr.domain = dst->domain;
    id.partner = partner;

    ret = (int) uxen_v4v_hypercall6 ((void *)V4VOP_create_ring, (void *) &id, (void *) 0, (void *) 0, (void *) 0, (void *) 0);

    if (ret != 0) {
        TraceError(("create destinatino ring failed - hypercall ret: %d\n", ret));
        return ret;
    }

    return 0;
}

V4V_DLL_EXPORT uxen_v4v_ring_handle_t *uxen_v4v_ring_bind (uint32_t local_port,
        domid_t partner_domain,
        uint32_t ring_size,
        uxen_v4v_callback_t *callback,
        void *callback_data1,  void *callback_data2)
{
    uxen_v4v_ring_handle_t *ret;
    xenv4v_extension_t *pde;
    KLOCK_QUEUE_HANDLE lqh;
    NTSTATUS status;

    uint32_t random_port;

    pde = uxen_v4v_get_pde ();
    if (!pde)
        return NULL;

    ret =
        (uxen_v4v_ring_handle_t *) ExAllocatePoolWithTag (NonPagedPool,
                sizeof
                (uxen_v4v_ring_handle_t),
                UXEN_V4V_TAG);

    if (!ret) {
        uxen_v4v_put_pde (pde);
        return NULL;
    }

    do {

        ret->ring_object = gh_v4v_allocate_ring (ring_size);
        if (!ret->ring_object)
            break;
        ret->ring = ret->ring_object->ring;


        ret->ring_object->ring->id.addr.port = local_port;
        ret->ring_object->ring->id.addr.domain = V4V_DOMID_ANY;
        ret->ring_object->ring->id.partner = partner_domain;

        ret->ring_object->direct_access = TRUE;
        ret->ring_object->callback = callback;
        ret->ring_object->callback_data1 = callback_data1;
        ret->ring_object->callback_data2 = callback_data2;

        random_port = gh_v4v_random_port (pde);

        KeAcquireInStackQueuedSpinLock (&pde->ring_lock, &lqh);

        if (ret->ring_object->ring->id.addr.port == V4V_PORT_NONE) {
            ret->ring_object->ring->id.addr.port =
                gh_v4v_spare_port_number (pde, random_port);
        } else if (gh_v4v_ring_id_in_use (pde, &ret->ring_object->ring->id)) {
            KeReleaseInStackQueuedSpinLock (&lqh);
            TraceWarning (("ring ID already in use, cannot bind\n"));
            break;
        }

        // Now register the ring, if there's no v4v yet we'll just queue this
        DbgPrint("exprr: Can make hypercall = %d\n", uxen_v4v_can_make_hypercall());
        if (uxen_v4v_can_make_hypercall()) {
            status = gh_v4v_register_ring (ret->ring_object);
            if (!NT_SUCCESS (status)) {
                KeReleaseInStackQueuedSpinLock (&lqh);
                TraceError (("failed in register ring hypercall - error: 0x%x\n",
                             status));
                break;
            }
        }
        ret->ring_object->registered = TRUE;
        ret->ring_object->uxen_ring_handle = ret;

        // Link it to the main list and set our pointer to it
        gh_v4v_link_to_ring_list (pde, ret->ring_object);

        KeReleaseInStackQueuedSpinLock (&lqh);
        check_resume();
        uxen_v4v_put_pde (pde);

        return ret;
    } while (0);

    if (ret->ring_object)
        gh_v4v_release_ring (pde, ret->ring_object);


    ExFreePoolWithTag (ret, UXEN_V4V_TAG);

    uxen_v4v_put_pde (pde);

    return NULL;
}

V4V_DLL_EXPORT void
uxen_v4v_ring_free (uxen_v4v_ring_handle_t *ring)
{
    xenv4v_extension_t *pde;
    pde = uxen_v4v_get_pde ();

    if (!pde) {
        TraceError (("Failed to free ring - v. bad"));
        /*in order to avoid total death - we'll at least tell the hypervisor and stop callsback */
        ring->ring_object->callback = NULL;
        gh_v4v_unregister_ring (ring->ring_object);
        return;
    }

    gh_v4v_release_ring (pde, ring->ring_object);

    uxen_v4v_put_pde (pde);

    ExFreePoolWithTag (ring, UXEN_V4V_TAG);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_send_async (v4v_addr_t *src, v4v_addr_t *dst, void *buf,
                     uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2)
{
    int ret;

    check_resume();

    ret =
        (int) uxen_v4v_hypercall6 ((void *) V4VOP_send, (void *) src,
                                   (void *) dst, (void *) buf, (void *) len,
                                   (void *) protocol);

    if ((ret == -EAGAIN) && callback)  uxen_v4v_notify_enqueue(len, dst, callback, callback_data1, callback_data2);

    return ret;
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_sendv_async (v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov,
                      uint32_t niov, uint32_t protocol,
                      uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2)
{
    int ret;
    uint64_t len;

    check_resume();

    ret =
        (int) uxen_v4v_hypercall6 ((void *) V4VOP_sendv, (void *) src,
                                   (void *) dst, (void *) iov, (void *) niov,
                                   (void *) protocol);

    if ((ret == -EAGAIN) && callback) {
        len = 0;
        while (niov--) len += (iov++)->iov_len;
        uxen_v4v_notify_enqueue((uint32_t) len, dst, callback, callback_data1, callback_data2);
    }

    return ret;
}

V4V_DLL_EXPORT BOOLEAN uxen_v4v_cancel_async(v4v_addr_t *dst, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2)
{
    return uxen_v4v_notify_dequeue(dst, callback, callback_data1, callback_data2);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_send (v4v_addr_t *src, v4v_addr_t *dst, void *buf,
               uint32_t len, uint32_t protocol)
{
    return uxen_v4v_send_async(src, dst, buf, len, protocol, NULL, NULL, NULL);
}

V4V_DLL_EXPORT ssize_t
uxen_v4v_sendv (v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov,
                uint32_t niov, uint32_t protocol)
{
    return uxen_v4v_sendv_async(src, dst, iov, niov, protocol, NULL, NULL, NULL);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_send_from_ring (uxen_v4v_ring_handle_t *
                         ring, v4v_addr_t *dst,
                         void *buf, uint32_t len, uint32_t protocol)
{
    return uxen_v4v_send_async (&ring->ring_object->ring->id.addr, dst, buf, len,
                                protocol, NULL, NULL, NULL);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_send_from_ring_async (uxen_v4v_ring_handle_t *
                               ring, v4v_addr_t *dst,
                               void *buf, uint32_t len, uint32_t protocol,
                               uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2)
{
    return uxen_v4v_send_async (&ring->ring_object->ring->id.addr, dst, buf, len,
                                protocol, callback, callback_data1, callback_data2);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_sendv_from_ring (uxen_v4v_ring_handle_t *
                          ring, v4v_addr_t *dst,
                          v4v_iov_t *iov, uint32_t niov, uint32_t protocol)
{
    return uxen_v4v_sendv_async (&ring->ring_object->ring->id.addr, dst, iov, niov,
                                 protocol, NULL, NULL, NULL);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_sendv_from_ring_async (uxen_v4v_ring_handle_t *
                                ring, v4v_addr_t *dst,
                                v4v_iov_t *iov, uint32_t niov, uint32_t protocol,
                                uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2)

{
    return uxen_v4v_sendv_async (&ring->ring_object->ring->id.addr, dst, iov, niov,
                                 protocol, callback, callback_data1, callback_data2);
}


V4V_DLL_EXPORT ssize_t
uxen_v4v_recv (uxen_v4v_ring_handle_t *ring, v4v_addr_t *from, void *buf,
               int buflen, uint32_t *protocol)
{
    ssize_t ret;

    ret =
        v4v_copy_out (ring->ring_object->ring, from, protocol, buf, buflen, 1);

    return ret;
}


V4V_DLL_EXPORT void
uxen_v4v_test (void)
{
    DbgPrint ("uxen_v4v_test()\n");
    uxen_v4v_hypercall6 ((void *) V4VOP_test, (void *) 0x1, (void *) 0x2,
                         (void *) 0x3, (void *) 0x4, (void *) 0x5);
}



V4V_DLL_EXPORT ssize_t
uxen_v4v_poke (v4v_addr_t *dst)
{
    ssize_t ret;

    check_resume();

    ret =
        (int) uxen_v4v_hypercall6 ((void *) V4VOP_poke, (void *) dst,  (void *) 0,
                                   (void *)0, (void *)0, (void *)0);

    return ret;
}


V4V_DLL_EXPORT void
uxen_v4v_notify (void /*hmm */ )
{
    xenv4v_extension_t *pde;
    pde = uxen_v4v_get_pde ();

    if (!pde)
        return;

    gh_v4v_process_notify (pde);

    uxen_v4v_put_pde (pde);

}

V4V_DLL_EXPORT
void uxen_v4vlib_set_resume_dpc(KDPC *dpc, void *arg1)
{
    unsigned i;
    KLOCK_QUEUE_HANDLE lqh;
    KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);

    for (i = 0; i < UXEN_V4VLIB_MAX_RESUME_DPCS; ++i) {
        if (!uxen_v4vlib_resume_dpcs[i]) {
            uxen_v4vlib_resume_dpcs[i] = dpc;
            uxen_v4vlib_resume_dpcs_arg1[i] = arg1;
            KeReleaseInStackQueuedSpinLock (&lqh);
            return;
        }
    }
    KeReleaseInStackQueuedSpinLock (&lqh);

    TraceWarning(("UXEN_V4VLIB_MAX_RESUME_DPCS set too low, skiping notification\n"));
}

V4V_DLL_EXPORT
void uxen_v4vlib_unset_resume_dpc(KDPC *dpc, void *arg1)
{
    unsigned i;
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);

    for (i = 0; i < UXEN_V4VLIB_MAX_RESUME_DPCS; ++i) {
        if ((uxen_v4vlib_resume_dpcs[i] == dpc) && (uxen_v4vlib_resume_dpcs_arg1[i] == arg1)) {
            uxen_v4vlib_resume_dpcs[i] = NULL;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock (&lqh);
}
