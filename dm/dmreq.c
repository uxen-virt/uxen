/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdint.h>

#include "dm.h"
#include "dmreq.h"
#include "uxen.h"
#include "vm-save.h"

#include <xenctrl.h>
#include <xen/hvm/dmreq.h>

struct dmreq_event {
    uxen_notification_event signal;
    uxen_user_notification_event completed;
};

struct dmreq_state {
    union {
        void *page;
        struct dmreq_page *dmreq;
    };
    struct dmreq_event *events;
    uint8_t *vcpu_pages;
};

static struct dmreq_state dmreq_state;

static uxen_thread dmreq_thread = NULL;
static int dmreq_thread_exit = 0;
#define DEFAULT_TIMEOUT_MS 100000

static WaitObjects dmreq_wait_objects;
static ioh_event dmreq_exit_event;

static void
dmreq_handle(void *arg)
{
    int vcpu = (int)(intptr_t)arg;
    struct dmreq *dmreq;
    uint32_t dmreq_gpfn;
    uint8_t dmreq_gpfn_access;
#define ID_SIZE 5
    char id[ID_SIZE + 1] = { };
    int ret;

    if (vcpu == vm_vcpus) {
        dmreq = &dmreq_state.dmreq->dmreq_dom0;
        strncat(id, "dom0", ID_SIZE);
    } else {
        dmreq = &dmreq_state.dmreq->dmreq_vcpu[vcpu];
        strncat(id, "vcpu0", ID_SIZE);
        id[4] += vcpu;
    }
    /* dprintf("%s: %s dmreq lazy load pfn %x\n", __FUNCTION__, id, */
    /*         dmreq->dmreq_gpfn); */

    if (dmreq_gpfn_valid(dmreq->dmreq_gpfn_loaded))
        dmreq->dmreq_gpfn_loaded = DMREQ_GPFN_INVALID;

    dmreq_gpfn_access = dmreq->dmreq_gpfn_access;
    dmreq_gpfn = dmreq->dmreq_gpfn;
    if (!dmreq_gpfn_valid(dmreq_gpfn))
        return;

    ret = vm_lazy_load_page(dmreq_gpfn,
                            dmreq_state.vcpu_pages + (vcpu << UXEN_PAGE_SHIFT),
                            dmreq_gpfn_access ==
                            DMREQ_GPFN_ACCESS_WRITE ? 1 : 0);
    if (ret < 0)
        warnx("%s: %s dmreq lazy load pfn %x failed", __FUNCTION__, id,
              dmreq->dmreq_gpfn);
    xen_wmb();

    if (ret >= 0) {
        dmreq->dmreq_gpfn_size = ret;
        dmreq->dmreq_gpfn_loaded = dmreq->dmreq_gpfn;
    } else
        dmreq->dmreq_gpfn_loaded = DMREQ_GPFN_ERROR;

    uxen_user_notification_event_set(&dmreq_state.events[vcpu].completed);
}

#ifdef _WIN32
static DWORD WINAPI
dmreq_thread_func(LPVOID arg)
#else
static void *
dmreq_thread_func(void *arg)
#endif
{
    int timeout, wait_time;

    for (;;) {
        if (dmreq_thread_exit)
            break;
        timeout = DEFAULT_TIMEOUT_MS;
        ioh_wait_for_objects(NULL, &dmreq_wait_objects, NULL, &timeout,
                             &wait_time);
    }

    return 0;
}

void
dmreq_init(void)
{
    xen_pfn_t pfn;
    int i;
    int ret;

    ioh_init_wait_objects(&dmreq_wait_objects);

    ret = xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_DMREQ_PFN, &pfn);
    if (ret)
        err(1, "xc_get_hvm_param(HVM_PARAM_DMREQ_PFN) failed");

    dmreq_state.page = xc_map_foreign_range(xc_handle, vm_id, XC_PAGE_SIZE,
                                            PROT_READ|PROT_WRITE, pfn);
    if (!dmreq_state.page)
        err(1, "map dmreq page failed");

    dprintf("dmreq page at pfn %"PRIx64" mapped at %p\n", pfn,
            dmreq_state.page);

    dmreq_state.events = calloc(vm_vcpus + 1, sizeof(*dmreq_state.events));
    if (dmreq_state.events == NULL)
	err(1, "calloc");

    for (i = 0; i < vm_vcpus + 1; i++) {
        uxen_notification_event_init(&dmreq_state.events[i].signal);
        uxen_notification_add_wait_object(&dmreq_state.events[i].signal,
                                          dmreq_handle, (void *)(intptr_t)i,
                                          &dmreq_wait_objects);
        uxen_user_notification_event_init(&dmreq_state.events[i].completed);

        if (i < vm_vcpus) {
            dprintf("dmreq_vcpu%d %p eport %d\n", i,
                    &dmreq_state.dmreq->dmreq_vcpu[i],
                    dmreq_state.dmreq->dmreq_vcpu[i].vp_eport);
            ret = uxen_setup_event_channel(
                i, dmreq_state.dmreq->dmreq_vcpu[i].vp_eport,
                &dmreq_state.events[i].signal,
                &dmreq_state.events[i].completed);
        } else {
            dprintf("dmreq_dom0 %p eport %d\n",
                    &dmreq_state.dmreq->dmreq_dom0,
                    dmreq_state.dmreq->dmreq_dom0.vp_eport);
            ret = uxen_setup_event_channel(
                i, dmreq_state.dmreq->dmreq_dom0.vp_eport,
                &dmreq_state.events[i].signal,
                &dmreq_state.events[i].completed);
        }
	if (ret)
            errx(1, "uxen_setup_event_channel dmreq");
    }

    ret = xc_get_hvm_param(xc_handle, vm_id, HVM_PARAM_DMREQ_VCPU_PFN, &pfn);
    if (ret)
        err(1, "xc_get_hvm_param(HVM_PARAM_DMREQ_VCPU_PFN) failed");

    dmreq_state.vcpu_pages =
        xc_map_foreign_range(xc_handle, vm_id, (vm_vcpus + 1) * XC_PAGE_SIZE,
                             PROT_READ|PROT_WRITE, pfn);
    if (!dmreq_state.vcpu_pages)
        err(1, "map dmreq vcpu pages failed");

    dprintf("dmreq vcpu pages at pfn %"PRIx64" mapped at %p\n", pfn,
            dmreq_state.vcpu_pages);

    ioh_event_init(&dmreq_exit_event);
    ioh_add_wait_object(&dmreq_exit_event, NULL, NULL, &dmreq_wait_objects);

    ret = create_thread(&dmreq_thread, dmreq_thread_func, NULL);
    if (ret < 0)
        err(1, "create_thread(dmreq_thread) failed");
}

void
dmreq_exit(void)
{

    if (!dmreq_thread)
        return;

    dmreq_thread_exit = 1;
    ioh_event_set(&dmreq_exit_event);

    wait_thread(dmreq_thread);
    close_thread_handle(dmreq_thread);
    dmreq_thread = NULL;
}
