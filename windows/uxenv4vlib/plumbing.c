/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

static DRIVER_OBJECT *driver_object; // This isn't shared, only the original caller should use this

V4V_DLL_EXPORT void uxen_v4vlib_set_state_bar_ptr(struct uxp_state_bar **a)
{
    DbgPrint("uxen_v4v_set_state_bar_ptr to %p\n", a);
    state_bar_ptr = a;
}

V4V_DLL_EXPORT void uxen_v4vlib_set_hypercall_func(uxen_v4vlib_hypercall_func_t *func)
{
    DbgPrint("uxen_v4v_set_hypercall_func setting func to %p\n", func);
    hypercall_6_func = func;
    check_resume();
}


V4V_DLL_EXPORT void uxen_v4vlib_set_page_notify_func(uxen_v4vlib_page_notify_func_t *func)
{
    DbgPrint("uxen_v4v_set_page_notify_func setting func to %p\n", func);


    page_notify_func = func;
}

V4V_DLL_EXPORT void uxen_v4vlib_we_are_dom0(void)
{
    uxen_v4v_am_dom0++;
}

V4V_DLL_EXPORT void uxen_v4vlib_deliver_signal (void )
{
    gh_signaled();
}

V4V_DLL_EXPORT void uxen_v4vlib_set_logger(uxen_v4v_logger_t logger)
{
    uxen_v4v_logger = logger;
}

V4V_DLL_EXPORT void uxen_v4vlib_free_driver(void )
{
    if (!driver_object) return;

    DbgPrint("uxen_v4v_free_driver\n");
    gh_destroy_device(driver_object);

    driver_object = NULL;
}

V4V_DLL_EXPORT void uxen_v4vlib_init_driver(PDRIVER_OBJECT pdo)
{
    DbgPrint("uxen_v4v_init_driver\n");
    if (driver_object) return;
    driver_object = pdo;

    gh_create_device(driver_object);
}

uintptr_t v4v_call_page_notify(v4v_pfn_t *pfn, uint32_t npfn, int map)
{
    return page_notify_func ? page_notify_func(pfn, npfn, map) : 0;
}
