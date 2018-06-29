/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef V4VPROXY_LIB_H_

/* driver exports */

#ifdef XENV4V_DRIVER
#define PROXY_DLL_DECL PROXY_DLL_EXPORT
#else
#define PROXY_DLL_DECL DECLSPEC_IMPORT
#endif

typedef void (*uxen_v4vproxy_logger_t)(int lvl, const char *);

PROXY_DLL_DECL void uxen_v4vproxy_init_driver_hook(PDRIVER_OBJECT);
PROXY_DLL_DECL void uxen_v4vproxy_free_driver_unhook(void);
PROXY_DLL_DECL void uxen_v4vproxy_set_logger(uxen_v4vproxy_logger_t logger);
PROXY_DLL_DECL void uxen_v4vproxy_start_device(void);

#endif

