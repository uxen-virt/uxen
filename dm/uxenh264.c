/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/dm.h>
#include <dm/vm.h>
#include <dm/dev.h>
#include "console.h"

#include "uxenh264.h"

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>
#include <uxenh264-common.h>

typedef DWORD (WINAPI *thread_run_type)(PVOID opaque);

static HMODULE module;
static struct uxenh264_dm_ctx ctx[UXENH264_DM_MAX_DEC];

void
uxenh264_start(void)
{
    LPTHREAD_START_ROUTINE thread_run = NULL;
    int ctx_idx = 0;

    if (module == NULL) {
        module = LoadLibraryA("uxenh264.dll");
        if (module == NULL) {
            debug_printf("failed to load uxenh264.dll library\n");
            return;
        }
    }

    thread_run = (LPTHREAD_START_ROUTINE)GetProcAddress(module, "uxenh264_thread_run");
    if (thread_run == NULL) {
        debug_printf("failed to get thread_run address from uxenh264.dll\n");
        return;
    }

    for (ctx_idx = 0; ctx_idx < UXENH264_DM_MAX_DEC; ++ctx_idx) {
        struct uxenh264_dm_ctx *c = &ctx[ctx_idx];

        c->debug_pfn = debug_printf;

        c->exit = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (ctx->exit == NULL) {
            debug_printf("failed to create exit event\n");
            return;
        }

        memcpy(c->v4v_idtoken, v4v_idtoken, ARRAYSIZE(v4v_idtoken));

        if (create_thread(&c->thread, thread_run, c) < 0) {
            debug_printf("failed to create thread");
            return;
        }
    }

    debug_printf("uxenh264 started\n");
}

void
uxenh264_stop(void)
{
    int ctx_idx = 0;
    for (ctx_idx = 0; ctx_idx < UXENH264_DM_MAX_DEC; ++ctx_idx) {
        struct uxenh264_dm_ctx *c = &ctx[ctx_idx];
        SetEvent(c->exit);
        wait_thread(c->thread);
        close_thread_handle(c->thread);
        CloseHandle(c->exit);
        memset(c, 0, sizeof (*c));
    }
    debug_printf("uxenh264 stopped\n");
}

