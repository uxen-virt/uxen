/*
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>

#if !defined(LIBIMG)
#define DEBUG_EARLYINIT
#endif

#ifdef DEBUG_EARLYINIT
#define EARLYINIT_LOG(x) debug_printf(x)
#else
#define EARLYINIT_LOG(x)
#endif

void os_early_init(void);
void early_init_async_op(void);
void early_init_swap(void);
void early_init_clock(void);
void early_init_console(void);
void early_init_wasapi(void);
void early_init_ns_echo(void);
void early_init_ns_fwd(void);
void early_init_ns_logging(void);
void early_init_ns_webdav(void);
void early_init_nickel(void);
void early_init_win32_logging(void);
void early_init_vbox_rt(void);
void early_init_console_win32(void);
void early_init_console_osx(void);
void early_init_console_remote(void);

#if !defined(LIBIMG)
void
early_init(void)
{
#if defined(_WIN32)
    early_init_win32_logging();
#endif

    EARLYINIT_LOG("early init os..\n");
    os_early_init();

    EARLYINIT_LOG("early init async op..\n");
    early_init_async_op();
    EARLYINIT_LOG("early init ns echo..\n");
    early_init_ns_echo();
    EARLYINIT_LOG("early init ns fwd..\n");
    early_init_ns_fwd();
    EARLYINIT_LOG("early init ns logging..\n");
    early_init_ns_logging();
#if defined(CONFIG_WEBDAV)
    EARLYINIT_LOG("early init ns webdav..\n");
    early_init_ns_webdav();
#endif
#if defined(CONFIG_NICKEL)
    EARLYINIT_LOG("early init nickel..\n");
    early_init_nickel();
#endif
    EARLYINIT_LOG("early init swap..\n");
    early_init_swap();
    EARLYINIT_LOG("early init clock..\n");
    early_init_clock();
#if defined(_WIN32)
    EARLYINIT_LOG("early init console win32..\n");
    early_init_console_win32();
#endif
#if defined(__APPLE__)
    EARLYINIT_LOG("early init console osx..\n");
    early_init_console_osx();
#endif
    EARLYINIT_LOG("early init console remote..\n");
    early_init_console_remote();
    EARLYINIT_LOG("early init console..\n");
    early_init_console();
#if defined(_WIN32)
    EARLYINIT_LOG("early init wasapi..\n");
    early_init_wasapi();
#endif
#if defined(CONFIG_VBOXDRV)
    EARLYINIT_LOG("early init vbox rt..\n");
    early_init_vbox_rt();
#endif
}

#else /* when LIBIMG */

void early_init(void)
{
    os_early_init();
    early_init_clock();
}

#endif
