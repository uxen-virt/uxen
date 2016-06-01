/*
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#ifndef LIBIMG

initcall(backtrace_init)
{
    if (!LoadLibraryA("uxen-backtrace.dll"))
        Wwarn("LoadLibraryA(uxen-backtrace.dll) failed");
}

#endif
