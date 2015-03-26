/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "uxenevent.h"

int
window_event(UINT message, WPARAM wParam, LPARAM lParam)
{
    debug_log("message=%x wParam=%x lParam=%x",
              message, (int)wParam, (int)lParam);

    switch (message) {
    case WM_KILLFOCUS:
        break;
    case WM_SETFOCUS:
        break;
    default:
        return -1;
    }

    return 0;
}


