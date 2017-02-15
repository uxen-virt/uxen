/*
 * Copyright 2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef PROCESS_H_
#define PROCESS_H_

#include <windows.h>

DWORD find_pid(const char *name);
DWORD suspend_pid(DWORD pid);
DWORD resume_pid(DWORD pid);

#endif
