/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef LOGGING_H_
#define LOGGING_H_

#include "msg.h"

void svc_vprintf(DWORD lvl, const wchar_t *fmt, va_list ap);
void svc_printf(DWORD lvl, const wchar_t *fmt, ...);

#endif /* LOGGING_H_ */
