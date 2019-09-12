/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_PLATFORM_ATTOVM_H_
#define _UXEN_PLATFORM_ATTOVM_H_

int attovm_platform_init(struct bus_type *uxen_bus);
void attovm_platform_exit(void);

#endif

