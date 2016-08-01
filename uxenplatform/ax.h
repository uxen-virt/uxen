/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_PLATFORM_AX_H_
#define _UXEN_PLATFORM_AX_H_

struct bus_type;
int ax_platform_init(struct bus_type *uxen_bus);
void ax_platform_exit(void);
#endif
