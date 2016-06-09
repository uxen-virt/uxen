/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VMSAVEFILE_SIMPLE_H_
#define _VMSAVEFILE_SIMPLE_H_

#include <xc_private.h>
int
vmsavefile_save_simple(xc_interface *_xc_handle, const char *savefile,
                       uint8_t *uuid, int domid);

#endif
