/*
 * Copyright 2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_SCSI_OSX_H_
#define _UXEN_SCSI_OSX_H_
#include <stddef.h>

size_t uxscsi_inquiry(void* dest, size_t max_len);

#endif
