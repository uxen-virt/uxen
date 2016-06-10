/*
 * Copyright 2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __V4VALLOC_H__
#define __V4VALLOC_H__

void  uxen_v4v_free_preallocation(xenv4v_extension_t *pde);
void *uxen_v4v_fast_alloc(SIZE_T nbytes);
void  uxen_v4v_fast_free(void *ptr);

#endif
