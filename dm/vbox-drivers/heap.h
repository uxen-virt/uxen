/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _HGCM_HEAP_H_
#define _HGCM_HEAP_H_

#include <dm/priv-heap.h>

extern heap_t hgcm_heap;

#define hgcm_malloc(sz) priv_malloc(hgcm_heap, sz)
#define hgcm_calloc(n, sz) priv_calloc(hgcm_heap, n, sz)
#define hgcm_realloc(p, sz) priv_realloc(hgcm_heap, p, sz)
#define hgcm_free(p) priv_free(hgcm_heap, p)
#define hgcm_strdup(s) priv_strdup(hgcm_heap, s)

#endif
