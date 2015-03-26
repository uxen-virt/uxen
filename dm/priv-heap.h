/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PRIV_HEAP_H_
#define _PRIV_HEAP_H_

#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <malloc/malloc.h>
typedef struct _malloc_zone_t* heap_t;
#else
typedef void* heap_t;
#endif

uint32_t priv_heap_create(heap_t *ph);
void priv_heap_destroy(heap_t h);
void *priv_calloc(heap_t h, size_t nmemb, size_t size);
void *priv_malloc(heap_t h, size_t nmemb);
void *priv_realloc(heap_t h, void *ptr, size_t size);
void priv_free(heap_t h, void *ptr);
char *priv_strdup(heap_t h, const char *s);
char *priv_strndup(heap_t h, const char *s, size_t n);

#endif
