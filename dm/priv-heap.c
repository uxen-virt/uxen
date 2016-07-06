/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "priv-heap.h"

#define MAX_ALLOC_LEN    ((size_t) (((size_t)(-1)) >> 1))

uint32_t priv_heap_create(heap_t *ph)
{
#if defined(_WIN32)
    *ph = HeapCreate(0, 0, 0);
    if (*ph == NULL)
        return (uint32_t) GetLastError();
#elif defined(__APPLE__)
    *ph = malloc_create_zone(4096, 0);
#else
    *ph = NULL;
#endif
    return 0;
}

void priv_heap_destroy(heap_t h)
{
#if defined(_WIN32)
    HeapDestroy(h);
#elif defined(__APPLE__)
    malloc_destroy_zone(h);
#endif
}

void *priv_calloc(heap_t h, size_t nmemb, size_t size)
{
    if (nmemb && size > MAX_ALLOC_LEN / nmemb)
        return NULL;
#if defined(_WIN32)
    if (!h)
        return NULL;
    return HeapAlloc(h, HEAP_ZERO_MEMORY, nmemb * size);
#elif defined(__APPLE__)
    if (!h)
        return NULL;
    return malloc_zone_calloc(h, nmemb, size);
#else
    return calloc(nmemb, size);
#endif
}

void *priv_malloc(heap_t h, size_t nmemb)
{
    if (nmemb > MAX_ALLOC_LEN)
        return NULL;
#if defined(_WIN32)
    if (!h)
        return NULL;
    return HeapAlloc(h, 0, nmemb);
#elif defined(__APPLE__)
    if (!h)
        return NULL;
    return malloc_zone_malloc(h, nmemb);
#else
    return malloc(nmemb);
#endif
}

void *priv_realloc(heap_t h, void *ptr, size_t size)
{
    if (size > MAX_ALLOC_LEN)
        return NULL;
#if defined(_WIN32)
    if (!h)
        return NULL;
    if (!ptr)
        return priv_calloc(h, 1, size);
    return HeapReAlloc(h, HEAP_ZERO_MEMORY, ptr, size);
#elif defined(__APPLE__)
    if (!h)
        return NULL;
    return malloc_zone_realloc(h, ptr, size);
#else
    return realloc(ptr, size);
#endif
}

void priv_free(heap_t h, void *ptr)
{
#if defined(_WIN32)
    if (!h || !ptr)
        return;
    HeapFree(h, 0, ptr);
#elif defined(__APPLE__)
    if (!h)
        return;
    malloc_zone_free(h, ptr);
#else
    free(ptr);
#endif
}

char *priv_strdup(heap_t h, const char *s)
{
#if defined(_WIN32) || defined(__APPLE__)
    char *ret = NULL;
    size_t len;

    if (!h || !s)
        return NULL;
    len = strlen(s);
    len += 1;
    ret = priv_calloc(h, 1, len);
    if (!ret)
        return NULL;
    memcpy(ret, s, len);
    return ret;
#else
    return strdup(s);
#endif
}

char *priv_strndup(heap_t h, const char *s, size_t n)
{
    char *ret = NULL;
    size_t len;

#if defined(_WIN32) || defined(__APPLE__)
    if (!h)
        return NULL;
#endif

     if (!s)
        return NULL;
    len = strlen(s);
    if (len > MAX_ALLOC_LEN || n > MAX_ALLOC_LEN)
        return NULL;
    if (len > n)
        len = n;

#if defined(_WIN32) || defined(__APPLE__)
    ret = priv_calloc(h, 1, len + 1);
#else
    ret = calloc(1, len + 1);
#endif

    if (!ret)
        return NULL;
    memcpy(ret, s, len);
    return ret;
}
