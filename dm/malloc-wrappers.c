/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "dm.h"

void *__real_malloc(size_t size);
void *__real_realloc(void *ptr, size_t size);
void *__real_calloc(size_t nmemb, size_t size);
void __real_free(void * ptr);

#define ALLOC_MAGIC 0xfedeabe7

typedef struct __attribute__ ((__packed__)) AllocHeader {
    uint32_t magic;
    uint32_t size;
    uint8_t bytes[0];
} AllocHeader;

volatile int64_t total_alloced = 0;

static inline
void update_malloc_stats(int64_t delta)
{
    if (__sync_add_and_fetch(&total_alloced, delta) > malloc_limit_bytes
            && delta > 0 && malloc_limit_bytes) {
        fprintf(stderr, "allocation limit=%"PRId64" reached, "
                        "trying to allocate %"PRId64" bytes.\n",
                malloc_limit_bytes, delta);
        *(uint32_t *)0 = 0;
    }
}

void *__wrap_malloc(size_t size)
{
    size_t total = sizeof(AllocHeader) + size;
    assert_always(total > size);
    AllocHeader *h = __real_malloc(total);
    assert_always(h);
    if (h) {
        h->magic = ALLOC_MAGIC;
        h->size = size;
        update_malloc_stats(size);
        return h->bytes;
    }
    return NULL;
}

void *__wrap_realloc(void *ptr, size_t size)
{
    AllocHeader *h = NULL;
    size_t total = sizeof(AllocHeader) + size;
    assert_always(total > size);
    if (ptr) {
        h = (AllocHeader *) ((uint8_t *) ptr - offsetof(AllocHeader, bytes));
        assert_always(h->magic == ALLOC_MAGIC);
        ptr = h;
        update_malloc_stats((int64_t) size - (int64_t) h->size);
    } else {
        ptr = NULL;
        update_malloc_stats(size);
    }
    h = __real_realloc(ptr, size ? total : 0);
    assert_always(!size || h);
    if (h) {
        h->magic = ALLOC_MAGIC;
        h->size = size;
        return h->bytes;
    }
    return NULL;
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    assert_always(nmemb < (1<<31));
    assert_always(size < (1<<31));
    uint64_t product = (uint64_t) nmemb * (uint64_t) size;
    size_t total = sizeof(AllocHeader) + (size_t) product;
    assert_always(total > product); /* In case size_t is 32-bit. */

    AllocHeader *h = __real_calloc(1, total);
    assert_always(h);
    if (h) {
        h->magic = ALLOC_MAGIC;
        h->size = product;
        update_malloc_stats(product);
        return h->bytes;
    }
    return NULL;
}

void __wrap_free(void * ptr)
{
    if (ptr) {
        uintptr_t p = (uintptr_t) ptr;
        assert_always(p >= sizeof(AllocHeader));
        AllocHeader *h = (AllocHeader *) ((uint8_t *) ptr - offsetof(AllocHeader, bytes));
        assert_always(h->magic == ALLOC_MAGIC);
        update_malloc_stats(- (int64_t) h->size);
        h->magic = 0;
        h->size = 0;
        __real_free(h);
    }
}

char *__wrap_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *r = __wrap_malloc(sizeof(char) * len);
    if (r)
        memcpy(r, s, len);
    return r;
}

char *__wrap_strndup(const char *s, size_t n)
{
    char *r;
    size_t len = strlen(s);
    len = n < len ? n : len;
    r = __wrap_malloc(sizeof(char) * (len + 1));
    if (r) {
        r[len] = '\0';
        memcpy(r, s, len);
    }
    return r;
}

wchar_t *__wrap_wcsdup(const wchar_t *s)
{
    size_t len = wcslen(s) + 1;
    wchar_t *r = __wrap_malloc(sizeof(wchar_t) * len);
    if (r)
        memcpy(r, s, sizeof(wchar_t) * len);
    return r;
}

wchar_t *__wrap_wcsndup(const wchar_t *s, size_t n)
{
    wchar_t *r;
    size_t len = wcslen(s);
    len = n < len ? n : len;
    r = __wrap_malloc(sizeof(wchar_t) * (len + 1));
    if (r) {
        r[len] = '\0';
        memcpy(r, s, sizeof(wchar_t) * len);
    }
    return r;
}

#ifdef _WIN32
#undef VirtualAlloc
#undef HeapAlloc
#undef HeapReAlloc

void * __wrap_VirtualAlloc(void *addr, size_t size, DWORD type, DWORD protect)
{
    void *r;
    r = VirtualAlloc(addr, size, type, protect);
    assert_always(type == MEM_RESET || r);
    return r;
}

void *__wrap_HeapAlloc(HANDLE heap, DWORD flags, size_t size)
{
    void *r;
    r = HeapAlloc(heap, flags, size);
    assert_always(r);
    return r;
}

void *__wrap_HeapReAlloc(HANDLE heap, DWORD flags, void *ptr, size_t size)
{
    void *r;
    r = HeapReAlloc(heap, flags, ptr, size);
    assert_always(r);
    return r;
}
#endif
