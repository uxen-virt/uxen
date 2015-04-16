/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "filecrypt.h"
#include <stdlib.h>
#include <time.h>

static uint32_t seed;

#if __x86_64__
typedef uint64_t word_t;
#else
typedef uint32_t word_t;
#endif

static int
_read(HANDLE file, void *buf, int cnt)
{
    DWORD part = 0;
    uint8_t *p = (uint8_t*)buf;

    while (cnt>0) {
        if (!ReadFile(file, p, cnt, &part, NULL))
            return GetLastError();
        if (part == 0)
            return ERROR_HANDLE_EOF;
        p += part;
        cnt -= part;
    }
    return 0;
}

static int
_write(HANDLE file, void *buf, int cnt)
{
    DWORD part = 0;
    uint8_t *p = (uint8_t*)buf;

    while (cnt>0) {
        if (!WriteFile(file, p, cnt, &part, NULL))
            return GetLastError();
        if (part == 0)
            return ERROR_WRITE_FAULT;
        p += part;
        cnt -= part;
    }
    return 0;
}

static int
_pad(HANDLE file, int sz)
{
    uint8_t *buf;
    int ret;

    if (sz <= 0)
        return 0;
    buf = calloc(1, sz);
    if (!buf)
        return ERROR_NOT_ENOUGH_MEMORY;
    ret = _write(file, buf, sz);
    free(buf);
    return ret;
}

void FILECRYPT_API
fc_init(void)
{
    seed = (uint32_t)(time(NULL) * 987654);
}

static uint32_t
random(uint32_t *seed)
{
    *seed = 1103515245 * *seed + 12345;
    return *seed;
}

static void
extend_key(filecrypt_hdr_t *h)
{
    int i;

    for (i = 0; i < h->keylen; ++i)
        h->key[i + h->keylen] = h->key[i];
}

filecrypt_hdr_t* FILECRYPT_API
fc_init_hdr(void)
{
    int i;
    filecrypt_hdr_t *h;

    h = calloc(1, sizeof(*h));
    if (!h)
        return NULL;
    memset(h, 0, sizeof(*h));
    h->magic = FILECRYPT_MAGIC;
    h->crypttype = CRYPT_TRIVIAL;
    h->keylen = FILECRYPT_KEYBYTES;
    for (i = 0; i < h->keylen; ++i) {
        h->key[i] = 1 + random(&seed) % 255;
    }
    extend_key(h);
    h->hdrversion = 0;
    h->hdrlen = FILECRYPT_HDR_PAD;

    return h;
}

void FILECRYPT_API
fc_free_hdr(filecrypt_hdr_t *h)
{
    free(h);
}

int FILECRYPT_API
fc_read_hdr(HANDLE file, int *iscrypt, filecrypt_hdr_t **_h)
{
    uint64_t magic;
    uint32_t hdrversion, hdrlen;
    filecrypt_hdr_t *h;
    int rc = 0;

    if (_h)
        *_h = NULL;
    *iscrypt = 0;

    if (SetFilePointer(file, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return GetLastError();
    if ((rc = _read(file, &magic, 8)))
        return rc;
    if (magic != FILECRYPT_MAGIC)
        return ERROR_INVALID_DATA;
    *iscrypt = 1;
    if ((rc = _read(file, &hdrversion, 4)))
        return rc;
    if ((rc = _read(file, &hdrlen, 4)))
        return rc;
    if (hdrlen > 4096)
        return ERROR_BUFFER_OVERFLOW;
    if (hdrlen < 16)
        return ERROR_INVALID_DATA;
    h = calloc(1, hdrlen);
    if (!h)
        return ERROR_NOT_ENOUGH_MEMORY;
    h->magic = magic;
    h->hdrversion = hdrversion;
    h->hdrlen = hdrlen;
    if ((rc = _read(file, ((uint8_t*)h) + 16, h->hdrlen-16)))
        return rc;
    if (h->keylen != FILECRYPT_KEYBYTES)
        return ERROR_INVALID_DATA;
    extend_key(h);
    if (_h)
        *_h = h;
    else
        free(h);

    return 0;
}

int FILECRYPT_API
fc_write_hdr(HANDLE file, filecrypt_hdr_t *h)
{
    int rc = 0;

    if (SetFilePointer(file, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return ERROR_WRITE_FAULT;
    if (h->hdrlen > 4096)
        return ERROR_BUFFER_OVERFLOW;
    if ((rc = _write(file, h, sizeof(*h))))
        return rc;
    if ((rc = _pad(file, FILECRYPT_HDR_PAD - sizeof(*h))))
        return rc;
    return 0;
}

static void
_crypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len)
{
    uint32_t keylen = h->keylen;
    uint32_t keyoff = (uint32_t)(off & (keylen-1));
    word_t *key = (word_t*)&h->key[keyoff];
    word_t *p = buf;
    word_t *pk, *pkend;
    uint32_t n = len / keylen;
    uint32_t rwords = (len % keylen) / sizeof(word_t);
    uint32_t r8  = (len % keylen) % sizeof(word_t);

    while (n--) {
        pk = key;
        pkend = key + (keylen / sizeof(word_t));
        while (pk != pkend)
            *p++ ^= *pk++;
    }

    pk = key;
    while (rwords--)
        *p++ ^= *pk++;

    if (r8) {
        uint8_t *p8 = (uint8_t *)p;
        uint8_t *pk8 = (uint8_t *)pk;
        while (r8--)
            *p8++ ^= *pk8++;
    }
}

void FILECRYPT_API
fc_crypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len)
{
    _crypt(h, buf, off, len);
}

void FILECRYPT_API
fc_decrypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len)
{
    _crypt(h, buf, off, len);
}

BOOL FILECRYPT_API
fc_read(filecrypt_hdr_t *h, HANDLE f, void *buffer, DWORD sz, DWORD *num_read)
{
    LARGE_INTEGER d, p;
    BOOL rv;

    d.QuadPart = 0;
    SetFilePointerEx(f, d, &p, FILE_CURRENT);
    if (p.QuadPart < h->hdrlen) {
        SetLastError(ERROR_NEGATIVE_SEEK);
        return FALSE;
    }
    rv = ReadFile(f, buffer, sz, num_read, NULL);
    if (rv)
        fc_decrypt(h, buffer, p.QuadPart - h->hdrlen, *num_read);
    return rv;
}

BOOL FILECRYPT_API
fc_write(filecrypt_hdr_t *h, HANDLE f, void *buffer, DWORD sz, DWORD *num_written)
{
    LARGE_INTEGER d, p;
    BOOL rv;

    d.QuadPart = 0;
    SetFilePointerEx(f, d, &p, FILE_CURRENT);
    if (p.QuadPart < h->hdrlen) {
        SetLastError(ERROR_NEGATIVE_SEEK);
        return FALSE;
    }
    fc_crypt(h, buffer, p.QuadPart - h->hdrlen, sz);
    rv = WriteFile(f, buffer, sz, num_written, NULL);
    return rv;
}
