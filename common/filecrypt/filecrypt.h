/*
 * Copyright 2015-2020, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _FILECRYPT_H_
#define _FILECRYPT_H_

#include <stdint.h>
#include <windows.h>
#include <wincrypt.h>

#define FILECRYPT_MAGIC 0x454C49464653C55F
#define FILECRYPT_HDR_PAD 4096
#define FILECRYPT_KEYBITS 256
#define FILECRYPT_KEYBYTES (FILECRYPT_KEYBITS / 8)
#define CRYPT_NONE 0
#define CRYPT_TRIVIAL 1

typedef struct filecrypt_hdr {
    uint64_t magic;
    uint32_t hdrversion;
    uint32_t hdrlen;
    uint32_t crypttype;
    uint32_t keylen;
    uint8_t key[FILECRYPT_KEYBYTES*2];
} filecrypt_hdr_t;

#ifdef __cplusplus
extern "C" {
#endif

static int fc_init(void);
/* allocate header */
static filecrypt_hdr_t* fc_init_hdr(void);
/* free header */
static void fc_free_hdr(filecrypt_hdr_t *h);
/* allocate & read header. caller responsible for free */
static int fc_read_hdr(HANDLE file, int *iscrypt, filecrypt_hdr_t **hdr);
/* allocate & read header. caller responsible for free */
static int fc_path_read_hdr(wchar_t *path, int *iscrypt, filecrypt_hdr_t **hdr);
/* write header */
static int fc_write_hdr(HANDLE file, filecrypt_hdr_t *hdr);
/* encrypt buffer in-place. off = offset in file (not in the buffer) */
static void fc_crypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len);
/* decrypt buffer in-place. off = offset in file (not in the buffer) */
static void fc_decrypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len);
/* read/write and decrypt/crypt bytes from file */
static BOOL fc_read(filecrypt_hdr_t *h, HANDLE f, void *buffer, DWORD sz, DWORD *num_read);
static BOOL fc_write(filecrypt_hdr_t *h, HANDLE f, void *buffer, DWORD sz, DWORD *num_written);



/*
 * 'private' implementation follows
 */

#define FC_MAX_CR_LAYERS 1024
 
#if defined(__x86_64__) || defined(_M_X64)
typedef uint64_t fc_word_t;
#else
typedef uint32_t fc_word_t;
#endif

static inline int
_fc_read(HANDLE file, void *buf, int cnt)
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

static inline int
_fc_write(HANDLE file, void *buf, int cnt)
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

static inline int
_fc_pad(HANDLE file, int sz)
{
    uint8_t *buf;
    int ret;

    if (sz <= 0)
        return 0;
    buf = (uint8_t*) calloc(1, sz);
    if (!buf)
        return ERROR_NOT_ENOUGH_MEMORY;
    ret = _fc_write(file, buf, sz);
    free(buf);
    return ret;
}

static inline int
fc_init(void)
{
    return 0;
}

static inline void
_fc_extend_key(filecrypt_hdr_t *h)
{
    uint32_t i;

    for (i = 0; i < h->keylen; ++i)
        h->key[i + h->keylen] = h->key[i];
}

static inline filecrypt_hdr_t*
fc_init_hdr(void)
{
    static HCRYPTPROV g_filecrypt_crprov;

    uint32_t i;
    filecrypt_hdr_t *h;

    h = (filecrypt_hdr_t*) calloc(1, sizeof(*h));
    if (!h)
        return NULL;
    memset(h, 0, sizeof(*h));
    h->magic = FILECRYPT_MAGIC;
    h->crypttype = CRYPT_TRIVIAL;
    h->keylen = FILECRYPT_KEYBYTES;
    if (!g_filecrypt_crprov)
        if (!CryptAcquireContextW(&g_filecrypt_crprov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
            return NULL;
    CryptGenRandom(g_filecrypt_crprov, h->keylen, (BYTE*)h->key);
    /* swap out zeros, bad for xoring */
    for (i = 0; i < h->keylen; ++i)
        if (h->key[i] == 0)
            h->key[i] = 0xff;
    _fc_extend_key(h);
    h->hdrversion = 0;
    h->hdrlen = FILECRYPT_HDR_PAD;

    return h;
}

static inline void
fc_free_hdr(filecrypt_hdr_t *h)
{
    free(h);
}

static inline int
_fc_read_hdr(HANDLE file, int *iscrypt, filecrypt_hdr_t *h_in, filecrypt_hdr_t **h_out)
{
    uint64_t magic;
    uint32_t hdrversion, hdrlen;
    filecrypt_hdr_t *h;
    int rc = 0;
    uint8_t *ptr;

    if (h_out)
        *h_out = NULL;
    *iscrypt = 0;

    rc = _fc_read(file, &magic, 8);
    if (rc)
        return rc;
    if (h_in)
        fc_decrypt(h_in, &magic, 0, 8);
    if (magic != FILECRYPT_MAGIC)
        return ERROR_INVALID_DATA;
    *iscrypt = 1;
    rc = _fc_read(file, &hdrversion, 4);
    if (rc)
        return rc;
    rc = _fc_read(file, &hdrlen, 4);
    if (rc)
        return rc;
    if (h_in) {
        fc_decrypt(h_in, &hdrversion, 8, 4);
        fc_decrypt(h_in, &hdrlen, 12, 4);
    }
    if (hdrlen > 4096)
        return ERROR_BUFFER_OVERFLOW;
    if (hdrlen < 16)
        return ERROR_INVALID_DATA;
    h = (filecrypt_hdr_t*) calloc(1, hdrlen);
    if (!h)
        return ERROR_NOT_ENOUGH_MEMORY;
    h->magic = magic;
    h->hdrversion = hdrversion;
    h->hdrlen = hdrlen;
    ptr = ((uint8_t*)h) + 16;
    rc = _fc_read(file, ptr, sizeof(filecrypt_hdr_t)-16);
    if (rc)
        return rc;
    if (h_in)
        fc_decrypt(h_in, ptr, 16, sizeof(filecrypt_hdr_t)-16);
    if (h->keylen != FILECRYPT_KEYBYTES)
        return ERROR_INVALID_DATA;
    _fc_extend_key(h);
    if (h_out)
        *h_out = h;
    else
        free(h);

    return 0;
}

static inline void
_fc_append_hdr(filecrypt_hdr_t *h, filecrypt_hdr_t *app)
{
    uint32_t i;
    uint32_t len = h->keylen;

    if (app->keylen > h->keylen)
        len = app->keylen;

    for (i = 0; i < len; ++i) {
        uint8_t v0 = i < h->keylen ? h->key[i] : 0;
        uint8_t v1 = i < app->keylen ? app->key[i] : 0;
        h->key[i] = v0 ^ v1;
    }
    h->keylen = len;
    h->hdrlen += app->hdrlen;
    _fc_extend_key(h);
}

static inline void
_fc_crypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len)
{
    uint32_t keylen = h->keylen;
    uint32_t keyoff = (uint32_t)(off & (keylen-1));
    fc_word_t *key = (fc_word_t*)&h->key[keyoff];
    fc_word_t *p = (fc_word_t*) buf;
    fc_word_t *pk, *pkend;
    uint32_t n = len / keylen;
    uint32_t rwords = (len % keylen) / sizeof(fc_word_t);
    uint32_t r8  = (len % keylen) % sizeof(fc_word_t);

    while (n--) {
        pk = key;
        pkend = key + (keylen / sizeof(fc_word_t));
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


static inline int
fc_read_hdr(HANDLE file, int *iscrypt, filecrypt_hdr_t **h_out)
{
    filecrypt_hdr_t *h;
    int rc = 0;
    uint64_t p;
    int layer;

    if (h_out)
        *h_out = NULL;
    *iscrypt = 0;

    if (SetFilePointer(file, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return GetLastError();
    rc = _fc_read_hdr(file, iscrypt, NULL, &h);
    if (rc) {
        SetFilePointer(file, 0, NULL, FILE_BEGIN);
        return rc;
    }
    p = h->hdrlen;
    layer = 0;
    for (;;) {
        int iscrypt_temp;
        filecrypt_hdr_t *htemp = NULL;

        if (layer++ > FC_MAX_CR_LAYERS)
            return ERROR_BUFFER_OVERFLOW;

        if (SetFilePointer(file, (LONG) p, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            break; /* no more crypt layers */
        rc = _fc_read_hdr(file, &iscrypt_temp, h, &htemp);
        if (iscrypt_temp && rc) {
            /* read error of crypt hdr */
            SetFilePointer(file, 0, NULL, FILE_BEGIN);
            return rc;
        } else if (rc)
            break; /* no more crypt layers */
        if (p + htemp->hdrlen > INT_MAX) {
            free(htemp);
            return ERROR_BUFFER_OVERFLOW;
        }
        _fc_append_hdr(h, htemp);
        p += htemp->hdrlen;
        free(htemp);
    }
    SetFilePointer(file, h->hdrlen, NULL, FILE_BEGIN);
    if (h_out)
        *h_out = h;
    return 0;
}

static inline int
fc_path_read_hdr(wchar_t *path, int *iscrypt, filecrypt_hdr_t **_hdr)
{
    HANDLE h;
    int rc;

    *iscrypt = 0;
    *_hdr = NULL;

    h = CreateFileW(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return GetLastError();
    rc = fc_read_hdr(h, iscrypt, _hdr);
    CloseHandle(h);
    return rc;
}

static inline int
fc_write_hdr(HANDLE file, filecrypt_hdr_t *h)
{
    int rc = 0;

    if (SetFilePointer(file, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        return ERROR_WRITE_FAULT;
    if (h->hdrlen > 4096)
        return ERROR_BUFFER_OVERFLOW;
    rc = _fc_write(file, h, sizeof(*h));
    if (rc)
        return rc;
    rc = _fc_pad(file, FILECRYPT_HDR_PAD - sizeof(*h));
    if (rc)
        return rc;
    return 0;
}

static inline void
fc_crypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len)
{
    _fc_crypt(h, buf, off, len);
}

static inline void
fc_decrypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len)
{
    _fc_crypt(h, buf, off, len);
}

static inline BOOL
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

static inline BOOL
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
  
#ifdef __cplusplus
} // extern "C"
#endif

#endif
