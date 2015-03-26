/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>

#include <ctype.h>
#include <stdarg.h>
#include "log.h"
#include "buff.h"
#include "nickel.h"

#define MAX_BUFF_LEN    ((uint32_t) (((uint32_t)(-1)) >> 2))

#if _WIN32
#define SANE_STR_SIZE MAX_BUFF_LEN
#define IS_SANE_LENGTH(a)   (((size_t)(a)) < SANE_STR_SIZE)
#include <wchar.h>
#endif

static struct buff * _buff_new(struct buff **pbuf, bool priv, size_t l)
{
    struct buff *buf = NULL;

    if (l > MAX_BUFF_LEN) {
        debug_printf("%s: l > MAX_BUFF_LEN = %lu\n", __FUNCTION__,
                (unsigned long) MAX_BUFF_LEN);
        goto cleanup;
    }
    buf = calloc(1, sizeof(struct buff));
    if (!buf)
        goto cleanup;
    if (priv)
        buf->priv_heap = 1;

    if (buf->priv_heap)
        buf->data = ni_priv_calloc(1, l + 1);
    else
        buf->data = calloc(1, l + 1);
    if (!buf->data)
        goto cleanup;
    buf->refcnt = 1;

    if (pbuf)
        *pbuf = buf;

    buf->m = buf->data;
    buf->size = l;
    buf->mx_size = buf->size;
    buf->len = 0;
    buf->prev_len = 0;
out:
    return buf;
cleanup:
    if (buf && buf->priv_heap)
        ni_priv_free(buf->data);
    else if (buf && !buf->priv_heap)
        free(buf->data);
    free(buf);
    buf = NULL;
    goto out;
}

struct buff * buff_new(struct buff **pbuf, size_t l)
{
    return _buff_new(pbuf, false, l);
}

struct buff * buff_new_priv(struct buff **pbuf, size_t l)
{
    return _buff_new(pbuf, true, l);
}

void buff_get(struct buff *buf)
{
    atomic_inc(&buf->refcnt);
}

void buff_put(struct buff *buf)
{
    assert(buf->refcnt);
    if (!atomic_dec_and_test(&buf->refcnt))
        return;

    if (buf->priv_heap)
        ni_priv_free(buf->data);
    else
        free(buf->data);
    free(buf);
}

void buff_free(struct buff **pbuf)
{
    if (!pbuf || !*pbuf)
        return;

    buff_put(*pbuf);
    *pbuf = NULL;
}

int buff_adj(struct buff *buf, size_t newlen)
{
    int ret = -1;
    uint8_t *ndata;
    size_t off;

    if (newlen > MAX_BUFF_LEN) {
        debug_printf("%s: l > MAX_BUFF_LEN = %u\n", __FUNCTION__, MAX_BUFF_LEN);
        goto out;
    }
    if (buf->size == newlen)
        goto out;

    if (buf->size > newlen)
        goto out;

    off = buf->m - buf->data;
    if (buf->priv_heap)
        ndata = ni_priv_realloc(buf->data, newlen + 1);
    else
        ndata = realloc(buf->data, newlen + 1);
    if (!ndata) {
        goto out;
    }
    buf->data = ndata;
    buf->size = newlen;
    if (buf->mx_size < buf->size)
        buf->mx_size = buf->size;
    (buf->data)[newlen] = 0;

    buf->m = buf->data + off;
    ret = 0;
out:
    return ret;
}

int buff_append(struct buff *buf, const char *c, size_t len)
{
    int ret = -1;

    if (len == 0) {
        /* zero length appends ok */
        ret = 0;
        goto out;
    }

    if (BUFF_FREEDOM(buf) < len) {
        if (BUFF_ENLARGE(buf, len) < 0)
            goto out;
    }

    memcpy(buf->m + buf->len, c, len);
    buf->prev_len = buf->len;
    buf->len += len;
    buf->m[buf->len] = 0;
    ret = 0;
out:
    return ret;
}

int buff_gc_consume(struct buff *b, size_t lb)
{
    size_t consumed;
    int ret = 0;

    if (lb == 0)
        goto out;

    consumed = BUFF_CONSUMED(b);
    assert(lb <= consumed);

    if (lb == consumed && b->len == 0) {
        BUFF_RESET(b);
        goto out;
    }

    memmove(b->data, b->data + lb, BUFF_BUFFERED(b) - lb);
    b->m -= lb;
    b->m[b->len] = 0;

out:
    return ret;
}

int buff_appendf(struct buff *bf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    char *tmp = NULL;

    va_start(ap, fmt);
    ret = vasprintf(&tmp, fmt, ap);
    va_end(ap);

    if (ret < 0)
        return ret;
    ret = buff_append(bf, tmp, ret);
    free(tmp);
    return ret;
}

#if _WIN32
/* Convert a char* string to unicode */
wchar_t * buff_unicode_encode(const char *str)
{
    int cbResult = 0;
    int iLastErr = 0;
    wchar_t *unicode_string = NULL;

    if (!str)
        goto err;

    cbResult = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (cbResult <= 0 || !IS_SANE_LENGTH(cbResult)) {
        warnx("%s: wrong cbResult = %d", __FUNCTION__, cbResult);
        goto err;
    }

    unicode_string = calloc(1, (((size_t)cbResult) + 1) * sizeof(wchar_t));
    if (!unicode_string) {
        warnx("%s: malloc", __FUNCTION__);
        goto err;
    }

    if (MultiByteToWideChar(CP_ACP, 0, str, -1, unicode_string, cbResult) <= 0) {
        iLastErr = GetLastError();
        NETLOG("Unicode to ACP translation failed. lasterr=%d", (int) iLastErr);
        goto err;
    }

out:
    return unicode_string;

err:
    if (unicode_string)
        free(unicode_string);
    unicode_string = NULL;
    goto out;
}

char * buff_priv_ansi_utf8_encode(const char *str)
{
    int str_len, ulen, resp_len;
    char *resp = NULL;
    wchar_t *ustr = NULL;

    if (!str)
       goto err;

    str_len = strlen(str);
    if (str_len < 0 || !IS_SANE_LENGTH(str_len))
        goto err;

    ulen = MultiByteToWideChar(CP_ACP, 0, str, str_len, NULL, 0);
    if (ulen <= 0 || !IS_SANE_LENGTH(ulen)) {
        Wwarn("%s: wrong ulen = %d", __FUNCTION__, ulen);
        goto err;
    }

    ustr = ni_priv_calloc(1, (ulen + 1) * sizeof(wchar_t));
    if (!ustr)
        goto mem_err;

    ulen = MultiByteToWideChar(CP_ACP, 0, str, str_len, ustr, ulen);
    if (ulen <= 0) {
        Wwarn("%s: MultiByteToWideChar failed", __FUNCTION__);
        goto err;
    }

    resp_len = WideCharToMultiByte(CP_UTF8, 0, ustr, ulen, NULL, 0, NULL, NULL);
    if (resp_len <= 0 || !IS_SANE_LENGTH(resp_len)) {
        Wwarn("%s: wrong resp_len = %d", __FUNCTION__, resp_len);
        goto err;
    }

    resp = ni_priv_calloc(1, resp_len + 1);
    if (!resp)
        goto mem_err;

    if (WideCharToMultiByte(CP_UTF8, 0, ustr, ulen, resp, resp_len, NULL, NULL) <= 0) {
        Wwarn("%s: WideCharToMultiByte failed", __FUNCTION__);
        goto err;
    }

out:
    ni_priv_free(ustr);
    ustr = NULL;
    return resp;

mem_err:
    warnx("%s: malloc", __FUNCTION__);
err:
    ni_priv_free(resp);
    resp = NULL;
    goto out;
}

#endif

void buff_strtolower(char *str)
{
    while (*str) {
        if (isalpha(*str))
            *str = tolower(*str);
        ++str;
    }
}

void buff_strtr(char *s, char search, char replace)
{
    while (s && *s) {
        if (*s == search)
            *s = replace;
        s++;
    }
}
