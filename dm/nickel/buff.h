/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _BUFF__H_
#define _BUFF__H_

#include <dm/queue2.h>
#include "constants.h"
struct buff;
RLIST_HEAD(buff_list, buff);

#define BFS_FREE    0
#define BFS_SOCKET  1
#define BFS_SENT    2

struct buff {
    RLIST_ENTRY(buff_list) entry;
    RLIST_ENTRY(buff_list) so_entry;
    uint32_t state;
    int retransmit;
    int64_t ts;
    uint8_t *m;
    void *opaque;
    uint8_t *data;
    size_t size;
    size_t mx_size;
    size_t len;
    size_t prev_len;
    uint32_t refcnt;

    int priv_heap;
};

struct buff * buff_new(struct buff **pbuf, size_t l);
struct buff * buff_new_priv(struct buff **pbuf, size_t l);
void buff_free(struct buff **pbuf);
void buff_get(struct buff *buf);
void buff_put(struct buff *buf);
int buff_adj(struct buff *buf, size_t newlen);
int buff_append(struct buff *buf, const char *c, size_t len);
int buff_appendf(struct buff *bf, const char *fmt, ...);
int buff_gc_consume(struct buff *b, size_t l);

#define BUFF_NEW(buf, pbuf, l) ((buf) = buff_new(pbuf, l))
#define BUFF_NEW_PRIV(buf, pbuf, l) ((buf) = buff_new_priv(pbuf, l))
#define BUFF_NEW_MX(pbuf, l, mx) (({ struct buff *b = NULL;                 \
                                     b = buff_new(pbuf, l);                 \
                                     if (b) b->mx_size = mx;                \
                                     b;                                     \
                                 }))
#define BUFF_NEW_MX_PRIV(pbuf, l, mx) (({ struct buff *b = NULL;            \
                                     b = buff_new_priv(pbuf, l);            \
                                     if (b) b->mx_size = mx;                \
                                     b;                                     \
                                 }))
#define BUFF_NEWSTR(str) (({ struct buff *b = NULL;                         \
                             ssize_t strl = -1;                             \
                             if (str) strl = strlen(str);                   \
                             if (strl >= 0) b = buff_new(NULL, strl);       \
                             if (b) buff_append(b, str, strl);              \
                             b;                                             \
                          }))
#define BUFF_ENLARGE(buf, extra) buff_adj(buf, (buf)->size + (extra))
#define BUFF_BEGINNING(b) ((char *) (b)->data)
#define BUFF_TO(b, t) ((t)((b)->m))
#define BUFF_CSTR(buf) BUFF_TO(buf, const char *)
#define BUFF_STR(buf)  BUFF_TO(buf, char *)
#define BUFF_FREEDOM(b) ((b)->size - (((b)->m - (b)->data) + (b)->len))
#define BUFF_BUFFERED(b) (((b)->m - (b)->data) + (b)->len)
#define BUFF_CONSUMED(b)    ((size_t) ((b)->m - (b)->data))
#define BUFF_CONSUME(b, ll) do { (b)->m += (ll); (b)->len -= (ll); (b)->prev_len = (b)->len; } while(0)
#define BUFF_CONSUME_ALL(b) do { (b)->m += (b)->len; (b)->len = 0; (b)->prev_len = 0; } while(0)
#define BUFF_UNCONSUME(b) do { (b)->len += ((b)->m - (b)->data); \
                               (b)->prev_len += ((b)->m - (b)->data); (b)->m = (b)->data; } while(0)
#define BUFF_GC(b) do { if ((b)->m == (b)->data) break; if ((b)->len) \
                    memmove((b)->data, (b)->m, (b)->len); \
                    (b)->m = (b)->data; (b)->m[(b)->len] = 0; } while(0)
#define BUFF_OFF(b) ((b)->m - (b)->data)
#define BUFF_RESET(b) do { if (!(b)) break; (b)->m = (b)->data; (b)->len = 0;                   \
                            (b)->prev_len = 0; *((b)->data) = 0; } while(0)
#define BUFF_APPENDSTR(buf, str) buff_append(buf, str, strlen(str))
#define BUFF_APPENDB(buf, b) buff_append(buf, BUFF_CSTR(b), (b)->len)
#define BUFF_APPENDFROM(out, in, from) buff_append(out, (const char *) (((in)->data) + from),   \
                    BUFF_BUFFERED(in) - from)
#define BUFF_ADVANCE(b, l) do { (b)->prev_len = (b)->len; (b)->len += (l); (b)->m[(b)->len] = 0; } \
                            while(0)

#if _WIN32
wchar_t * buff_unicode_encode(const char *str);
char * buff_priv_ansi_utf8_encode(const char *str);
#endif

void buff_strtolower(char *str);
void buff_strtr(char *s, char search, char replace);

#endif
