/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _JSON_H_
#define _JSON_H_

#include <yajl/yajl_gen.h>

#define SET_STR(prop,str)                                               \
do {                                                                    \
    yajl_gen_string(g, (const unsigned char *)(prop), strlen(prop));    \
    yajl_gen_string(g, (const unsigned char *)(str), strlen(str));      \
} while (0)

#define SET_BUF(prop,buf,len)                                           \
do {                                                                    \
    yajl_gen_string(g, (const unsigned char *)(prop), strlen(prop));    \
    yajl_gen_string(g, (const unsigned char *)(buf), (len));            \
} while (0)

#define SET_BASE64(prop,buf,len)                                        \
do {                                                                    \
    char *str = base64_encode((buf), (len));                            \
    if (!str)                                                           \
        break;                                                          \
    yajl_gen_string(g, (const unsigned char *)(prop), strlen(prop));    \
    yajl_gen_string(g, (const unsigned char *)str, strlen(str));        \
    free(str);                                                          \
} while (0)

#define SET_BASE64_ELEM(buf,len)                                        \
do {                                                                    \
    char *str = base64_encode((buf), (len));                            \
    if (!str)                                                           \
        break;                                                          \
    yajl_gen_string(g, (const unsigned char *)str, strlen(str));        \
    free(str);                                                          \
} while (0)

#define SET_INT(prop,val)                                               \
do {                                                                    \
    yajl_gen_string(g, (const unsigned char *)(prop), strlen(prop));    \
    yajl_gen_integer(g, (val));                                         \
} while (0)

#endif /* _JSON_H_ */
