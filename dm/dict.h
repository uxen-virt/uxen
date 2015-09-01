/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DICT_H_
#define _DICT_H_

#include "yajl.h"

typedef yajl_val dict;

typedef yajl_type dict_type;
#define DICT_TYPE_NONE 0
#define DICT_TYPE_STRING yajl_t_string
#define DICT_TYPE_NUMBER yajl_t_number
#define DICT_TYPE_OBJECT yajl_t_object
#define DICT_TYPE_ARRAY yajl_t_array
#define DICT_TYPE_TRUE yajl_t_true
#define DICT_TYPE_FALSE yajl_t_false
#define DICT_TYPE_NULL yajl_t_null

static inline dict
dict_new(void)
{

    return yajl_object_create();
}

static inline void
dict_free(dict d)
{

    yajl_object_destroy(d);
}

static inline dict
dict_new_from_buffer(const char *input, char *errbuf, size_t errbuf_size)
{
    dict d;

    d = yajl_tree_parse(input, errbuf, errbuf_size);
    if (!d)
        return NULL;

    if (!YAJL_IS_OBJECT(d)) {
        dict_free(d);
        d = NULL;
        if (errbuf)
            snprintf(errbuf, errbuf_size,
                     "malformed input: top-level not a map");
    }

    return d;
}

static inline const dict_type
dict_typeof(dict d)
{

    return yajl_object_type(d);
}

static inline const dict
dict_get(dict d, const char *key)
{

    return yajl_object_get(d, key);
}

static inline const char *
dict_get_string(dict d, const char *key)
{

    return yajl_object_get_string(d, key);
}

static inline int
dict_string_as_bool(const char *s, int defval)
{

    if (!s)
        return defval;
    if (!strcasecmp(s, "true") || !strcasecmp(s, "t") ||
        !strcasecmp(s, "on") || !strcasecmp(s, "1"))
        return 1;
    if (!strcasecmp(s, "false") || !strcasecmp(s, "f") ||
        !strcasecmp(s, "off") || !strcasecmp(s, "0"))
        return 0;
    return defval;
}

static inline int64_t
dict_get_integer(dict d, const char *key)
{

    return yajl_object_get_integer(d, key);
}

static inline int64_t
dict_get_integer_default(dict d, const char *key, int64_t defval)
{

    return yajl_object_get_integer_default(d, key, defval);
}

static inline int
dict_integer_as_bool(int64_t i, int defval)
{

    if (i == 1)
        return 1;
    if (i == 0)
        return 0;
    return defval;
}

static inline int
dict_get_boolean(dict d, const char *key)
{

    return yajl_object_get_bool_default(d, key, 0);
}

static inline int
dict_get_boolean_default(dict d, const char *key, int64_t defval)
{

    return yajl_object_get_bool_default(d, key, defval);
}

/* XXX name _dict_put since it can easily lead to memory corruption
 * because val will be freed when d is freed */
static inline int
_dict_put(dict d, const char *key, dict val)
{
    int ret;

    ret = yajl_object_set(d, key, val);

    return ret ? -1 : 0;
}

static inline int
dict_put_string(dict d, const char *key, const char *val)
{
    int ret;

    ret = yajl_object_set_string(d, key, val);

    return ret ? -1 : 0;
}

static inline int
dict_put_vstringf(dict d, const char *key, const char *fmt, va_list ap)
{
    char *s;
    int ret;

    ret = vasprintf(&s, fmt, ap);
    if (ret == -1)
        return -1;

    ret = yajl_object_set_string(d, key, s);

    free(s);

    return ret ? -1 : 0;
}

static inline int
dict_put_stringf(dict d, const char *key, const char *fmt, ...)
{
    va_list va;
    int ret;

    va_start(va, fmt);
    ret = dict_put_vstringf(d, key, fmt, va);
    va_end(va);

    return ret;
}

static inline int
dict_put_integer(dict d, const char *key, int64_t val)
{
    int ret;

    ret = yajl_object_set_integer(d, key, val);

    return ret ? -1 : 0;
}

static inline int
dict_put_boolean(dict d, const char *key, bool val)
{
    int ret;

    ret = yajl_object_set_bool(d, key, val);

    return ret ? -1 : 0;
}

static inline int
dict_put_number(dict d, const char *key, const char *val)
{
    int ret;

    ret = yajl_object_set_number(d, key, val);

    return ret ? -1 : 0;
}

static inline dict
dict_array_new(void)
{

    return yajl_tree_new_array();
}

/* XXX name _dict_array_put since it can easily lead to memory corruption
 * because val will be freed when a is freed */
static inline int
_dict_array_put(dict a, dict val)
{
    int ret;

    ret = yajl_tree_array_add_value(a, val);

    return ret ? -1 : 0;
}

#define dict_key(d,i)                                   \
        (((i) < YAJL_GET_OBJECT(d)->len) ?              \
         YAJL_GET_OBJECT(d)->keys[i] : NULL)
#define dict_val(d,i)                                   \
        (((i) < YAJL_GET_OBJECT(d)->len) ?              \
         YAJL_GET_OBJECT(d)->values[i] : NULL)
#define array_val(a,i)                                  \
        (((i) < YAJL_GET_ARRAY((a))->len) ?             \
         YAJL_GET_ARRAY((a))->values[i] : NULL)


#define DICT_FOREACH(key, val, d, itvar)                \
    for ((itvar) = 0;                                   \
         ((key) = dict_key(d, itvar),                   \
          (val) = dict_val(d, itvar),                   \
          (itvar) < YAJL_GET_OBJECT(d)->len);           \
         (itvar)++)

#define DICT_FOREACH_KEY(key, d, itvar)                 \
    for ((itvar) = 0;                                   \
         ((key) = dict_key(d, itvar),                   \
          (itvar) < YAJL_GET_OBJECT(d)->len);           \
         (itvar)++)

#define ARRAY_FOREACH(val, d, itvar)                    \
    for ((itvar) = 0;                                   \
         ((val) = array_val(d, itvar),                  \
          (itvar) < YAJL_GET_ARRAY(d)->len);            \
         (itvar)++)

int dict_write_buf(dict, char **, size_t *);

int dict_merge(dict, dict);

#endif  /* _DICT_H_ */
