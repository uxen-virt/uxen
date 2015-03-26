/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _YAJL_H_
#define _YAJL_H_

#include "lib.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>

#define yajl_path1(i) (const char *[]){ (i), NULL }

static inline const yajl_type
yajl_object_type(yajl_val object)
{

    return object ? object->type : 0;
}

static inline const yajl_val
yajl_object_get(yajl_val object, const char *path)
{

    return yajl_tree_get(object, yajl_path1(path), yajl_t_any);
}

static inline const yajl_val
yajl_object_get_object(yajl_val object, const char *path)
{
    yajl_val v;

    v = yajl_tree_get(object, yajl_path1(path), yajl_t_object);
    return YAJL_IS_OBJECT(v) ? v : NULL;
}

static inline const char *
yajl_object_get_string(yajl_val object, const char *path)
{
    yajl_val v;

    v = yajl_tree_get(object, yajl_path1(path), yajl_t_string);
    return YAJL_GET_STRING(v);
}

static inline int
yajl_object_get_bool_default(yajl_val object, const char *path,
                             int defval)
{
    yajl_val v;

    v = yajl_tree_get(object, yajl_path1(path), yajl_t_any);
    if (YAJL_IS_TRUE(v))
        return 1;
    if (YAJL_IS_FALSE(v))
        return 0;
    return defval;
}

static inline int64_t
yajl_object_get_integer_default(yajl_val object, const char *path,
				uint64_t defval)
{
    yajl_val v;

    v = yajl_tree_get(object, yajl_path1(path), yajl_t_number);
    return YAJL_IS_INTEGER(v) ? YAJL_GET_INTEGER(v) : defval;
}

static inline int64_t
yajl_object_get_integer(yajl_val object, const char *path)
{

    return yajl_object_get_integer_default(object, path, 0);
}

static inline int
yajl_object_set(yajl_val object, const char *path, yajl_val v)
{

    return yajl_tree_set(object, yajl_path1(path), v);
}

static inline int
yajl_object_set_integer(yajl_val object, const char *path, int64_t val)
{
    yajl_val v;

    v = yajl_tree_new_integer(val);
    if (v == NULL)
        return -1;
    v->type = yajl_t_number;
    return yajl_tree_set(object, yajl_path1(path), v);
}

static inline int
yajl_object_set_bool(yajl_val object, const char *path, int val)
{
    yajl_val v;

    v = yajl_tree_new_boolean(val);
    if (v == NULL)
        return -1;
    v->type = val ? yajl_t_true : yajl_t_false;
    return yajl_tree_set(object, yajl_path1(path), v);
}

static inline int
yajl_object_set_number(yajl_val object, const char *path, const char *val)
{
    yajl_val v;

    v = yajl_tree_new_number((const unsigned char *)val, strlen(val));
    if (v == NULL)
        return -1;
    return yajl_tree_set(object, yajl_path1(path), v);
}

static inline int
yajl_object_set_string(yajl_val object, const char *path, const char *val)
{
    yajl_val v;

    v = yajl_tree_new_string((const unsigned char *)val, strlen(val));
    if (v == NULL)
        return -1;
    return yajl_tree_set(object, yajl_path1(path), v);
}

static inline yajl_val
yajl_object_create(void)
{
    yajl_val v;

    v = yajl_tree_new_object();
    return v;
}

static inline void
yajl_object_destroy(yajl_val v)
{

    yajl_tree_free(v);
}

static inline yajl_gen_status
yajl_gen_cstring(yajl_gen g, const char *str)
{

    return yajl_gen_string(g, (const unsigned char *)str, strlen(str));
}

static inline yajl_gen_status
yajl_gen_vprintf(yajl_gen g, const char *fmt, va_list ap)
{
    char *s;
    int ret;

    ret = vasprintf(&s, fmt, ap);
    if (ret == -1)
        return yajl_gen_no_buf;

    ret = yajl_gen_cstring(g, s);

    free(s);

    return ret;
}

static inline yajl_gen_status
yajl_gen_printf(yajl_gen g, const char *fmt, ...)
{
    yajl_gen_status ret;
    va_list va;

    va_start(va, fmt);
    ret = yajl_gen_vprintf(g, fmt, va);
    va_end(va);
    return ret;
}

/* iterate over obj:
 * - if obj is an array, iterate through the elements
 * - otherwise just execute body once with obj
 */
#define YAJL_FOREACH_ARRAY_OR_OBJECT(var, obj, itvar)		\
    for ((itvar) = 0;						\
	 ((var) = YAJL_IS_ARRAY((obj)) ?                        \
          (((itvar) < YAJL_GET_ARRAY((obj))->len) ?             \
           YAJL_GET_ARRAY((obj))->values[(itvar)] : NULL) : (obj),\
	  YAJL_IS_ARRAY((obj)) ?				\
	  ((itvar) < YAJL_GET_ARRAY((obj))->len) : !(itvar));	\
	 (itvar)++)

#endif	/* _YAJL_H_ */
